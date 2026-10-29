//go:build linux

package censor

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor/dpi"
	"github.com/payam-foundation/dotvpn-lab/internal/netlab"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

// Border is the packet-level censor: it sits in the border namespace, takes the
// stateless part of the profile from nftables and the rest from the engine via
// NFQUEUE. IPv4 only; IPv6 crosses untouched (the leak suite watches it).
type Border struct {
	E *Engine

	lab    *netlab.Lab
	inside netip.Prefix
	queue  uint16
	nf     *nfqueue.Nfqueue
	raw    int
	cancel context.CancelFunc

	mu    sync.Mutex
	flows map[string]*bflow
}

type bflow struct {
	f    *Flow
	init netip.AddrPort
	last time.Time
	lim  *limiter
}

// StartBorder installs the profile on the border of lab. Stop removes it.
func StartBorder(l *netlab.Lab, e *Engine) (*Border, error) {
	b := &Border{E: e, lab: l, inside: netip.MustParsePrefix(netlab.InNet), queue: 0, flows: map[string]*bflow{}}
	script, _ := compileNFT(e.P, b.inside, b.queue)
	cmd := l.Cmd(l.Border, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("nft: %v: %s\n%s", err, out, script)
	}
	if err := l.InNS(l.Border, func() (err error) {
		b.raw, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		return err
	}); err != nil {
		return nil, err
	}
	nsf, err := l.NetNSFile(l.Border)
	if err != nil {
		return nil, err
	}
	defer nsf.Close()
	b.nf, err = nfqueue.Open(&nfqueue.Config{
		NetNS: int(nsf.Fd()), NfQueue: b.queue, MaxPacketLen: 0xFFFF, MaxQueueLen: 1 << 14,
		Copymode: nfqueue.NfQnlCopyPacket, AfFamily: unix.AF_INET, Flags: nfqueue.NfQaCfgFlagGSO,
	})
	if err != nil {
		return nil, fmt.Errorf("nfqueue: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	if err := b.nf.RegisterWithErrorFunc(ctx, b.handle, func(error) int { return 0 }); err != nil {
		return nil, err
	}
	go b.gc(ctx)
	return b, nil
}

// Stop detaches the censor; queued packets pass (the rule says bypass).
func (b *Border) Stop() {
	b.cancel()
	_ = b.nf.Close()
	_ = unix.Close(b.raw)
	_ = b.lab.Cmd(b.lab.Border, "nft", "delete", "table", "ip", nftTable).Run()
}

// Rules lists every rule that fired, from the kernel counters and the engine.
func (b *Border) Rules() []string {
	set := map[string]bool{}
	out, _ := b.lab.Run(b.lab.Border, "nft", "list", "chain", "ip", nftTable, "lab")
	for id, n := range parseCounters(out) {
		if n > 0 {
			set[id] = true
		}
	}
	for _, h := range b.E.Hits() {
		set[h.Rule] = true
	}
	var res []string
	for id := range set {
		res = append(res, id)
	}
	slices.Sort(res)
	return res
}

func (b *Border) gc(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.mu.Lock()
			for k, f := range b.flows {
				if time.Since(f.last) > 2*time.Minute {
					delete(b.flows, k)
				}
			}
			b.mu.Unlock()
		}
	}
}

// pkt is a parsed IPv4 packet.
type pkt struct {
	proto    string
	src, dst netip.AddrPort
	payload  []byte // TCP/UDP payload, or the whole ICMP message
	ip       []byte
	l4       []byte
	flags    byte
	seq, ack uint32
	tcp      bool
}

func parse(p []byte) (pkt, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return pkt{}, false
	}
	ihl := int(p[0]&0xf) * 4
	if ihl < 20 || len(p) < ihl {
		return pkt{}, false
	}
	tot := int(binary.BigEndian.Uint16(p[2:4]))
	if tot > len(p) || tot < ihl {
		tot = len(p)
	}
	p = p[:tot]
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 { // later fragment: no L4 header
		return pkt{}, false
	}
	var q pkt
	sa, _ := netip.AddrFromSlice(p[12:16])
	da, _ := netip.AddrFromSlice(p[16:20])
	q.ip, q.l4 = p[:ihl], p[ihl:]
	switch p[9] {
	case unix.IPPROTO_TCP:
		if len(q.l4) < 20 {
			return pkt{}, false
		}
		off := int(q.l4[12]>>4) * 4
		if off < 20 || off > len(q.l4) {
			return pkt{}, false
		}
		q.proto, q.tcp = "tcp", true
		q.src = netip.AddrPortFrom(sa, binary.BigEndian.Uint16(q.l4[0:2]))
		q.dst = netip.AddrPortFrom(da, binary.BigEndian.Uint16(q.l4[2:4]))
		q.seq, q.ack, q.flags = binary.BigEndian.Uint32(q.l4[4:8]), binary.BigEndian.Uint32(q.l4[8:12]), q.l4[13]
		q.payload = q.l4[off:]
	case unix.IPPROTO_UDP:
		if len(q.l4) < 8 {
			return pkt{}, false
		}
		q.proto = "udp"
		q.src = netip.AddrPortFrom(sa, binary.BigEndian.Uint16(q.l4[0:2]))
		q.dst = netip.AddrPortFrom(da, binary.BigEndian.Uint16(q.l4[2:4]))
		q.payload = q.l4[8:]
	case unix.IPPROTO_ICMP:
		q.proto = "icmp"
		q.src, q.dst = netip.AddrPortFrom(sa, 0), netip.AddrPortFrom(da, 0)
		q.payload = q.l4
	default:
		return pkt{}, false
	}
	return q, true
}

func flowKey(q pkt) string {
	a, b := q.src, q.dst
	if b.Compare(a) < 0 {
		a, b = b, a
	}
	return q.proto + "|" + a.String() + "|" + b.String()
}

func (b *Border) flow(q pkt) (*bflow, Dir) {
	k := flowKey(q)
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.flows[k]
	if !ok {
		ingress := !b.inside.Contains(q.src.Addr())
		out := q.dst.Addr()
		if ingress {
			out = q.src.Addr()
		}
		f = &bflow{f: b.E.OpenAt(q.proto, q.src, q.dst, out, ingress), init: q.src}
		b.flows[k] = f
	}
	f.last = time.Now()
	if q.src == f.init {
		return f, C2S
	}
	return f, S2C
}

func (b *Border) handle(a nfqueue.Attribute) int {
	if a.PacketID == nil || a.Payload == nil {
		return 0
	}
	id := *a.PacketID
	verdict := func(v int) { _ = b.nf.SetVerdict(id, v) }
	q, ok := parse(*a.Payload)
	if !ok {
		verdict(nfqueue.NfAccept)
		return 0
	}
	bf, d := b.flow(q)
	v := bf.f.Observe(d, q.payload)
	switch v.Type {
	case Drop:
		verdict(nfqueue.NfDrop)
	case RST:
		verdict(nfqueue.NfDrop)
		if q.tcp {
			b.injectRST(q)
		}
	case Throttle:
		if bf.limiter(v.Action).allow(len(*a.Payload)) {
			verdict(nfqueue.NfAccept)
		} else {
			verdict(nfqueue.NfDrop)
		}
	case Delay:
		go func() {
			time.Sleep(time.Duration(v.DelayMS) * time.Millisecond)
			verdict(nfqueue.NfAccept)
		}()
	case InjectDNS:
		verdict(nfqueue.NfDrop)
		if q.proto == "udp" {
			b.sendUDP(q.dst, q.src, dpi.DNSReply(q.payload, v.Rcode))
		}
	default:
		verdict(nfqueue.NfAccept)
	}
	return 0
}

// limiter is a token bucket on bytes and packets per second.
type limiter struct {
	mu           sync.Mutex
	rateB, rateP float64
	tb, tp       float64
	last         time.Time
}

func (f *bflow) limiter(a Action) *limiter {
	if f.lim == nil {
		f.lim = &limiter{rateB: float64(a.RateBps), rateP: float64(a.RatePPS), last: time.Now()}
		f.lim.tb, f.lim.tp = f.lim.rateB/10, f.lim.rateP/10
	}
	return f.lim
}

func (l *limiter) allow(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	dt := now.Sub(l.last).Seconds()
	l.last = now
	if l.rateB > 0 {
		l.tb = min(l.tb+dt*l.rateB, max(l.rateB/10, 1500))
	}
	if l.rateP > 0 {
		l.tp = min(l.tp+dt*l.rateP, max(l.rateP/10, 1))
	}
	if l.rateB > 0 && l.tb < float64(n) || l.rateP > 0 && l.tp < 1 {
		return false
	}
	l.tb -= float64(n)
	l.tp--
	return true
}

// ---- raw injection ----

func (b *Border) send(pkt []byte, dst netip.Addr) {
	a := dst.As4()
	_ = unix.Sendto(b.raw, pkt, 0, &unix.SockaddrInet4{Addr: a})
}

func ipHeader(src, dst netip.Addr, proto byte, l4len int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+l4len))
	h[8], h[9] = 64, proto
	s, d := src.As4(), dst.As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return h // the kernel fills the header checksum for raw sockets
}

func (b *Border) sendUDP(from, to netip.AddrPort, payload []byte) {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], from.Port())
	binary.BigEndian.PutUint16(u[2:], to.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload) // checksum 0 is legal for IPv4 UDP
	b.send(append(ipHeader(from.Addr(), to.Addr(), unix.IPPROTO_UDP, len(u)), u...), to.Addr())
}

func tcpRST(from, to netip.AddrPort, seq, ack uint32, withAck bool) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:], from.Port())
	binary.BigEndian.PutUint16(t[2:], to.Port())
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12] = 5 << 4
	t[13] = 0x04
	if withAck {
		t[13] |= 0x10
	}
	ps := make([]byte, 12)
	s, d := from.Addr().As4(), to.Addr().As4()
	copy(ps[0:], s[:])
	copy(ps[4:], d[:])
	ps[9], ps[11] = unix.IPPROTO_TCP, 20
	binary.BigEndian.PutUint16(t[16:], csum(append(ps, t...)))
	return append(ipHeader(from.Addr(), to.Addr(), unix.IPPROTO_TCP, len(t)), t...)
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// injectRST resets both ends, as the GFW does: the sender sees a reset from
// the receiver and the receiver sees one from the sender.
func (b *Border) injectRST(q pkt) {
	n := uint32(len(q.payload))
	if q.flags&0x02 != 0 { // SYN
		n++
	}
	if q.flags&0x10 != 0 {
		b.send(tcpRST(q.dst, q.src, q.ack, 0, false), q.src.Addr())
	} else {
		b.send(tcpRST(q.dst, q.src, 0, q.seq+n, true), q.src.Addr())
	}
	b.send(tcpRST(q.src, q.dst, q.seq+n, 0, false), q.dst.Addr())
}
