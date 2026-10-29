package censor

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor/dpi"
)

// holdMax is how long a TCP proxy waits for a client payload to become
// readable by the censor before judging what it has.
const holdMax = 1500 * time.Millisecond

// Proxy is the userspace censor backend: a listener in front of one upstream
// that applies the engine's verdicts. The destination the profile sees is a
// lab placement, since the real upstream is on loopback.
type Proxy struct {
	Addr string // listen address

	e   *Engine
	dst netip.AddrPort // destination the engine matches on

	up   string
	tcp  net.Listener
	udp  net.PacketConn
	done chan struct{}
	once sync.Once
}

// StartTCP puts the censor in front of a TCP upstream.
func StartTCP(e *Engine, upstream string, dst netip.AddrPort) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{Addr: ln.Addr().String(), e: e, dst: dst, up: upstream, tcp: ln, done: make(chan struct{})}
	go p.acceptLoop()
	return p, nil
}

// StartUDP puts the censor in front of a UDP upstream.
func StartUDP(e *Engine, upstream string, dst netip.AddrPort) (*Proxy, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{Addr: pc.LocalAddr().String(), e: e, dst: dst, up: upstream, udp: pc, done: make(chan struct{})}
	go p.udpLoop()
	return p, nil
}

// Close stops the proxy; open flows end when their peers do.
func (p *Proxy) Close() {
	p.once.Do(func() {
		close(p.done)
		if p.tcp != nil {
			p.tcp.Close()
		}
		if p.udp != nil {
			p.udp.Close()
		}
	})
}

func (p *Proxy) open(proto string, src netip.AddrPort) *Flow {
	return p.e.Open(proto, src, p.dst)
}

// ---- TCP ----

func (p *Proxy) acceptLoop() {
	for {
		c, err := p.tcp.Accept()
		if err != nil {
			return
		}
		go p.serve(c.(*net.TCPConn))
	}
}

func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

func (p *Proxy) serve(c *net.TCPConn) {
	defer c.Close()
	f := p.open("tcp", c.RemoteAddr().(*net.TCPAddr).AddrPort())
	if !p.judge(c, f.Observe(C2S, nil)) {
		return
	}
	// Hold client bytes until the censor can read the first payload.
	var held []byte
	buf := make([]byte, 32<<10)
	deadline := time.Now().Add(holdMax)
	var v Verdict
	for {
		_ = c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if n > 0 {
			held = append(held, buf[:n]...)
			v = f.Observe(C2S, buf[:n])
			if v.Type != Pass || f.Ready() {
				break
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break // judged on what we have
			}
			return
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	if !p.judge(c, v) {
		return
	}
	up, err := net.Dial("tcp", p.up)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(held); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.pump(f, C2S, c, up); closeWrite(up) }()
	go func() { defer wg.Done(); p.pump(f, S2C, up, c); closeWrite(c) }()
	wg.Wait()
}

// judge applies the verdict to an unforwarded connection. It returns true if
// the connection should proceed.
func (p *Proxy) judge(c *net.TCPConn, v Verdict) bool {
	switch v.Type {
	case RST:
		reset(c)
		return false
	case Drop:
		p.blackhole(c)
		return false
	}
	return true
}

// blackhole reads and discards until the peer gives up: the client hangs.
func (p *Proxy) blackhole(c net.Conn) {
	t := time.AfterFunc(2*time.Minute, func() { c.Close() })
	defer t.Stop()
	_, _ = io.Copy(io.Discard, c)
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// pump copies src to dst chunk by chunk, asking the engine about each chunk.
func (p *Proxy) pump(f *Flow, d Dir, src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			v := f.Observe(d, buf[:n])
			switch v.Type {
			case RST:
				if tc, ok := src.(*net.TCPConn); ok {
					reset(tc)
				}
				if tc, ok := dst.(*net.TCPConn); ok {
					reset(tc)
				}
				return
			case Drop:
				// Freeze: stop forwarding both ways but keep the sockets open,
				// as RU-TCP-1 describes. Keep draining this side.
				_, _ = io.Copy(io.Discard, src)
				return
			case Throttle:
				time.Sleep(time.Duration(float64(n) / float64(v.RateBps) * float64(time.Second)))
			case Delay:
				time.Sleep(time.Duration(v.DelayMS) * time.Millisecond)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ---- UDP ----

type udpFlow struct {
	f      *Flow
	up     net.Conn
	client net.Addr
}

func (p *Proxy) udpLoop() {
	flows := map[string]*udpFlow{}
	var mu sync.Mutex
	buf := make([]byte, 64<<10)
	for {
		n, from, err := p.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		mu.Lock()
		fl := flows[from.String()]
		if fl == nil {
			up, err := net.Dial("udp", p.up)
			if err != nil {
				mu.Unlock()
				continue
			}
			fl = &udpFlow{f: p.open("udp", from.(*net.UDPAddr).AddrPort()), up: up, client: from}
			flows[from.String()] = fl
			go p.udpBack(fl)
		}
		mu.Unlock()

		v := fl.f.Observe(C2S, pkt)
		switch v.Type {
		case Drop, RST: // no reset exists for UDP: discard
			continue
		case InjectDNS:
			rc := v.Rcode
			if rc == 0 {
				rc = 3
			}
			if r := dpi.DNSReply(pkt, rc); r != nil {
				_, _ = p.udp.WriteTo(r, from)
			}
			continue
		case Throttle:
			time.Sleep(time.Duration(float64(n) / float64(v.RateBps) * float64(time.Second)))
		case Delay:
			time.Sleep(time.Duration(v.DelayMS) * time.Millisecond)
		}
		_, _ = fl.up.Write(pkt)
	}
}

func (p *Proxy) udpBack(fl *udpFlow) {
	defer fl.up.Close()
	buf := make([]byte, 64<<10)
	for {
		_ = fl.up.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := fl.up.Read(buf)
		if err != nil {
			return
		}
		if v := fl.f.Observe(S2C, buf[:n]); v.Type == Drop || v.Type == RST {
			continue
		}
		_, _ = p.udp.WriteTo(buf[:n], fl.client)
	}
}
