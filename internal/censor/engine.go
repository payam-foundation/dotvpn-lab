package censor

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor/dpi"
)

// Dir is the direction of a packet relative to the censored client.
type Dir int

const (
	C2S Dir = iota // client (inside) to server (outside)
	S2C
)

func (d Dir) String() string {
	if d == C2S {
		return "c2s"
	}
	return "s2c"
}

// Verdict is the decision for one packet or chunk.
type Verdict struct {
	Action
	Rule string // rule ID, "residual:<ID>" for a remembered block, "" for default pass
}

// Seen is what the censor learned about a flow from its first payload.
type Seen struct {
	Proto, Class, SNI, Host, DNS string
	Src, Dst                     netip.AddrPort
}

// Hit records a non-pass verdict, for reports and assertions.
type Hit struct {
	Rule, Action string
	Src, Dst     netip.AddrPort
}

const maxHello = 16 << 10 // give up waiting for a complete first payload here

// Engine evaluates flows against one profile and keeps the cross-flow state
// (residual blocks, observations, hits). Safe for concurrent use.
type Engine struct {
	P   *Profile
	Now func() time.Time // injectable for tests

	mu       sync.Mutex
	residual map[string]residual
	seen     []Seen
	hits     []Hit
	rng      *rand.Rand
}

type residual struct {
	until time.Time
	v     Verdict
}

// New returns an engine. seed fixes the per-flow probability rolls.
func New(p *Profile, seed uint64) *Engine {
	return &Engine{P: p, Now: time.Now, residual: map[string]residual{}, rng: rand.New(rand.NewPCG(seed, 1))}
}

// Seen returns every first-payload observation so far.
func (e *Engine) Seen() []Seen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.seen)
}

// Hits returns every non-pass verdict so far (one per flow and rule).
func (e *Engine) Hits() []Hit {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.hits)
}

// HitCount counts hits of one rule.
func (e *Engine) HitCount(rule string) (n int) {
	for _, h := range e.Hits() {
		if h.Rule == rule {
			n++
		}
	}
	return n
}

// Ready reports whether the first client payload has been understood well
// enough for payload rules to decide.
func (f *Flow) Ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info.ready
}

// Flow is the per-connection (TCP) or per-4-tuple (UDP) state.
type Flow struct {
	e        *Engine
	proto    string
	src, dst netip.AddrPort
	out      netip.Addr // the address on the far side of the border; prefix rules match it
	ingress  bool       // the initiator (src) is outside the border
	curLen   int        // payload length of the packet being judged
	curType  int        // ICMP type of the packet being judged, -1 if none

	mu      sync.Mutex
	buf     []byte // client bytes until the first payload is understood (TCP)
	first   []byte // first client payload
	frags   []dpi.Frag
	pkts    int
	info    info
	bytes   int64
	sec     int64 // current one-second bucket
	secB    int64
	secP    int64
	hot     int // consecutive hot seconds
	rolls   map[int]bool
	sticky  *Verdict
	flagged map[int]bool // rules already counted as hits
}

type info struct {
	ready                   bool
	class, sni, host, qname string
	frag                    bool
}

// Open starts tracking a flow and returns it. Call Observe(C2S, nil) to get
// the verdict that needs no payload (prefix blocks, residual blocks).
func (e *Engine) Open(proto string, src, dst netip.AddrPort) *Flow {
	return e.OpenAt(proto, src, dst, dst.Addr(), false)
}

// OpenAt is Open for a flow seen on a border: src is the initiator, dst the
// responder, outside the address on the far side of the border (prefix rules
// match it), ingress true if the initiator is outside. proto may be "icmp".
func (e *Engine) OpenAt(proto string, src, dst netip.AddrPort, outside netip.Addr, ingress bool) *Flow {
	f := &Flow{e: e, proto: proto, src: src, dst: dst, out: outside, ingress: ingress, curType: -1,
		rolls: map[int]bool{}, flagged: map[int]bool{}}
	if proto == "icmp" {
		f.info = info{ready: true, class: "icmp"}
	}
	return f
}

func (f *Flow) strict() bool { return f.e.P.DPI != "naive" }

// Observe accounts a packet or chunk and returns the verdict for it. A
// non-pass verdict of a sticky kind (drop, rst, throttle, delay) stays for the
// rest of the flow. inject-dns applies to the packet only.
func (f *Flow) Observe(d Dir, p []byte) Verdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.e.Now()
	f.bytes += int64(len(p))
	f.curLen, f.curType = len(p), -1
	if f.proto == "icmp" && len(p) > 0 {
		f.curType = int(p[0])
	}
	f.account(now, int64(len(p)))
	if d == C2S && len(p) > 0 && f.proto != "icmp" {
		f.learn(p)
	}
	if f.sticky == nil {
		// Not sticky: a residual block ends with its TTL, even for an open flow.
		if rv, ok := f.e.residualFor(f.key("src-dst"), f.key("4tuple")); ok {
			return rv
		}
	}
	if f.sticky != nil {
		return *f.sticky
	}
	v := f.eval(d, now)
	if v.sticky() && f.proto != "icmp" { // ICMP rules judge each packet on its own
		f.sticky = &v
	}
	return v
}

func (f *Flow) key(kind string) string {
	if kind == "4tuple" {
		return f.proto + "|" + f.src.String() + "|" + f.dst.String()
	}
	return f.proto + "|" + f.src.Addr().String() + "|" + f.dst.Addr().String() + ":" + strconv.Itoa(int(f.dst.Port()))
}

func (e *Engine) residualFor(keys ...string) (Verdict, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	for _, k := range keys {
		if r, ok := e.residual[k]; ok {
			if now.Before(r.until) {
				v := r.v
				v.Rule = "residual:" + v.Rule
				return v, true
			}
			delete(e.residual, k)
		}
	}
	return Verdict{}, false
}

func (f *Flow) account(now time.Time, n int64) {
	s := now.Unix()
	if s != f.sec {
		if f.sec != 0 {
			if f.secB > 0 && f.hotThreshold(f.secB, f.secP) {
				f.hot++
			} else {
				f.hot = 0
			}
		}
		f.sec, f.secB, f.secP = s, 0, 0
	}
	f.secB += n
	f.secP++
}

// hotThreshold is true if b exceeds the smallest rate threshold of any rule;
// precise per-rule checks happen in matches via f.hot, so one threshold per
// profile is supported (rules with different rates share the lowest).
func (f *Flow) hotThreshold(b, pk int64) bool {
	for i := range f.e.P.Rules {
		m := &f.e.P.Rules[i].Match
		if m.RateBps > 0 && b >= m.RateBps || m.RatePPS > 0 && pk >= m.RatePPS {
			return true
		}
	}
	return false
}

// learn parses client payload into f.info.
func (f *Flow) learn(p []byte) {
	if f.first == nil {
		f.first = append([]byte(nil), p...)
	}
	f.pkts++
	if f.proto == "udp" {
		f.learnUDP(p)
		return
	}
	if f.info.ready {
		return
	}
	if len(f.buf) < maxHello {
		f.buf = append(f.buf, p...)
	}
	b := f.buf
	if len(b) < 3 {
		return
	}
	switch c := dpi.Classify(b, false, int(f.dst.Port())); c {
	case dpi.ClassTLS:
		h, err := dpi.ParseClientHello(b, f.strict())
		switch {
		case err == dpi.ErrShort && len(b) < maxHello:
			return
		case err == dpi.ErrNotTLS || err != nil:
			f.ready(info{class: dpi.ClassUnknown})
		default:
			f.ready(info{class: c, sni: strings.ToLower(h.SNI), frag: h.Fragmented})
		}
	case dpi.ClassHTTP:
		host, ok := dpi.HTTPHost(b)
		if !ok && len(b) < maxHello && !bytes.Contains(b, []byte("\r\n\r\n")) {
			return
		}
		f.ready(info{class: c, host: strings.ToLower(host)})
	default:
		f.ready(info{class: dpi.ClassUnknown})
	}
}

func (f *Flow) learnUDP(p []byte) {
	if f.pkts == 1 {
		c := dpi.Classify(p, true, int(f.dst.Port()))
		f.info = info{class: c}
		if c == dpi.ClassDNS {
			f.info.qname, _ = dpi.DNSQuestion(p)
		}
		f.markReady()
	} else if f.info.class == dpi.ClassDNS {
		f.info.qname, _ = dpi.DNSQuestion(p) // every query is judged on its own name
	}
	if f.info.class == dpi.ClassQUIC && (f.strict() || f.pkts == 1) {
		if fr, err := dpi.QUICInitialFrags(p); err == nil {
			f.frags = append(f.frags, fr...)
			if sni := strings.ToLower(dpi.SNIFromFrags(f.frags)); sni != f.info.sni {
				f.info.sni = sni
				f.e.mu.Lock()
				f.e.seen = append(f.e.seen, Seen{Proto: "udp", Class: dpi.ClassQUIC, SNI: sni, Src: f.src, Dst: f.dst})
				f.e.mu.Unlock()
			}
		}
	}
}

func (f *Flow) ready(i info) {
	f.info = i
	f.markReady()
}

func (f *Flow) markReady() {
	f.info.ready = true
	f.e.mu.Lock()
	f.e.seen = append(f.e.seen, Seen{Proto: f.proto, Class: f.info.class, SNI: f.info.sni, Host: f.info.host, DNS: f.info.qname, Src: f.src, Dst: f.dst})
	f.e.mu.Unlock()
}

var passV = Verdict{Action: Action{Type: Pass}}

func (f *Flow) eval(d Dir, now time.Time) Verdict {
	for i := range f.e.P.Rules {
		r := &f.e.P.Rules[i]
		ok, pending := f.matches(&r.Match, d)
		if pending {
			return passV
		}
		if !ok {
			continue
		}
		if r.Prob > 0 {
			roll, done := f.rolls[i]
			if !done {
				f.e.mu.Lock()
				roll = f.e.rng.Float64() < r.Prob
				f.e.mu.Unlock()
				f.rolls[i] = roll
			}
			if !roll {
				continue
			}
		}
		v := Verdict{Action: r.Action, Rule: r.ID}
		if v.Type != Pass {
			f.e.mu.Lock()
			if !f.flagged[i] {
				f.flagged[i] = true
				f.e.hits = append(f.e.hits, Hit{Rule: r.ID, Action: r.Action.Type, Src: f.src, Dst: f.dst})
			}
			if r.Action.TTLSec > 0 {
				k := "src-dst"
				if r.Action.Key == "4tuple" {
					k = "4tuple"
				}
				f.e.residual[f.key(k)] = residual{until: now.Add(time.Duration(r.Action.TTLSec) * time.Second), v: v}
			}
			f.e.mu.Unlock()
		}
		return v
	}
	return passV
}

func (f *Flow) needsPayload(m *Match) bool {
	return len(m.Class) > 0 || len(m.NotClass) > 0 || len(m.SNI) > 0 || len(m.SNINotIn) > 0 ||
		len(m.Host) > 0 || len(m.DNS) > 0 || m.Entropy || m.Fragmented
}

// matches reports whether m holds, or that it cannot be decided yet.
func (f *Flow) matches(m *Match, d Dir) (ok, pending bool) {
	if m.Proto != "" && m.Proto != f.proto {
		return false, false
	}
	if m.Dir != "" {
		got := d.String()
		if m.Dir == "egress" || m.Dir == "ingress" {
			got = "ingress"
			if (d == C2S) != f.ingress {
				got = "egress"
			}
		}
		if m.Dir != got {
			return false, false
		}
	}
	if len(m.ICMPType) > 0 && !slices.Contains(m.ICMPType, f.curType) {
		return false, false
	}
	if m.MinLen > 0 && f.curLen < m.MinLen {
		return false, false
	}
	if len(m.Ports) > 0 && !slices.Contains(m.Ports, int(f.dst.Port())) {
		return false, false
	}
	if len(m.prefixes) > 0 && !anyPrefix(m.prefixes, f.out) {
		return false, false
	}
	if len(m.notPrefixes) > 0 && anyPrefix(m.notPrefixes, f.out) {
		return false, false
	}
	if m.AfterBytes > 0 && f.bytes < m.AfterBytes {
		return false, false
	}
	if (m.RateBps > 0 || m.RatePPS > 0) && f.hot < m.ForSec {
		return false, false
	}
	if !f.needsPayload(m) {
		return true, false
	}
	if !f.info.ready {
		return false, true
	}
	i := f.info
	if len(m.Class) > 0 && !slices.Contains(m.Class, i.class) {
		return false, false
	}
	if len(m.NotClass) > 0 && slices.Contains(m.NotClass, i.class) {
		return false, false
	}
	if len(m.SNI) > 0 && !nameIn(i.sni, m.SNI) {
		return false, false
	}
	if len(m.SNINotIn) > 0 && (i.class != dpi.ClassTLS && i.class != dpi.ClassQUIC || nameIn(i.sni, m.SNINotIn)) {
		return false, false
	}
	if len(m.Host) > 0 && !nameIn(i.host, m.Host) {
		return false, false
	}
	if len(m.DNS) > 0 && !nameIn(i.qname, m.DNS) {
		return false, false
	}
	if m.Entropy && !dpi.FullyEncrypted(f.first) {
		return false, false
	}
	if m.Fragmented && !i.frag {
		return false, false
	}
	return true, false
}

func anyPrefix(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// nameIn is a suffix match on DNS labels: "example.com" matches itself and
// "a.example.com".
func nameIn(name string, list []string) bool {
	if name == "" {
		return false
	}
	for _, s := range list {
		s = strings.ToLower(s)
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}
