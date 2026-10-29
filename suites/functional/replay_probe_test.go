package functional

import (
	"crypto/tls"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/frame"
	"github.com/payam-foundation/dotvpn-wire/handshake"
	"github.com/payam-foundation/dotvpn-wire/mimic"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// probe opens a connection to addr, runs fn, and returns everything read
// until the peer closes or 1.5s of silence.
func probe(t *testing.T, addr string, send func(net.Conn)) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	send(c)
	var out []byte
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return string(out) + "<silence>"
			}
			return string(out) + "<closed>"
		}
	}
}

// tlsGET does a TLS handshake with sni and a GET /, returning status and body.
func tlsGET(t *testing.T, addr, sni string) string {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) // prober, not a client
	if err != nil {
		t.Fatalf("tls probe %s sni=%q: %v", addr, sni, err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	s := string(b)
	// Date differs between requests; everything else must match.
	var keep []string
	for _, l := range strings.Split(s, "\r\n") {
		if !strings.HasPrefix(l, "Date:") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func TestActiveProbingIndistinguishableFromDecoy(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})

	hello := func(sni string, key []byte) []byte {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		h, err := mimic.Hello(a, sni, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	probes := map[string]func(addr string) string{
		"plain http": func(a string) string {
			return probe(t, a, func(c net.Conn) { _, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n") })
		},
		"random bytes": func(a string) string {
			return probe(t, a, func(c net.Conn) { _, _ = c.Write([]byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc}) })
		},
		"valid sni": func(a string) string { return tlsGET(t, a, harness.RelaySNI) },
		"wrong sni": func(a string) string { return tlsGET(t, a, "www.wrong.example") },
		"no sni":    func(a string) string { return tlsGET(t, a, "") },
		"partial hello": func(a string) string {
			return probe(t, a, func(c net.Conn) { _, _ = c.Write(hello(harness.RelaySNI, []byte("not-a-key"))[:30]) })
		},
	}
	for name, p := range probes {
		t.Run(name, func(t *testing.T) {
			got, want := p(s.RelayReal), p(s.DecoyAddr)
			if got != want {
				t.Errorf("relay and decoy differ.\nrelay: %q\ndecoy: %q", got, want)
			}
		})
	}
}

// A hello with the wrong knock, a knock for a node that has no tunnel here,
// and any replayed knock are all just visitors: they get the decoy's
// ServerHello, never silence or a reset.
func TestProbeResistanceAndReplay(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})

	var nodeID string
	for _, ep := range s.Endpoints(t) {
		if ep.Kind == reverse.KindReverse {
			nodeID = ep.Params[reverse.ParamNode]
		}
	}
	if nodeID == "" {
		t.Fatal("no reverse endpoint in the list")
	}
	helloFor := func(key []byte) []byte {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		h, err := mimic.Hello(a, harness.RelaySNI, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	// serverHello reports whether the answer starts like a TLS handshake
	// record, which is what a real web server answers to a ClientHello.
	serverHello := func(h []byte) bool {
		r := probe(t, s.RelayReal, func(c net.Conn) { _, _ = c.Write(h) })
		return strings.HasPrefix(r, "\x16\x03")
	}

	if !serverHello(helloFor(mimic.KnockKey("junk", []byte("x")))) {
		t.Error("a wrong knock did not get the decoy's answer")
	}
	if !serverHello(helloFor(reverse.ClientKnockKey(s.RelayPub, "ghost-node"))) {
		t.Error("a knock for an unknown node did not get the decoy's answer")
	}

	// A valid client knock is accepted once (it is spliced onto a parked node
	// tunnel and so stays quiet until the handshake) ...
	h := helloFor(reverse.ClientKnockKey(s.RelayPub, nodeID))
	if serverHello(h) {
		t.Fatal("a valid knock was answered by the decoy")
	}
	// ... and the same bytes replayed by a censor are not.
	if !serverHello(h) {
		t.Error("a replayed knock was accepted instead of getting the decoy's answer")
	}
	// The same holds for the pool knock the node uses.
	ph := helloFor(reverse.PoolKnockKey(s.RelayPub))
	probe(t, s.RelayReal, func(c net.Conn) { _, _ = c.Write(ph) }) // first use: relay waits for a handshake
	if !serverHello(ph) {
		t.Error("a replayed pool knock was accepted")
	}
}

// Nobody gets into the pool without a token signed by control for the pool
// audience, so a scanner that knows the (public) pool knock still parks nothing.
func TestPoolRequiresControlToken(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	before := s.Parked(t)

	_, other, _ := auth.GenerateKey()
	forged, _ := auth.NewSigner(other).Mint(auth.Claims{Sub: "n", Aud: auth.AudPool}, time.Minute)
	for name, tok := range map[string]string{"junk": "junk", "forged": forged} {
		c, err := net.Dial("tcp", s.RelayReal)
		if err != nil {
			t.Fatal(err)
		}
		if err := mimic.Dial(c, harness.RelaySNI, reverse.PoolKnockKey(s.RelayPub)); err != nil {
			t.Fatal(err)
		}
		outer, err := handshake.Initiate(c, s.RelayPub, frame.Opts{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = reverse.WriteAuth(outer, tok)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := outer.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s token: relay kept the connection open", name)
		}
		c.Close()
	}
	// Parked count can only move because the real node refills its pool.
	time.Sleep(500 * time.Millisecond)
	if after := s.Parked(t); after > before+4 {
		t.Errorf("parked %d -> %d: unauthenticated connections were parked", before, after)
	}
}

// The relay's answer time to an unauthenticated hello must match the decoy's:
// a relay that thinks (or does crypto) before falling back is a timing tell.
func TestProbeTimingMatchesDecoy(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	measure := func(addr string) time.Duration {
		var ds []time.Duration
		for range 15 {
			start := time.Now()
			_ = tlsGET(t, addr, harness.RelaySNI)
			ds = append(ds, time.Since(start))
		}
		slices.Sort(ds)
		return ds[len(ds)/2]
	}
	measure(s.DecoyAddr) // warm up
	relay, decoy := measure(s.RelayReal), measure(s.DecoyAddr)
	diff := relay - decoy
	if diff < 0 {
		diff = -diff
	}
	t.Logf("median probe time: relay %v, decoy %v", relay, decoy)
	if diff > 40*time.Millisecond {
		t.Errorf("relay and decoy differ by %v", diff)
	}
}
