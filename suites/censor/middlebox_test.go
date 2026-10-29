package censor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"

	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// middlebox is the original lab censor, now a thin wrapper over the profile
// engine: it forwards TCP, resets connections that are not a TLS ClientHello
// (active probes, rule LAB-PROBE) and resets TLS connections whose SNI is on
// the block list (rule LAB-SNI).
type middlebox struct {
	addr string
	e    *censor.Engine
}

func startMiddlebox(t *testing.T, upstream string, blocked ...string) *middlebox {
	t.Helper()
	sni, _ := json.Marshal(blocked)
	p, err := censor.Parse([]byte(`{"name":"middlebox","rules":[
	 {"id":"LAB-PROBE","source":"suites/censor","confidence":"assumed","match":{"proto":"tcp","not_class":["tls"]},"action":{"type":"rst"}},
	 {"id":"LAB-SNI","source":"suites/censor","confidence":"assumed","match":{"proto":"tcp","sni":` + string(sni) + `},"action":{"type":"rst"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := censor.New(p, 1)
	px, err := censor.StartTCP(e, upstream, netip.MustParseAddrPort("192.0.2.10:443"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(px.Close)
	return &middlebox{addr: px.Addr, e: e}
}

// snis lists the SNI of every ClientHello, in order.
func (m *middlebox) snis() (out []string) {
	for _, s := range m.e.Seen() {
		if s.Class == "tls" {
			out = append(out, s.SNI)
		}
	}
	return out
}

func (m *middlebox) probes() int  { return m.e.HitCount("LAB-PROBE") }
func (m *middlebox) dropped() int { return m.e.HitCount("LAB-SNI") }

// The censor blocks UDP (so h3 dies), drops the node's real SNI (so h2 dies)
// and resets probes. The client must land on cdnws with an innocent SNI, and
// the probe must not learn anything.
func TestMiddleboxFallbackLadder(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	mb := startMiddlebox(t, d.Addr, "node.blocked.example")
	udpHole, err := net.ListenPacket("udp", "127.0.0.1:0") // swallows QUIC
	if err != nil {
		t.Fatal(err)
	}
	defer udpHole.Close()

	e := harness.StaticEngine(d.Token(t, "mallory"),
		transport.Endpoint{Kind: transport.KindH3, Addr: udpHole.LocalAddr().String(), Host: "node.blocked.example", Pin: d.Pin},
		transport.Endpoint{Kind: transport.KindH2, Addr: mb.addr, Host: "node.blocked.example", Pin: d.Pin},
		transport.Endpoint{Kind: transport.KindCDNWS, Addr: mb.addr, Host: "cdn.allowed.example", Path: harness.WSPath, Pin: d.Pin},
	)
	defer e.Close()
	if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
		t.Fatalf("body %q", body)
	}
	if !strings.HasPrefix(e.Status(), "cdnws@") {
		t.Fatalf("status %q, want a fallback to cdnws", e.Status())
	}

	// Active probe: plain HTTP on the node's port is reset by the middlebox
	// and never reaches the node.
	hc := &http.Client{Timeout: 3 * time.Second}
	if resp, err := hc.Get("http://" + mb.addr + "/"); err == nil {
		resp.Body.Close()
		t.Fatal("probe got an answer")
	}
	// A TLS probe with a clean SNI only ever sees the decoy.
	tc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "cdn.allowed.example"}}, Timeout: 5 * time.Second} // we are the prober
	resp, err := tc.Get("https://" + mb.addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "Welcome") {
		t.Fatalf("probe saw %d %q, want the decoy", resp.StatusCode, b)
	}

	if mb.dropped() == 0 {
		t.Error("the blocked SNI was never tried: h2 should have been attempted first")
	}
	if mb.probes() != 1 {
		t.Errorf("probes = %d, want 1", mb.probes())
	}
}

// With every path cut the client reports an error instead of hanging.
func TestMiddleboxTotalBlock(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	mb := startMiddlebox(t, d.Addr, "node.blocked.example")
	e := harness.StaticEngine(d.Token(t, "mallory"), transport.Endpoint{Kind: transport.KindH2, Addr: mb.addr, Host: "node.blocked.example", Pin: d.Pin})
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, "tcp", harness.HostPort(origin.URL))
	if err == nil {
		c.Close()
		t.Fatal("dial succeeded through a total block")
	}
	if ctx.Err() != nil {
		t.Fatal("client hung instead of failing")
	}
}

// The relay sits behind a censor that resets non-TLS and filters SNI. Node and
// client both speak a plain Chrome ClientHello with the relay's innocent SNI,
// so everything passes; a blocked SNI never gets through.
func TestStealthPathThroughMiddlebox(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	var mb *middlebox
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port, Front: func(relay string) string {
		mb = startMiddlebox(t, relay, "blocked.example")
		return mb.addr
	}})
	e := s.Engine(t, reverse.KindReverse)
	defer e.Close()
	if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
		t.Fatalf("body %q", body)
	}
	for _, sni := range mb.snis() {
		if sni != harness.RelaySNI {
			t.Errorf("a client or node sent SNI %q: only the relay's cover name may appear on the wire", sni)
		}
	}
	if probes := mb.probes(); probes != 0 {
		t.Errorf("%d connections were not TLS ClientHellos: the stealth path must always look like TLS", probes)
	}
}

// UDP follows the ladder: with QUIC cut and the node's SNI blocked, the
// tunnel lands on cdnws and a UDP flow still round-trips through it.
func TestMiddleboxUDPFallsBackOffH3(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], a)
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	d := harness.StartDirect(t, harness.Bins.Core, port)
	mb := startMiddlebox(t, d.Addr, "node.blocked.example")
	udpHole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpHole.Close()
	udp := map[string]string{transport.ParamUDP: "1"}
	e := harness.StaticEngine(d.Token(t, "mallory"),
		transport.Endpoint{Kind: transport.KindH3, Addr: udpHole.LocalAddr().String(), Host: "node.blocked.example", Pin: d.Pin, Params: udp},
		transport.Endpoint{Kind: transport.KindH2, Addr: mb.addr, Host: "node.blocked.example", Pin: d.Pin, Params: udp},
		transport.Endpoint{Kind: transport.KindCDNWS, Addr: mb.addr, Host: "cdn.allowed.example", Path: harness.WSPath, Pin: d.Pin, Params: udp},
	)
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := e.DialPacket(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "ping" {
		t.Fatalf("echo %q err %v", b[:n], err)
	}
	if !strings.HasPrefix(e.Status(), "cdnws@") {
		t.Fatalf("status %q, want cdnws", e.Status())
	}
}
