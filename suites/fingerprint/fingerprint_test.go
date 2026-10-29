// Package fingerprint compares what an observer computes from our connections
// with what Chrome and a stock web server produce (REPORT.md needs-validation:
// JA3/JA4 and packet sizes).
//
// Baselines are measurements, not guesses:
//   - Chrome 156 ClientHello JA4 and extension set: docs/hetzner-test-report.md
//     "Fingerprint and traffic-shape pass".
//   - Server side: the relay must answer as the decoy behind it. The harness
//     decoy is a Go TLS server; the Hetzner run compared against nginx 1.28.
//
// Size and timing are recorded and written to $LAB_OUT/fingerprint.json; no
// tolerance is asserted until enough runs exist to set one.
package fingerprint

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor/dpi"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/measure"
	"github.com/payam-foundation/dotvpn-wire/mimic"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

const (
	chrome156JA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"
	// Non-GREASE extensions of Chrome 156 in ascending order.
)

var chromeExts = []uint16{0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 51764, 65037, 65281}

var results = map[string]any{}

func record(t *testing.T, key string, v any) {
	t.Helper()
	results[key] = v
	if dir := os.Getenv("LAB_OUT"); dir != "" {
		root := harness.Root()
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, dir)
		}
		_ = os.MkdirAll(dir, 0o755)
		b, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "fingerprint.json"), b, 0o644)
	}
}

func knockHello(t *testing.T, sni string, key []byte) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h, err := mimic.Hello(a, sni, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func parse(t *testing.T, rec []byte) *measure.Hello {
	t.Helper()
	h, err := measure.ParseHello(rec)
	if err != nil {
		t.Fatalf("not a ClientHello: %v", err)
	}
	return h
}

func exts(h *measure.Hello) string {
	b, _ := json.Marshal(h.SortedExtensions())
	return string(b)
}

// The knock hello is the Chrome hello: same JA4, same extension set, and a
// JA3 that varies per connection as Chrome's does (extension shuffling).
func TestKnockHelloMatchesChrome(t *testing.T) {
	ja3s := map[string]bool{}
	for range 20 {
		h := parse(t, knockHello(t, "cdn.example.com", mimic.KnockKey("x", []byte("y"))))
		if got := h.JA4(); got != chrome156JA4 {
			t.Fatalf("JA4 %s, Chrome 156 is %s", got, chrome156JA4)
		}
		if !slices.Equal(h.SortedExtensions(), chromeExts) {
			t.Fatalf("extensions %s, Chrome 156 sends %v", exts(h), chromeExts)
		}
		ja3s[h.JA3()] = true
	}
	if len(ja3s) < 10 {
		t.Errorf("only %d distinct JA3 in 20 hellos: Chrome shuffles extensions, a constant JA3 is a tell", len(ja3s))
	}
	record(t, "knock_hello", map[string]any{"ja4": chrome156JA4, "distinct_ja3_of_20": len(ja3s)})
}

// Every ClientHello our components put on the wire toward a relay, whether
// from a client or from the node's pool, has the Chrome JA4. The tee sits
// where the censor sits.
func TestRelayPathHellosMatchChrome(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	var tee *measure.Tee
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port, Front: func(real string) string {
		var err error
		if tee, err = measure.NewTee(real); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(tee.Close)
		return tee.Addr
	}})
	e := s.Engine(t, reverse.KindReverse)
	defer e.Close()
	for range 3 {
		if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
			t.Fatalf("body %q", body)
		}
	}
	conns := tee.Conns()
	if len(conns) < 2 {
		t.Fatalf("tee saw %d connections, want node pool and client", len(conns))
	}
	var shapes []map[string]any
	for i, c := range conns {
		h := parse(t, c.First)
		if h.JA4() != chrome156JA4 {
			t.Errorf("conn %d JA4 %s, want %s", i, h.JA4(), chrome156JA4)
		}
		// The censor's own first-packet classifiers (CN-ENT-1 entropy rule,
		// protocol class) must not flag what we send.
		if dpi.FullyEncrypted(c.First) || dpi.Classify(c.First, false, 443) != dpi.ClassTLS {
			t.Errorf("conn %d first packet flagged by the censor classifier (class %s)", i, dpi.Classify(c.First, false, 443))
		}
		shapes = append(shapes, shape(c))
	}
	record(t, "relay_path_conns", shapes)
}

// A direct h2 connection to core is a TLS client of the Chrome family too.
func TestCoreH2HelloMatchesChrome(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	tee, err := measure.NewTee(d.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tee.Close()
	e := harness.StaticEngine(d.Token(t, "alice"), transport.Endpoint{Kind: transport.KindH2, Addr: tee.Addr, Host: "node.example.com", Pin: d.Pin})
	defer e.Close()
	if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
		t.Fatalf("body %q", body)
	}
	conns := tee.Conns()
	if len(conns) == 0 {
		t.Fatal("tee saw nothing")
	}
	h := parse(t, conns[0].First)
	t.Logf("client-to-core h2: %s", h.Describe())
	if h.JA4() != chrome156JA4 {
		t.Errorf("client-to-core JA4 %s, want Chrome's %s", h.JA4(), chrome156JA4)
	}
	record(t, "core_h2", shape(conns[0]))
}

// The relay answers a non-knock hello exactly as the decoy behind it: same
// ServerHello summary and record length, for the right SNI and a wrong one.
func TestRelayServerHelloMatchesDecoy(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	first := func(addr, sni string) string {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(knockHello(t, sni, []byte("not-a-valid-knock-key-000000000000"))); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		rec, err := measure.ReadRecord(c)
		if err != nil {
			t.Fatalf("no TLS record from %s: %v", addr, err)
		}
		return measure.DescribeServer(rec)
	}
	for _, sni := range []string{harness.RelaySNI, "www.wrong.example"} {
		got, want := first(s.RelayReal, sni), first(s.DecoyAddr, sni)
		if got != want {
			t.Errorf("sni %q: relay %q, decoy %q", sni, got, want)
		}
	}
}

// shape summarises what a passive observer sees of one connection: the
// first-flight size, the client-to-server packet-size spread, and idle gaps.
func shape(c measure.Conn) map[string]any {
	var up, down []int
	var gaps []time.Duration
	var last time.Duration
	for _, ch := range c.Chunks {
		if ch.ToServer {
			up = append(up, ch.Size)
		} else {
			down = append(down, ch.Size)
		}
		if g := ch.At - last; g > 0 {
			gaps = append(gaps, g)
		}
		last = ch.At
	}
	sort.Ints(up)
	sort.Ints(down)
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	q := func(v []int, p int) int {
		if len(v) == 0 {
			return 0
		}
		return v[len(v)*p/100]
	}
	var maxGap time.Duration
	if len(gaps) > 0 {
		maxGap = gaps[len(gaps)-1]
	}
	return map[string]any{
		"first_flight": len(c.First), "up_chunks": len(up), "down_chunks": len(down),
		"up_p50": q(up, 50), "up_p90": q(up, 90), "down_p50": q(down, 50), "down_p90": q(down, 90),
		"max_gap_ms": maxGap.Milliseconds(),
	}
}

// captureHello runs transport.DialTLS against a listener that records the
// first TLS record and hangs up, and returns that ClientHello.
func captureHello(t *testing.T, ep transport.Endpoint, o transport.Options) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 16<<10)
		n, _ := io.ReadAtLeast(c, buf, 5)
		if need := 5 + int(buf[3])<<8 + int(buf[4]); n < need {
			m, _ := io.ReadFull(c, buf[n:need])
			n += m
		}
		got <- buf[:n]
	}()
	ep.Addr = ln.Addr().String()
	raw, err := transport.DialTCP(t.Context(), ep.Addr, o)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = transport.DialTLS(t.Context(), raw, ep, o, "h2", "http/1.1") // fails: the listener hangs up
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello captured")
		return nil
	}
}

// echConfigList is a syntactically valid ECHConfigList (X25519, HKDF-SHA256,
// AES-128-GCM, public name "front.example"). Nobody holds the private key; the
// hello is only inspected, never answered.
func echConfigList(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u16 := func(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
	pub := key.PublicKey().Bytes()
	c := []byte{1}
	c = append(c, u16(0x0020)...)
	c = append(c, u16(len(pub))...)
	c = append(c, pub...)
	c = append(c, u16(4)...)
	c = append(c, u16(1)...)
	c = append(c, u16(1)...)
	c = append(c, 64, byte(len("front.example")))
	c = append(c, "front.example"...)
	c = append(c, u16(0)...)
	cfg := append(u16(0xfe0d), u16(len(c))...)
	cfg = append(cfg, c...)
	return base64.StdEncoding.EncodeToString(append(u16(len(cfg)), cfg...))
}

// Offering ECH (real config, or the GREASE the preset sends when ech is off or
// has no record) must not change what an observer fingerprints: the Chrome 156
// JA4 and extension set, with the ECH extension 65037 present either way. A
// require-mode client that fell over to a different hello would be a tell.
func TestECHHelloMatchesChrome(t *testing.T) {
	cfg := echConfigList(t)
	for _, tc := range []struct{ name, ech string }{
		{"no ech param (preset GREASE)", ""},
		{"real ech config", cfg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := transport.Endpoint{Kind: transport.KindH2, Host: "cdn.example.com"}
			if tc.ech != "" {
				ep.Params = map[string]string{"ech": tc.ech}
			}
			h := parse(t, captureHello(t, ep, transport.Options{DialTimeout: 3 * time.Second}))
			if got := h.JA4(); got != chrome156JA4 {
				t.Errorf("JA4 %s, Chrome 156 is %s", got, chrome156JA4)
			}
			if !slices.Equal(h.SortedExtensions(), chromeExts) {
				t.Errorf("extensions %s, Chrome 156 sends %v", exts(h), chromeExts)
			}
			record(t, "ech_hello_"+map[bool]string{true: "real", false: "grease"}[tc.ech != ""], map[string]any{"ja4": h.JA4()})
		})
	}
}
