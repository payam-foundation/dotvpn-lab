package censor

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"
)

func mustProfile(t *testing.T, js string) *Profile {
	t.Helper()
	p, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() { _ = tls.Client(a, &tls.Config{ServerName: sni}).Handshake() }()
	buf := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	return buf[:n]
}

var (
	src = netip.MustParseAddrPort("10.0.0.2:40000")
	dst = netip.MustParseAddrPort("192.0.2.10:443")
)

const src1 = `"source":"test","confidence":"assumed"`

func TestSNIRuleAndResidual(t *testing.T) {
	p := mustProfile(t, `{"name":"t","rules":[
	 {"id":"A",`+src1+`,"match":{"proto":"tcp","sni":["blocked.example"]},"action":{"type":"rst","ttl_s":60}}]}`)
	now := time.Unix(1000, 0)
	e := New(p, 1)
	e.Now = func() time.Time { return now }

	f := e.Open("tcp", src, dst)
	if v := f.Observe(C2S, hello(t, "ok.example")); v.Type != Pass {
		t.Fatalf("clean SNI: %+v", v)
	}
	f = e.Open("tcp", netip.MustParseAddrPort("10.0.0.2:40001"), dst)
	if v := f.Observe(C2S, hello(t, "a.blocked.example")); v.Type != RST || v.Rule != "A" {
		t.Fatalf("blocked SNI: %+v", v)
	}
	// Residual: a new flow from the same host to the same server is cut at once.
	f = e.Open("tcp", netip.MustParseAddrPort("10.0.0.2:40002"), dst)
	if v := f.Observe(C2S, nil); v.Type != RST || v.Rule != "residual:A" {
		t.Fatalf("residual: %+v", v)
	}
	now = now.Add(61 * time.Second)
	f = e.Open("tcp", netip.MustParseAddrPort("10.0.0.2:40003"), dst)
	if v := f.Observe(C2S, nil); v.Type != Pass {
		t.Fatalf("residual should have expired: %+v", v)
	}
	if e.HitCount("A") != 1 {
		t.Fatalf("hits %d", e.HitCount("A"))
	}
}

func TestStrictVersusNaive(t *testing.T) {
	h := hello(t, "blocked.example")
	body := h[5:]
	cut := 60
	split := append([]byte{0x16, 3, 1, 0, byte(cut)}, body[:cut]...)
	rest := body[cut:]
	split = append(split, 0x16, 3, 1, byte(len(rest)>>8), byte(len(rest)))
	split = append(split, rest...)
	rules := `"rules":[
	 {"id":"S",` + src1 + `,"match":{"proto":"tcp","sni":["blocked.example"]},"action":{"type":"drop"}},
	 {"id":"F",` + src1 + `,"match":{"proto":"tcp","fragmented_hello":true},"action":{"type":"drop"}}]`
	for _, tc := range []struct {
		dpi  string
		want string
	}{{"naive", Pass}, {"strict", Drop}} {
		e := New(mustProfile(t, `{"name":"t","dpi":"`+tc.dpi+`",`+rules+`}`), 1)
		f := e.Open("tcp", src, dst)
		var v Verdict
		for i := 0; i < len(split); i += 40 { // trickle in, like a real stream
			end := min(i+40, len(split))
			v = f.Observe(C2S, split[i:end])
		}
		if v.Type != tc.want {
			t.Errorf("%s: %+v, want %s", tc.dpi, v, tc.want)
		}
	}
}

func TestVolumeTriggerAndAfterBytes(t *testing.T) {
	p := mustProfile(t, `{"name":"t","rules":[
	 {"id":"V",`+src1+`,"match":{"rate_bps":1000,"for_sec":2},"action":{"type":"throttle","rate_bps":10}},
	 {"id":"B",`+src1+`,"match":{"after_bytes":5000,"proto":"tcp"},"action":{"type":"drop"}}]}`)
	now := time.Unix(1000, 0)
	e := New(p, 1)
	e.Now = func() time.Time { return now }
	f := e.Open("tcp", src, dst)
	var v Verdict
	for range 4 { // 1500 B per second for four seconds
		v = f.Observe(C2S, make([]byte, 1500))
		now = now.Add(time.Second)
	}
	if v.Type != Throttle {
		t.Fatalf("sustained rate should trigger: %+v", v)
	}
	f = e.Open("tcp", netip.MustParseAddrPort("10.0.0.3:1"), dst)
	for range 2 { // bursts below the rate threshold per second
		f.Observe(C2S, make([]byte, 900))
		now = now.Add(time.Second)
	}
	if v = f.Observe(C2S, make([]byte, 900)); v.Type != Pass {
		t.Fatalf("below rate: %+v", v)
	}
	if v = f.Observe(C2S, make([]byte, 4000)); v.Type != Drop || v.Rule != "B" {
		t.Fatalf("after_bytes: %+v", v)
	}
}

func TestDNSAndPrefixes(t *testing.T) {
	p := mustProfile(t, `{"name":"t","rules":[
	 {"id":"P",`+src1+`,"match":{"prefixes":["198.51.100.0/24"]},"action":{"type":"drop"}},
	 {"id":"D",`+src1+`,"match":{"proto":"udp","dns":["youtube.com"]},"action":{"type":"inject-dns"}}]}`)
	e := New(p, 1)
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'y', 'o', 'u', 't', 'u', 'b', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	f := e.Open("udp", src, netip.MustParseAddrPort("8.8.8.8:53"))
	if v := f.Observe(C2S, q); v.Type != InjectDNS {
		t.Fatalf("%+v", v)
	}
	if v := f.Observe(C2S, q); v.Type != InjectDNS { // not sticky, judged per query
		t.Fatalf("%+v", v)
	}
	f = e.Open("tcp", src, netip.MustParseAddrPort("198.51.100.7:443"))
	if v := f.Observe(C2S, nil); v.Type != Drop || v.Rule != "P" {
		t.Fatalf("%+v", v)
	}
}

func TestValidateRejectsUnsourcedRule(t *testing.T) {
	if _, err := Parse([]byte(`{"name":"t","rules":[{"id":"X","confidence":"assumed","match":{},"action":{"type":"drop"}}]}`)); err == nil {
		t.Fatal("rule without source accepted")
	}
	if _, err := Parse([]byte(`{"name":"t","rules":[{"id":"X","source":"s","confidence":"vibes","match":{},"action":{"type":"drop"}}]}`)); err == nil {
		t.Fatal("bad confidence accepted")
	}
}
