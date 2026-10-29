//go:build linux

package censor

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCompileNFT(t *testing.T) {
	p, err := Parse([]byte(`{"name":"t","rules":[
	 {"id":"A","source":"s","confidence":"assumed","match":{"proto":"tcp","ports":[443],"prefixes":["198.51.100.0/24"]},"action":{"type":"drop"}},
	 {"id":"B","source":"s","confidence":"assumed","match":{"proto":"udp","class":["quic"],"sni":["x.example"]},"action":{"type":"drop"}},
	 {"id":"C","source":"s","confidence":"assumed","match":{},"action":{"type":"drop"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s, first := compileNFT(p, netip.MustParsePrefix("10.77.1.0/24"), 0)
	if first != 1 {
		t.Fatalf("first dynamic rule = %d, want 1 (B needs the payload)", first)
	}
	for _, want := range []string{"ip daddr { 198.51.100.0/24 }", "ct direction original th dport { 443 }", "queue num 0 bypass", `comment "A"`} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, `comment "C"`) {
		t.Error("rules after the first dynamic one must be left to the engine")
	}
	if m := parseCounters(`ip daddr { 1.1.1.1 } counter packets 7 bytes 100 drop comment "A"`); m["A"] != 7 {
		t.Errorf("parseCounters = %v", m)
	}
}
