//go:build linux

package netlab

import (
	"fmt"
	"regexp"
	"strconv"
)

// CountLeaks counts, on the border, what the inside host sends anywhere but
// the allowed addresses. It is a plain nftables counter in its own table, in
// the prerouting hook ahead of everything else, so it sees packets whatever
// the censor does with them. Neighbour discovery and IGMP are not leaks.
type CountLeaks struct{ l *Lab }

const leakTable = "dvleak"

// CountLeaks installs the counters. allowed are IPv4 addresses the client may reach.
func (l *Lab) CountLeaks(allowed ...string) (*CountLeaks, error) {
	set := "{ " + InAddr
	for _, a := range allowed {
		set += ", " + a
	}
	set += " }"
	script := fmt.Sprintf(`table inet %[1]s {
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    iifname %[2]q ip protocol != igmp ip daddr != %[3]s counter comment "v4"
    iifname %[2]q ip protocol udp ip daddr != %[3]s counter comment "udp"
    iifname %[2]q ip protocol udp udp dport 53 counter comment "dns"
    iifname %[2]q meta nfproto ipv6 meta l4proto != ipv6-icmp counter comment "v6"
  }
}
`, leakTable, l.bdI, set)
	if err := l.Nft(l.Border, script); err != nil {
		return nil, err
	}
	return &CountLeaks{l}, nil
}

var counterLine = regexp.MustCompile(`counter packets (\d+) bytes \d+ comment "(\w+)"`)

// Packets returns the packet counts by name: v4 (anything not to an allowed
// address), udp (the same, UDP only), dns (UDP to port 53, anywhere) and v6.
func (c *CountLeaks) Packets() map[string]int {
	out, _ := c.l.Run(c.l.Border, "nft", "list", "chain", "inet", leakTable, "pre")
	m := map[string]int{}
	for _, g := range counterLine.FindAllStringSubmatch(out, -1) {
		m[g[2]], _ = strconv.Atoi(g[1])
	}
	return m
}
