//go:build linux

package censor

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// The nft backend compiles the leading, stateless part of a profile into
// nftables rules. Rules are kept in order: every static rule up to the first
// one that needs state or payload is enforced by the kernel; from that rule on
// everything is queued to the engine (nfq_linux.go), which evaluates the whole
// profile again, so both backends give the same verdict.

const nftTable = "dvlab"

// isStatic reports whether a rule can be enforced by nftables alone.
func isStatic(r *Rule) bool {
	m, a := &r.Match, r.Action
	if r.Prob > 0 || len(m.Class) > 0 || len(m.NotClass) > 0 || len(m.SNI) > 0 || len(m.SNINotIn) > 0 ||
		len(m.Host) > 0 || len(m.DNS) > 0 || m.Entropy || m.Fragmented || m.AfterBytes > 0 ||
		m.RateBps > 0 || m.RatePPS > 0 || m.MinLen > 0 || m.Dir == "c2s" || m.Dir == "s2c" {
		return false
	}
	if a.TTLSec > 0 {
		return false
	}
	switch a.Type {
	case Pass, Drop:
		return true
	case RST:
		return m.Proto == "tcp"
	}
	return false
}

func quoteSet(items []string) string { return "{ " + strings.Join(items, ", ") + " }" }

func intSet(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return quoteSet(s)
}

// ruleLines renders one static rule. A flow has an initiator side and each
// packet is original or reply, so a rule that names ports expands to four nft
// rules (conntrack tells original from reply); one that does not, to two.
// Egress means the packet travels from inside to outside, as in the engine.
func ruleLines(r *Rule, inside netip.Prefix) []string {
	m := &r.Match
	verdict := map[string]string{Pass: "accept", Drop: "drop", RST: "reject with tcp reset"}[r.Action.Type]
	var out []string
	for _, egress := range []bool{true, false} {
		dir := "ingress"
		if egress {
			dir = "egress"
		}
		if m.Dir != "" && m.Dir != dir {
			continue
		}
		var base []string
		far := "ip daddr"
		if egress {
			base = append(base, "ip saddr "+inside.String())
		} else {
			base = append(base, "ip daddr "+inside.String())
			far = "ip saddr"
		}
		if m.Proto != "" {
			base = append(base, "meta l4proto "+m.Proto)
		} else if len(m.Ports) > 0 {
			base = append(base, "meta l4proto { tcp, udp }")
		}
		if len(m.Prefixes) > 0 {
			base = append(base, far+" "+quoteSet(m.Prefixes))
		}
		if len(m.NotPrefixes) > 0 {
			base = append(base, far+" != "+quoteSet(m.NotPrefixes))
		}
		if len(m.ICMPType) > 0 {
			base = append(base, "icmp type "+intSet(m.ICMPType))
		}
		if len(m.Ports) == 0 {
			out = append(out, fmt.Sprintf("%s counter %s comment %q", strings.Join(base, " "), verdict, r.ID))
			continue
		}
		for _, orig := range []bool{true, false} {
			port := "th dport"
			ct := "original"
			if !orig {
				port, ct = "th sport", "reply"
			}
			l := append(slicesClone(base), "ct direction "+ct, port+" "+intSet(m.Ports))
			out = append(out, fmt.Sprintf("%s counter %s comment %q", strings.Join(l, " "), verdict, r.ID))
		}
	}
	return out
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// compileNFT returns the nft script for the profile and the index of the first
// dynamic rule (len(rules) if none).
func compileNFT(p *Profile, inside netip.Prefix, queue uint16) (script string, firstDynamic int) {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n chain lab {\n  type filter hook forward priority 0; policy accept;\n", nftTable)
	firstDynamic = len(p.Rules)
	for i := range p.Rules {
		r := &p.Rules[i]
		if !isStatic(r) {
			firstDynamic = i
			fmt.Fprintf(&b, "  counter queue num %d bypass\n", queue)
			break
		}
		for _, l := range ruleLines(r, inside) {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}
	b.WriteString(" }\n}\n")
	return b.String(), firstDynamic
}

var counterRe = regexp.MustCompile(`counter packets (\d+) bytes \d+ .*comment "([^"]+)"`)

// parseCounters sums the per-rule packet counters out of `nft list chain`.
func parseCounters(out string) map[string]int64 {
	res := map[string]int64{}
	for _, l := range strings.Split(out, "\n") {
		if m := counterRe.FindStringSubmatch(l); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			res[m[2]] += n
		}
	}
	return res
}
