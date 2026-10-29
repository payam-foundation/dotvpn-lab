//go:build linux && lab

package netns

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/report"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

// The userspace matrix's direct-carrier cells, replayed at packet level. The
// same baseline.json must hold: a different verdict means the two backends
// disagree about a profile, which is a lab bug until proven otherwise.
func TestDirectCarriersMatchUserspace(t *testing.T) {
	bl, err := report.ReadBaseline(harness.Root() + "/profiles/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"baseline-pass", "iran-2026-10", "iran-allowlist", "iran-partition", "russia-2026-10", "russia-mobile-whitelist", "china-reference"}
	var profiles []*censor.Profile
	var ips []string
	for _, n := range names {
		p := profile(t, n)
		profiles = append(profiles, p)
		for _, pl := range p.PlacementList() {
			ips = append(ips, pl.IP)
		}
	}
	w := newWorld(t, ips...)
	w.StartNode(t)
	budget := 10 * time.Second
	if testing.Short() {
		budget = 6 * time.Second
	}
	var cells []report.Cell
	for _, p := range profiles {
		for _, pl := range p.PlacementList() {
			for _, carrier := range []string{"h3", "h2", "cdnws", "webtunnel", "ladder"} {
				key := p.Name + "/" + pl.Name + "/" + carrier
				exp, ok := bl.Expected[key]
				if !ok {
					continue
				}
				run := func() report.Cell {
					b, _ := w.Border(t, p)
					defer b.Stop()
					eps := w.Endpoints(pl.IP)
					use := []string{carrier}
					if carrier == "ladder" {
						use = []string{"h3", "h2", "cdnws", "webtunnel"}
					}
					var list = make([]transport.Endpoint, 0, len(use))
					for _, u := range use {
						list = append(list, eps[u])
					}
					c := w.Probe(t, list, budget)
					if carrier == "ladder" {
						c.Landed = strings.SplitN(c.Landed, "@", 2)[0]
					}
					c.Profile, c.Placement, c.Carrier = p.Name, pl.Name, carrier
					c.Rules = b.Rules()
					return c
				}
				c := run()
				if c.Verdict != exp.Verdict {
					c = run() // one retry, as the userspace matrix does
				}
				cells = append(cells, c)
				if c.Verdict != exp.Verdict {
					t.Errorf("%s: got %s, userspace baseline says %s (%s)", key, c.Verdict, exp.Verdict, exp.Reason)
				}
				if exp.Landed != "" && c.Landed != exp.Landed {
					t.Errorf("%s: ladder landed on %q, baseline says %q", key, c.Landed, exp.Landed)
				}
			}
		}
	}
	if out := os.Getenv("LAB_OUT"); out != "" {
		_ = os.MkdirAll(harness.Root()+"/"+out, 0o755)
		m := &report.Matrix{Generated: time.Now().UTC().Format(time.RFC3339), Disclaimer: report.Disclaimer, Cells: cells}
		b, _ := json.MarshalIndent(m, "", "  ")
		_ = os.WriteFile(harness.Root()+"/"+out+"/matrix-netns.json", b, 0o644)
	}
}
