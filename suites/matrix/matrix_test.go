// Package matrix runs every userspace profile against every carrier and
// compares the verdicts with profiles/baseline.json.
package matrix

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/probe"
	"github.com/payam-foundation/dotvpn-lab/internal/report"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

var profileNames = []string{
	"baseline-pass", "iran-2026-10", "iran-allowlist", "iran-partition",
	"russia-2026-10", "russia-mobile-whitelist", "china-reference",
}

const (
	nodeSNI = "node.lab.example" // stands for a blocklisted node name
	cdnSNI  = "cdn.lab.example"  // stands for a CDN host fronting a carrier
	wtSNI   = "wt.lab.example"
)

// carriers measured through a direct node.
var directCarriers = []string{"h3", "h2", "cdnws", "webtunnel", "ladder"}

var (
	mu    sync.Mutex
	cells []report.Cell
)

func profilesDir() string { return filepath.Join(harness.Root(), "profiles") }

func TestMatrix(t *testing.T) {
	if testing.Short() && os.Getenv("LAB_MATRIX") == "" {
		t.Skip("matrix is slow; run `make matrix` or set LAB_MATRIX=1")
	}
	conf := map[string]string{}
	type job struct {
		p  *censor.Profile
		pl censor.Placement
	}
	var jobs []job
	for _, n := range profileNames {
		p, err := censor.Load(profilesDir(), n)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Rules {
			conf[p.Name+"/"+r.ID] = r.Confidence
		}
		for _, pl := range p.PlacementList() {
			jobs = append(jobs, job{p, pl})
		}
	}

	t.Run("cells", func(t *testing.T) {
		sem := make(chan struct{}, 3)
		for _, j := range jobs {
			t.Run(j.p.Name+"_"+j.pl.Name, func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				runGroup(t, j.p, j.pl)
			})
		}
	})

	m := &report.Matrix{Generated: time.Now().UTC().Format(time.RFC3339), Disclaimer: report.Disclaimer, Confidence: conf, Cells: cells}
	slices.SortFunc(m.Cells, func(a, b report.Cell) int { return strings.Compare(a.Key(), b.Key()) })
	if out := os.Getenv("LAB_OUT"); out != "" {
		out = filepath.Join(harness.Root(), out)
		_ = os.MkdirAll(out, 0o755)
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "matrix.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bpath := filepath.Join(profilesDir(), "baseline.json")
	old, _ := report.ReadBaseline(bpath)
	if os.Getenv("LAB_UPDATE") != "" {
		b, _ := json.MarshalIndent(report.BaselineFrom(m, old), "", "  ")
		if err := os.WriteFile(bpath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if old == nil {
		t.Fatalf("no baseline at %s: run with LAB_UPDATE=1 after reviewing the matrix", bpath)
	}
	changed, added, missing := report.Diff(m, old)
	for _, s := range slices.Concat(changed, added) {
		t.Error(s)
	}
	for _, s := range missing {
		t.Errorf("baseline cell not run: %s", s)
	}
}

func record(c report.Cell) {
	mu.Lock()
	cells = append(cells, c)
	mu.Unlock()
}

// runGroup measures every carrier for one profile and placement. A cell whose
// verdict differs from the baseline is measured once more before it counts.
func runGroup(t *testing.T, p *censor.Profile, pl censor.Placement) {
	dst := netip.MustParseAddrPort(pl.IP + ":443")
	origin, port := harness.StartOrigin(t)
	bl, _ := report.ReadBaseline(filepath.Join(profilesDir(), "baseline.json"))

	measure := func(carrier string, once func() report.Cell) {
		c := once()
		c.Profile, c.Placement, c.Carrier = p.Name, pl.Name, carrier
		if bl != nil {
			if e, ok := bl.Expected[c.Key()]; ok && e.Verdict != c.Verdict {
				r := once()
				r.Profile, r.Placement, r.Carrier = c.Profile, c.Placement, c.Carrier
				c = r
			}
		}
		record(c)
	}

	d := harness.StartDirect(t, harness.Bins.Core, port)
	tcpFront := func(e *censor.Engine, up string) *censor.Proxy {
		px, err := censor.StartTCP(e, up, dst)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(px.Close)
		return px
	}
	udpFront := func(e *censor.Engine, up string, dport uint16) *censor.Proxy {
		px, err := censor.StartUDP(e, up, netip.AddrPortFrom(dst.Addr(), dport))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(px.Close)
		return px
	}

	for _, carrier := range directCarriers {
		measure(carrier, func() report.Cell {
			e := censor.New(p, 1)
			tcp, udp := tcpFront(e, d.Addr), udpFront(e, d.Addr, 443)
			eps := map[string]transport.Endpoint{
				"h3":        {Kind: transport.KindH3, Addr: udp.Addr, Host: nodeSNI, Pin: d.Pin},
				"h2":        {Kind: transport.KindH2, Addr: tcp.Addr, Host: nodeSNI, Pin: d.Pin},
				"cdnws":     {Kind: transport.KindCDNWS, Addr: tcp.Addr, Host: cdnSNI, Path: harness.WSPath, Pin: d.Pin},
				"webtunnel": {Kind: transport.KindWebTunnel, Addr: tcp.Addr, Host: wtSNI, Path: harness.WTPath, Pin: d.Pin},
			}
			var use []transport.Endpoint
			if carrier == "ladder" {
				use = []transport.Endpoint{eps["h3"], eps["h2"], eps["cdnws"], eps["webtunnel"]}
			} else {
				use = []transport.Endpoint{eps[carrier]}
			}
			eng := harness.StaticEngine(d.Token(t, "matrix"), use...)
			defer eng.Close()
			c := probe.Probe(eng, origin.URL, 10*time.Second, true)
			if carrier == "ladder" {
				c.Landed = strings.SplitN(eng.Status(), "@", 2)[0]
			}
			c.Rules = rules(e)
			return c
		})
	}

	// Reverse path: client and node both cross the censor to reach the relay.
	for _, kind := range []transport.Kind{reverse.KindReverse, reverse.KindDNS} {
		measure(string(kind), func() report.Cell {
			e := censor.New(p, 1)
			s := harness.StartStack(t, harness.StackOpts{
				OriginPort: port, NoWaitParked: true,
				Front:    func(relay string) string { return tcpFront(e, relay).Addr },
				FrontDNS: func(dns string) string { return udpFront(e, dns, 53).Addr },
			})
			eng := s.Engine(t, kind)
			c := probe.Probe(eng, origin.URL, 25*time.Second, kind != reverse.KindDNS)
			c.Rules = rules(e)
			return c
		})
	}
}

func rules(e *censor.Engine) []string {
	set := map[string]bool{}
	for _, h := range e.Hits() {
		set[h.Rule] = true
	}
	var out []string
	for r := range set {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}
