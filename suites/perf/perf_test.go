//go:build linux && lab

// Package perf measures throughput and small-request latency through each
// carrier in the lab, with no censor and no impairment, so a drop is the
// software and not the path. Numbers are written to $LAB_OUT/perf.json and
// compared with profiles/perf-baseline.json when that file has the carrier.
// Nightly only: set LAB_PERF=1.
package perf

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/labworld"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

const nodeIP = "203.0.113.10"

type result struct {
	MBps      float64 `json:"mbps"`
	LatencyUS int64   `json:"latency_us"`
}

// band is how far below the committed baseline a run may fall. Lab throughput
// is bounded by veth and one CPU, so it is noisy; the first nightly runs set
// the baseline, tighten it only after the spread is known.
const band = 0.5

func TestCarrierThroughput(t *testing.T) {
	if os.Getenv("LAB_PERF") == "" {
		t.Skip("nightly only: set LAB_PERF=1")
	}
	w := labworld.New(t, nodeIP)
	w.StartNode(t)
	var base map[string]result
	if b, err := os.ReadFile(harness.Root() + "/profiles/perf-baseline.json"); err == nil {
		_ = json.Unmarshal(b, &base)
	}
	got := map[string]result{}
	for _, k := range []string{"h2", "h3", "cdnws", "webtunnel"} {
		t.Run(k, func(t *testing.T) {
			b, _ := json.Marshal([]transport.Endpoint{w.Endpoints(nodeIP)[k]})
			cmd := w.Lab.Cmd(w.Lab.In, harness.Bins.Labtool, "bench", "-endpoints", string(b), "-token", w.D.TokenFor(t, "perf", time.Hour),
				"-origin", labworld.OriginURL(), "-bytes", "268435456")
			o, err := cmd.Output()
			if err != nil {
				t.Fatalf("bench: %v", err)
			}
			var r result
			if err := json.Unmarshal(o, &r); err != nil {
				t.Fatalf("bench output %q: %v", o, err)
			}
			got[k] = r
			t.Logf("%s: %.1f MB/s, median small-request latency %d us", k, r.MBps, r.LatencyUS)
			if b, ok := base[k]; ok {
				if r.MBps < b.MBps*(1-band) {
					t.Errorf("%s throughput %.1f MB/s is below %.0f%% of baseline %.1f", k, r.MBps, (1-band)*100, b.MBps)
				}
				if float64(r.LatencyUS) > float64(b.LatencyUS)*(1+band)+2000 {
					t.Errorf("%s latency %d us is above baseline %d us + %.0f%%", k, r.LatencyUS, b.LatencyUS, band*100)
				}
			}
		})
	}
	if d := os.Getenv("LAB_OUT"); d != "" {
		_ = os.MkdirAll(harness.Root()+"/"+d, 0o755)
		b, _ := json.MarshalIndent(got, "", "  ")
		_ = os.WriteFile(harness.Root()+"/"+d+"/perf.json", b, 0o644)
	}
}
