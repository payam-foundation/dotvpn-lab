//go:build linux && lab

package netns

import (
	"slices"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/netlab"
)

// iran-icmp-2026-10: IR-4 (one-way ping), IR-5 (size), IR-3 (volume trigger).
func TestIranICMP(t *testing.T) {
	p := profile(t, "iran-icmp-2026-10")
	w := newWorld(t, "203.0.113.10")
	b, _ := w.Border(t, p)
	defer b.Stop()
	dst := "203.0.113.10"

	// IR-4: echo requests from inside are dropped, so ping from inside fails...
	if err := ping(w, w.Lab.In, dst, 56, 2); err == nil {
		t.Fatal("ping from inside succeeded; IR-4 should drop echo requests going out")
	}
	// ...while ping from abroad to inside is answered (requests pass in, replies are type 0).
	if err := ping(w, w.Lab.Out, netlab.InAddr, 56, 2); err != nil {
		t.Fatalf("ping from abroad to inside failed: %v", err)
	}
	if !slices.Contains(b.Rules(), "IR-4") {
		t.Errorf("rules fired %v, want IR-4", b.Rules())
	}
	// IR-5: large payload is dropped in the direction that is allowed.
	if err := ping(w, w.Lab.Out, netlab.InAddr, 1000, 2); err == nil {
		t.Error("large ping from abroad passed; IR-5 should drop payloads over 640 B")
	}
	if !slices.Contains(b.Rules(), "IR-5") {
		t.Errorf("rules fired %v, want IR-5", b.Rules())
	}
	// IR-3: a flood trips the volume rule; afterwards even small pings are dropped for a while.
	_, _ = w.Lab.Run(w.Lab.Out, "ping", "-f", "-c", "6000", "-s", "16", netlab.InAddr)
	time.Sleep(3 * time.Second)
	if err := ping(w, w.Lab.Out, netlab.InAddr, 16, 2); err == nil {
		t.Error("ping right after a flood passed; IR-3 should hold a residual block")
	}
	if !slices.Contains(b.Rules(), "IR-3") {
		t.Errorf("rules fired %v, want IR-3", b.Rules())
	}
	time.Sleep(8 * time.Second) // block ends
	if err := ping(w, w.Lab.Out, netlab.InAddr, 16, 2); err != nil {
		t.Errorf("ping after the block expired failed: %v", err)
	}
}
