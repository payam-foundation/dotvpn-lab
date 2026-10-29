package chaos

import (
	"syscall"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// Relay restarts (userspace, any OS): the node's parked tunnels die with the
// relay and the node must refill the pool, then a client must get through
// again. This is the pool refill time from the Hetzner resilience run.
func TestRelayRestartRefillsPool(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	e := s.Engine(t, reverse.KindReverse)
	if harness.FetchVia(t, e, origin.URL) != "origin-ok" {
		t.Fatal("no baseline fetch")
	}
	s.RelayLog.Stop(syscall.SIGKILL)
	time.Sleep(2 * time.Second)
	t0 := time.Now()
	harness.Run(t, harness.Bins.Relay, "run", "-config", s.RelayCfg)
	harness.WaitTCP(t, s.RelayReal)
	harness.WaitFor(t, 60*time.Second, "node tunnels parked again", func() bool { return s.Parked(t) >= 1 })
	refill := time.Since(t0)
	if harness.FetchVia(t, e, origin.URL) != "origin-ok" {
		t.Fatal("no fetch after the relay restarted")
	}
	t.Logf("relay restart: pool refilled in %s", refill)
	if refill > 45*time.Second {
		t.Errorf("pool refill took %s, ceiling 45s", refill)
	}
}
