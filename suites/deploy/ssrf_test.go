// Package deploy checks what ships: the production core build (no e2e tag)
// keeps its egress guard, and the real Docker images run as documented and
// survive an upgrade and a rollback on the same volume.
package deploy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func dialVia(t *testing.T, d *harness.Direct, target string) error {
	t.Helper()
	e := harness.StaticEngine(d.Token(t, "alice"), transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin})
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, "tcp", target)
	if err == nil {
		c.Close()
	}
	return err
}

// The release build refuses loopback, RFC1918, CGNAT, link-local and the
// cloud metadata address even for a port the operator allowed, while the
// e2e build (same config, same origin) reaches the loopback origin. The e2e
// run is the control: it proves a refusal comes from the guard, not from a
// broken tunnel.
func TestProductionCoreBlocksPrivateEgress(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	originAddr := harness.HostPort(origin.URL)

	e2e := harness.StartDirect(t, harness.Bins.Core, port, 80)
	if err := dialVia(t, e2e, originAddr); err != nil {
		t.Fatalf("control: e2e core cannot reach the loopback origin: %v", err)
	}

	prod := harness.StartDirect(t, harness.Bins.CoreProd, port, 80)
	targets := map[string]string{
		"loopback":        originAddr,
		"loopback v6":     net.JoinHostPort("::1", "80"),
		"rfc1918 10/8":    "10.0.0.1:80",
		"rfc1918 192.168": "192.168.1.1:80",
		"rfc1918 172.16":  "172.16.0.1:80",
		"cgnat":           "100.64.0.1:80",
		"link-local":      "169.254.1.1:80",
		"cloud metadata":  "169.254.169.254:80",
		"unspecified":     "0.0.0.0:80",
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			err := dialVia(t, prod, target)
			if err == nil {
				t.Fatalf("production core connected to %s", target)
			}
			t.Logf("refused: %v", err)
		})
	}
}
