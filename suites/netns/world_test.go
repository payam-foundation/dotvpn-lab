//go:build linux && lab

package netns

import (
	"testing"

	"github.com/payam-foundation/dotvpn-lab/internal/censor"
	"github.com/payam-foundation/dotvpn-lab/internal/labworld"
)

type world = labworld.World

func newWorld(t *testing.T, ips ...string) *world       { return labworld.New(t, ips...) }
func profile(t testing.TB, name string) *censor.Profile { return labworld.Profile(t, name) }
func originURL() string                                 { return labworld.OriginURL() }
func ping(w *world, ns, dst string, size, count int) error {
	return labworld.Ping(w, ns, dst, size, count)
}
