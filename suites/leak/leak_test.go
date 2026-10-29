//go:build linux && lab

// Package leak runs the real dotvpn client (TUN and kill switch) in the inside
// namespace and counts, on the border, every packet that is not going to the
// tunnel endpoint. Linux only: macOS and Windows kill switches are covered by
// unit tests of internal/leak and are not exercised here.
package leak

import (
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/labworld"
	"github.com/payam-foundation/dotvpn-lab/internal/netlab"
)

const (
	endpointIP = "203.0.113.10" // the node: the only address the client may talk to
	publicIP   = "203.0.113.20" // any other host abroad: reachable only if something leaks
	stunPort   = "3478"
)

type env struct {
	w      *labworld.World
	leaks  *netlab.CountLeaks
	config string
}

func setup(t *testing.T) *env {
	t.Helper()
	w := labworld.New(t, endpointIP, publicIP)
	w.StartNode(t)
	leaks, err := w.Lab.CountLeaks(endpointIP)
	if err != nil {
		t.Fatal(err)
	}
	cfg := t.TempDir() + "/client.yaml"
	harness.WriteFile(t, cfg, fmt.Sprintf(`token: %s
endpoints:
  - kind: h2
    addr: %s:443
    host: %s
    pin: %s
`, w.D.TokenFor(t, "leak", time.Hour), endpointIP, labworld.NodeSNI, w.Pin))
	return &env{w, leaks, cfg}
}

func (e *env) client(t *testing.T, args ...string) *harness.Proc {
	t.Helper()
	p := harness.Start(t, e.w.Lab.Cmd(e.w.Lab.In, harness.Bins.Client, append([]string{"-config", e.config}, args...)...))
	harness.WaitFor(t, 20*time.Second, "tunnel up", func() bool { return strings.Contains(p.Out(), "full tunnel up") })
	return p
}

func (e *env) tool(args ...string) (string, error) {
	out, err := e.w.Lab.Cmd(e.w.Lab.In, harness.Bins.Labtool, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// getOK fetches the origin page, retrying while the ladder connects.
func (e *env) getOK(t *testing.T, host string) {
	t.Helper()
	url := fmt.Sprintf("http://%s:%d/", host, labworld.OriginPort)
	var out string
	var err error
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(300 * time.Millisecond) {
		if out, err = e.tool("get", "-url", url); err == nil && out == "origin-ok" {
			return
		}
	}
	t.Fatalf("GET %s through the tunnel: %q %v", url, out, err)
}

// probes tries every way a stray application could reach the outside. None
// may reach the border outside the tunnel; without a tunnel they must fail.
func (e *env) probes(t *testing.T, label string, tunnelUp bool) {
	t.Helper()
	url := fmt.Sprintf("http://%s:%d/", publicIP, labworld.OriginPort)
	// With the tunnel up a plain TCP connection is captured by the TUN and
	// legitimately works; the border counters decide whether it leaked.
	if out, err := e.tool("get", "-url", url); (err == nil) != tunnelUp {
		t.Errorf("%s: plain TCP to %s: err=%v out=%q, tunnel up=%v", label, publicIP, err, out, tunnelUp)
	}
	if _, err := e.tool("get", "-url", "http://[2001:db8::1]:8080/"); err == nil {
		t.Errorf("%s: IPv6 TCP succeeded", label)
	}
	_, _ = e.tool("udp", "-addr", publicIP+":"+stunPort) // STUN-like: no reply expected either way
	_, _ = e.tool("udp", "-addr", "[2001:db8::1]:"+stunPort)
	// The OS resolver must not reach a real resolver.
	if out, err := e.tool("lookup", "-name", "leak.example.org"); err == nil {
		ips := strings.Trim(out, "[]")
		for ip := range strings.FieldsSeq(ips) {
			if a, perr := netip.ParseAddr(ip); perr != nil || !netip.MustParsePrefix("198.18.0.0/15").Contains(a) {
				t.Errorf("%s: resolver answered %s, want a fakedns address", label, ip)
			}
		}
	}
}

func (e *env) assertNoLeak(t *testing.T, base map[string]int, label string) {
	t.Helper()
	now := e.leaks.Packets()
	for _, k := range []string{"v4", "udp", "dns", "v6"} {
		if now[k] != base[k] {
			t.Errorf("%s: %d %s packet(s) reached the border outside the tunnel", label, now[k]-base[k], k)
		}
	}
}

// The control: without the client every probe leaks, so a zero later means
// the kill switch worked and not that the counters are blind.
func TestCountersSeeLeaks(t *testing.T) {
	e := setup(t)
	base := e.leaks.Packets()
	e.getOK(t, publicIP)
	_, _ = e.tool("udp", "-addr", publicIP+":"+stunPort)
	_, _ = e.tool("get", "-url", "http://[2001:db8::1]:8080/")
	_, _ = e.tool("lookup", "-name", "example.org")
	now := e.leaks.Packets()
	for _, k := range []string{"v4", "udp", "dns", "v6"} {
		if now[k] <= base[k] {
			t.Errorf("control: %s counter did not move without the client (%v)", k, now)
		}
	}
}

// Tunnel up: traffic works and nothing else leaves. Then the tunnel dies
// mid-flow (node killed): still nothing leaves. Then the client itself is
// killed: the rules outlive it, and -unblock removes them.
func TestKillSwitch(t *testing.T) {
	e := setup(t)
	base := e.leaks.Packets() // zero: startup and the ladder's first dials must not leak either
	c := e.client(t, "-kill-switch")
	e.getOK(t, publicIP) // goes through the tunnel and the node
	t.Logf("counters with the tunnel up: %v", base)
	e.probes(t, "tunnel up", true)
	e.assertNoLeak(t, base, "tunnel up")

	// A long download is in flight when the tunnel drops.
	dl := e.w.Lab.Cmd(e.w.Lab.In, harness.Bins.Labtool, "dl", "-url", fmt.Sprintf("http://%s:%d/big?n=%d", publicIP, labworld.OriginPort, 4<<30))
	if err := dl.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- dl.Wait() }()
	time.Sleep(2 * time.Second)
	e.w.Node.Stop(syscall.SIGKILL)
	select {
	case err := <-done:
		if err == nil {
			t.Error("download finished although the node was killed")
		}
	case <-time.After(60 * time.Second):
		_ = dl.Process.Kill()
		t.Error("download still hanging 60 s after the tunnel died")
	}
	e.probes(t, "tunnel dead", false)
	e.assertNoLeak(t, base, "tunnel dead")

	// Client crash: the kill switch must stay.
	c.Stop(syscall.SIGKILL)
	e.probes(t, "client crashed", false)
	e.assertNoLeak(t, base, "client crashed")
	if out, err := e.w.Lab.Run(e.w.Lab.In, "iptables", "-S", "DOTVPN_KS"); err != nil {
		t.Errorf("kill-switch chain gone after a crash: %v %s", err, out)
	}

	// -unblock restores connectivity.
	if out, err := e.w.Lab.Run(e.w.Lab.In, harness.Bins.Client, "-config", e.config, "-unblock"); err != nil {
		t.Fatalf("-unblock: %v %s", err, out)
	}
	e.getOK(t, publicIP)
}

// Tunnel without kill switch: documents what -tun alone does and does not cover.
func TestTunWithoutKillSwitchStillBlocksIPv6AndUDP(t *testing.T) {
	e := setup(t)
	base := e.leaks.Packets()
	e.client(t, "-tun")
	e.getOK(t, publicIP)
	_, _ = e.tool("udp", "-addr", publicIP+":"+stunPort)
	if _, err := e.tool("get", "-url", "http://[2001:db8::1]:8080/"); err == nil {
		t.Error("IPv6 TCP succeeded through a tunnel that blackholes IPv6")
	}
	_, _ = e.tool("lookup", "-name", "leak.example.org")
	e.assertNoLeak(t, base, "tun only")
}
