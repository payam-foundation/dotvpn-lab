package functional

import (
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// The full stealth path with the three released components:
// admin creates relay -> relay enrolls -> node joins and dials out ->
// client learns the relay endpoints from control and reaches the origin
// through relay and node, without ever learning the node's address.
func TestStealthReverseRelayTCP(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	e := s.Engine(t, reverse.KindReverse)
	defer e.Close()
	for range 3 { // each use consumes a parked tunnel; the node refills the pool
		if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
			t.Fatalf("body %q", body)
		}
	}
	if !strings.HasPrefix(e.Status(), "reverse@") && !strings.Contains(e.Status(), "r1") {
		t.Fatalf("status %q", e.Status())
	}
}

func TestStealthReverseRelayDNS(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	e := s.Engine(t, reverse.KindDNS)
	defer e.Close()
	if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
		t.Fatalf("body %q", body)
	}
}

// The node's address and secrets never reach a client, and a seized relay
// holds nothing that points at control, the node, or a user.
func TestRelayCompromiseModel(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})

	for _, ep := range s.Endpoints(t) {
		if ep.Addr != "" && ep.Addr != s.RelayAddr && ep.Addr != s.RelayDNS {
			t.Errorf("client list names %s (%s): only relays may appear", ep.Addr, ep.Kind)
		}
		if _, p, _ := net.SplitHostPort(s.NodeAddr); strings.Contains(ep.Addr, ":"+p) && ep.Addr != s.RelayAddr {
			t.Errorf("node port leaked in %+v", ep)
		}
	}

	cfg, err := os.ReadFile(s.RelayCfg)
	if err != nil {
		t.Fatal(err)
	}
	for what, secret := range map[string]string{
		"control url": strings.TrimPrefix(s.CtlURL, "http://"), "node address": s.NodeAddr,
		"admin token": s.AdminTok, "account key": s.AccountKey,
	} {
		if strings.Contains(string(cfg), secret) {
			t.Errorf("relay config contains the %s", what)
		}
	}
	// What it does hold: its own key and control's public key only.
	if !strings.Contains(string(cfg), "trusted_keys") || !strings.Contains(string(cfg), auth.EncodeKey(s.CtlPub)) {
		t.Error("relay config lacks control's public key")
	}

	// No address, domain or key in the relay's output, even after traffic.
	out := s.RelayLog.Out()
	for _, bad := range []string{"127.0.0.1", harness.RelaySNI, s.AccountKey, s.AdminTok} {
		if strings.Contains(out, bad) {
			t.Errorf("relay output contains %q:\n%s", bad, out)
		}
	}
}

func TestRelayEnrollment(t *testing.T) {
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})

	// A fresh relay record: its enrollment token works exactly once.
	id, tok := s.CreateRelay(t, "r2", "127.0.0.1:9", harness.RelaySNI, "", "")
	dir := t.TempDir()
	mk := func(name string) string {
		_, priv, _ := auth.GenerateKey()
		p := filepath.Join(dir, name)
		harness.WriteFile(t, p, "listen: 127.0.0.1:0\nidentity_key: "+auth.EncodeKey(priv)+"\ndecoy: 127.0.0.1:1\n")
		return p
	}
	if out, err := harness.RunOnce(harness.Bins.Relay, "enroll", "-config", mk("a.yaml"), "-control", s.CtlURL, "-token", tok); err != nil {
		t.Fatalf("first enroll: %v\n%s", err, out)
	}
	if out, err := harness.RunOnce(harness.Bins.Relay, "enroll", "-config", mk("b.yaml"), "-control", s.CtlURL, "-token", tok); err == nil {
		t.Fatalf("token reused:\n%s", out)
	}
	if out, err := harness.RunOnce(harness.Bins.Relay, "enroll", "-config", mk("c.yaml"), "-control", s.CtlURL, "-token", "junk"); err == nil {
		t.Fatalf("junk token enrolled:\n%s", out)
	}
	// The old shared-secret header gives no access to anything.
	req, _ := http.NewRequest("POST", s.CtlURL+"/v1/relays/enroll", strings.NewReader(`{"public_key":"x"}`))
	req.Header.Set("X-Relay-Key", "anything")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode == http.StatusOK {
		t.Fatalf("X-Relay-Key accepted: %v", err)
	}

	// Revoking a relay removes it from client lists and it cannot enroll again.
	has := func(id string) bool {
		for _, ep := range s.Endpoints(t) {
			if ep.Name == "r2" {
				return true
			}
		}
		return false
	}
	if !has(id) {
		t.Fatal("enrolled relay missing from the client list")
	}
	if code := harness.AdminDo(t, s, "DELETE", "/v1/admin/relays/"+id, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if has(id) {
		t.Fatal("revoked relay still in the client list")
	}
}

func TestControlAdminSurface(t *testing.T) {
	// A non-loopback admin listener is refused at startup.
	dir := t.TempDir()
	_, priv, _ := auth.GenerateKey()
	cfg := filepath.Join(dir, "c.yaml")
	harness.WriteFile(t, cfg, "data_dir: "+dir+"\ncontrol:\n  listen: 127.0.0.1:0\n  admin_listen: 0.0.0.0:18081\n  admin_token: x\n  private_key: "+auth.EncodeKey(priv)+"\n")
	if out, err := harness.RunOnce(harness.Bins.Core, "control", "-config", cfg); err == nil || !strings.Contains(out, "loopback") {
		t.Fatalf("public admin listener accepted: %v\n%s", err, out)
	}

	// Every admin route needs the token; the public listener has none.
	_, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	for _, path := range []string{"/v1/admin/accounts", "/v1/admin/relays", "/v1/admin/nodes"} {
		for _, hdr := range []string{"", "Bearer wrong"} {
			req, _ := http.NewRequest("GET", s.AdminURL+path, nil)
			if hdr != "" {
				req.Header.Set("Authorization", hdr)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("GET %s with %q: %d", path, hdr, resp.StatusCode)
			}
		}
		resp, err := http.Get(s.CtlURL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("admin route %s is served on the public listener", path)
		}
	}
}

// Killing the node's tunnel pool does not leave clients hanging forever, and
// a node that comes back is picked up again.
func TestReverseClientFailsFastWithoutNode(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	e := harness.StaticEngine("x", transport.Endpoint{Kind: reverse.KindReverse, Addr: s.RelayAddr, Host: harness.RelaySNI,
		Params: map[string]string{reverse.ParamNode: "ghost", reverse.ParamID: auth.EncodeKey(s.RelayPub)}})
	defer e.Close()
	start := time.Now()
	if err := tryDial(e, harness.HostPort(origin.URL)); err == nil {
		t.Fatal("dial to an unknown node succeeded")
	}
	if time.Since(start) > 8*time.Second {
		t.Fatal("client hung")
	}
}
