//go:build linux

// Package labworld is the netns lab plus a core node and an origin outside it,
// shared by the packet-level suites (netns, leak, chaos, perf).
package labworld

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/censor"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/netlab"
	"github.com/payam-foundation/dotvpn-lab/internal/report"
	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

const (
	OriginPort = 8080
	NodeSNI    = "node.lab.example"
	CDNSNI     = "cdn.lab.example"
	WTSNI      = "wt.lab.example"
)

func OriginURL() string { return fmt.Sprintf("http://%s:%d", netlab.OutAddr, OriginPort) }

func Profile(t testing.TB, name string) *censor.Profile {
	t.Helper()
	p, err := censor.Load(harness.Root()+"/profiles", name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// World is the lab with an origin and a core node running outside.
type World struct {
	Lab  *netlab.Lab
	D    *harness.Direct
	Pin  string
	Cfg  string        // node config, kept so the node can be restarted with the same identity
	Node *harness.Proc // the running node
}

// New builds the topology, with abroad addresses for every ip given.
func New(t *testing.T, ips ...string) *World {
	t.Helper()
	l := netlab.New(t)
	l.Abroad(ips...)
	harness.Start(t, l.Cmd(l.Out, harness.Bins.Labtool, "origin", "-addr", fmt.Sprintf("0.0.0.0:%d", OriginPort)))
	return &World{Lab: l}
}

// StartNode runs a core node in the outside namespace on every abroad address.
func (w *World) StartNode(t *testing.T) {
	t.Helper()
	pub, priv, _ := auth.GenerateKey()
	w.D = &harness.Direct{Priv: priv}
	dir := t.TempDir()
	cfg := dir + "/node.yaml"
	w.Cfg = cfg
	harness.WriteFile(t, cfg, fmt.Sprintf(`data_dir: %q
node:
  name: lab
  listen: 0.0.0.0:443
  admin_listen: 127.0.0.1:9100
  allowed_ports: [%d]
  trusted_keys: [%s]
  transports:
    h3: true
    cdnws_path: %s
    webtunnel_path: %s
`, dir, OriginPort, auth.EncodeKey(pub), harness.WSPath, harness.WTPath))
	w.RunNode(t)
}

// RunNode (re)starts the node from w.Cfg and returns once its pin is readable.
func (w *World) RunNode(t *testing.T) {
	t.Helper()
	w.Node = harness.Start(t, w.Lab.Cmd(w.Lab.Out, harness.Bins.Core, "node", "-config", w.Cfg))
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		out, err := w.Lab.Cmd(w.Lab.Out, harness.Bins.Labtool, "pin", "-addr", "127.0.0.1:443").Output()
		if err == nil {
			if w.Pin != "" && w.Pin != string(out) {
				t.Fatalf("node pin changed across restart: %s -> %s", w.Pin, out)
			}
			w.Pin = string(out)
			break
		}
		if time.Now().After(end) {
			t.Fatal("core node did not start")
		}
	}
	time.Sleep(300 * time.Millisecond) // the UDP (h3) listener binds just after TCP
}

// probe runs the client from the inside namespace.
func (w *World) Probe(t *testing.T, eps []transport.Endpoint, budget time.Duration) report.Cell {
	t.Helper()
	b, _ := json.Marshal(eps)
	cmd := w.Lab.Cmd(w.Lab.In, harness.Bins.Labtool, "probe", "-endpoints", string(b), "-token", w.D.Token(t, "lab"),
		"-origin", OriginURL(), "-budget", budget.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("labtool probe: %v: %s", err, stderr.String())
	}
	var c report.Cell
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatalf("labtool probe output %q: %v", out, err)
	}
	return c
}

func (w *World) Endpoints(ip string) map[string]transport.Endpoint {
	return map[string]transport.Endpoint{
		"h3":        {Kind: transport.KindH3, Addr: ip + ":443", Host: NodeSNI, Pin: w.Pin},
		"h2":        {Kind: transport.KindH2, Addr: ip + ":443", Host: NodeSNI, Pin: w.Pin},
		"cdnws":     {Kind: transport.KindCDNWS, Addr: ip + ":443", Host: CDNSNI, Path: harness.WSPath, Pin: w.Pin},
		"webtunnel": {Kind: transport.KindWebTunnel, Addr: ip + ":443", Host: WTSNI, Path: harness.WTPath, Pin: w.Pin},
	}
}

func (w *World) Border(t *testing.T, p *censor.Profile) (*censor.Border, *censor.Engine) {
	t.Helper()
	e := censor.New(p, 1)
	b, err := censor.StartBorder(w.Lab, e)
	if err != nil {
		t.Fatal(err)
	}
	return b, e
}

func Ping(w *World, ns, dst string, size int, count int) error {
	_, err := w.Lab.Run(ns, "ping", "-c", fmt.Sprint(count), "-W", "1", "-s", fmt.Sprint(size), dst)
	return err
}

func Sh(t *testing.T, w *World, ns string, name string, args ...string) string {
	t.Helper()
	out, err := w.Lab.Cmd(ns, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}
