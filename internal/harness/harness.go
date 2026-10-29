// Package harness runs the released binaries of dotvpn-core and dotvpn-relay and
// the dotvpn-client library against each other, with censor simulators in
// between. Core is built twice: with -tags e2e (loopback origins allowed, so
// the tests can reach httptest servers) and as released (SSRF guard on).
package harness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-client/client"
	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/discovery"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/cdnws"
	"github.com/payam-foundation/dotvpn-wire/transport/h2connect"
	"github.com/payam-foundation/dotvpn-wire/transport/h3connect"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
	"github.com/payam-foundation/dotvpn-wire/transport/snowflake"
	"github.com/payam-foundation/dotvpn-wire/transport/webtunnel"
)

// Bins holds the paths of the binaries built by Main.
var Bins struct{ Core, CoreProd, Relay, Labtool, Client string }

// Main builds the binaries, runs the package tests and cleans up. Each suite
// package calls it from its TestMain.
func Main(m *testing.M) {
	if d := os.Getenv("LAB_BINS"); d != "" { // prebuilt (cross-built for the lab container)
		Bins.Core, Bins.CoreProd, Bins.Relay = filepath.Join(d, "core-e2e"), filepath.Join(d, "core"), filepath.Join(d, "relay")
		Bins.Labtool = filepath.Join(d, "labtool")
		Bins.Client = filepath.Join(d, "dotvpn")
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "dotvpn-lab-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	Bins.Core = filepath.Join(dir, "core-e2e")
	Bins.CoreProd = filepath.Join(dir, "core")
	Bins.Relay = filepath.Join(dir, "relay")
	Bins.Labtool = filepath.Join(dir, "labtool")
	Bins.Client = filepath.Join(dir, "dotvpn")
	for _, b := range []struct {
		out, repo, pkg string
		tags           string
	}{
		{Bins.Core, "../dotvpn-core", "./cmd/dotvpn-core", "e2e"},
		{Bins.CoreProd, "../dotvpn-core", "./cmd/dotvpn-core", ""},
		{Bins.Relay, "../dotvpn-relay", "./cmd/dotvpn-relay", ""},
		{Bins.Labtool, ".", "./cmd/labtool", ""},
		{Bins.Client, "../dotvpn-client", "./cmd/dotvpn", ""},
	} {
		args := []string{"build", "-trimpath", "-o", b.out}
		if b.tags != "" {
			args = append(args, "-tags", b.tags)
		}
		cmd := exec.Command("go", append(args, b.pkg)...)
		cmd.Dir = filepath.Join(Root(), b.repo)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", b.repo, err, out)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// Root returns the dotvpn-lab module directory (siblings live next to it).
func Root() string {
	if d := os.Getenv("LAB_ROOT"); d != "" {
		return d
	}
	wd, _ := os.Getwd()
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if d == filepath.Dir(d) {
			return wd
		}
	}
}

// ---- processes ----

type Proc struct {
	Cmd  *exec.Cmd
	Done chan struct{} // closed when the process has exited
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (p *Proc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.Write(b)
}

func (p *Proc) Out() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

// run starts bin and stops it when the test ends. Output is shown on failure.
func Run(t *testing.T, bin string, args ...string) *Proc {
	t.Helper()
	return Start(t, exec.Command(bin, args...))
}

// Start runs cmd in the background and stops it when the test ends.
func Start(t *testing.T, cmd *exec.Cmd) *Proc {
	t.Helper()
	p := &Proc{Cmd: cmd, Done: make(chan struct{})}
	bin, args := filepath.Base(cmd.Path), cmd.Args[1:]
	if len(args) == 0 {
		args = []string{""}
	}
	cmd.Stdout, cmd.Stderr = p, p
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait(); close(p.Done) }()
	t.Cleanup(func() {
		p.Stop(syscall.SIGTERM)
		if t.Failed() {
			t.Logf("%s %s output:\n%s", filepath.Base(bin), args[0], p.Out())
		}
	})
	return p
}

// Stop sends sig and waits for exit, killing the process after 5 s.
func (p *Proc) Stop(sig os.Signal) {
	_ = p.Cmd.Process.Signal(sig)
	select {
	case <-p.Done:
	case <-time.After(5 * time.Second):
		_ = p.Cmd.Process.Kill()
		<-p.Done
	}
}

// RunOnce runs bin to completion and returns its combined output.
func RunOnce(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return string(out), err
}

func FreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func FreeUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

func WaitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func WaitTCP(t *testing.T, addr string) {
	t.Helper()
	WaitFor(t, 20*time.Second, "tcp "+addr, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
}

func WriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- origin and local proxy ----

// BulkPath serves BulkSize zero bytes from the origin.
const (
	BulkPath = "/bulk"
	BulkSize = 512 << 10
)

func StartOrigin(t *testing.T) (*httptest.Server, int) {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == BulkPath { // fixed-size body for throughput probes
			w.Header().Set("Content-Length", strconv.Itoa(BulkSize))
			_, _ = w.Write(make([]byte, BulkSize))
			return
		}
		fmt.Fprint(w, "origin-ok")
	}))
	t.Cleanup(s.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	n, _ := strconv.Atoi(port)
	return s, n
}

func HostPort(u string) string { return strings.TrimPrefix(u, "http://") }

func LocalProxy(t *testing.T, e *client.Engine) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lp := &client.LocalProxy{Dial: e.DialContext}
	go func() { _ = lp.Serve(ctx, ln) }()
	return ln.Addr().String()
}

// FetchVia GETs origin through the engine, retrying while tunnels come up
// (reverse pools refill after each use).
func FetchVia(t *testing.T, e *client.Engine, origin string) string {
	t.Helper()
	pu, _ := url.Parse("http://" + LocalProxy(t, e))
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}, Timeout: 10 * time.Second}
	var last error
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		resp, err := hc.Get(origin)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return string(b)
		}
		last = fmt.Errorf("status %d", resp.StatusCode)
	}
	t.Fatalf("fetch via engine: %v", last)
	return ""
}

func Dialers() map[transport.Kind]transport.Dialer {
	return map[transport.Kind]transport.Dialer{
		transport.KindH2:        h2connect.Dialer{},
		transport.KindH3:        h3connect.Dialer{},
		transport.KindCDNWS:     cdnws.Dialer{},
		transport.KindWebTunnel: webtunnel.Dialer{},
		transport.KindSnowflake: snowflake.Dialer{Opts: transport.Options{DialTimeout: 40 * time.Second}},
		reverse.KindReverse:     reverse.Dialer{},
		reverse.KindDNS:         reverse.Dialer{},
	}
}

func StaticEngine(tok string, eps ...transport.Endpoint) *client.Engine {
	return client.NewEngine(client.EngineConfig{
		Endpoints: eps, Dialers: Dialers(), Token: func() string { return tok }, Stagger: 100 * time.Millisecond,
	})
}

// ---- a direct node (core binary, static trust) ----

type Direct struct {
	Addr string
	Pin  string
	Priv ed25519.PrivateKey
	P    *Proc
}

func (d *Direct) Token(t *testing.T, sub string) string {
	t.Helper()
	return d.TokenFor(t, sub, time.Minute)
}

// TokenFor mints a token that stays valid for ttl (long runs outlive a minute).
func (d *Direct) TokenFor(t *testing.T, sub string, ttl time.Duration) string {
	t.Helper()
	tok, err := auth.NewSigner(d.Priv).Mint(auth.Claims{Sub: sub}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const (
	WSPath = "/ws-secret"
	WTPath = "/wt-secret"
)

func StartDirect(t *testing.T, bin string, ports ...int) *Direct {
	t.Helper()
	pub, priv, _ := auth.GenerateKey()
	dir := t.TempDir()
	addr := FreeAddr(t)
	var pl []string
	for _, p := range ports {
		pl = append(pl, strconv.Itoa(p))
	}
	cfg := filepath.Join(dir, "node.yaml")
	WriteFile(t, cfg, fmt.Sprintf(`data_dir: %q
node:
  name: e2e
  listen: %s
  admin_listen: %s
  allowed_ports: [%s]
  allowed_udp_ports: [%s]
  trusted_keys: [%s]
  transports:
    h3: true
    cdnws_path: %s
    webtunnel_path: %s
`, dir, addr, FreeAddr(t), strings.Join(pl, ","), strings.Join(pl, ","), auth.EncodeKey(pub), WSPath, WTPath))
	d := &Direct{Addr: addr, Priv: priv, P: Run(t, bin, "node", "-config", cfg)}
	WaitTCP(t, addr)
	time.Sleep(300 * time.Millisecond) // the UDP (h3) listener binds just after TCP
	d.Pin = PinOf(t, addr)
	return d
}

func PinOf(t *testing.T, addr string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // learning the pin of our own test node
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return transport.SPKIPin(c.ConnectionState().PeerCertificates[0])
}

// ---- the three-component stack ----

type Stack struct {
	CtlURL, AdminURL, AdminTok string
	CtlPub                     ed25519.PublicKey
	RelayReal, RelayAddr       string // listen address, and the address nodes and clients use
	RelayDNS, RelayAdmin       string
	RelayDNSAddr               string // the DNS address clients use
	RelayPub                   ed25519.PublicKey
	RelayCfg, RelayID          string
	RelayLog                   *Proc
	DecoyAddr                  string
	NodeAddr                   string
	AccountKey                 string
}

type StackOpts struct {
	OriginPort int
	// Front lets a test put a middlebox between everybody and the relay.
	Front func(relayListen string) string
	// NoWaitParked returns once control lists the relay, without requiring
	// the node's tunnel to park: a censor may stop it from ever parking.
	NoWaitParked bool
	// FrontDNS does the same for the relay's UDP DNS listener.
	FrontDNS func(relayDNS string) string
}

func AdminDo(t *testing.T, s *Stack, method, path string, body, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, s.AdminURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+s.AdminTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: %d: %v", method, path, resp.StatusCode, err)
		}
	}
	return resp.StatusCode
}

type relayCreated struct {
	Relay struct {
		ID string `json:"id"`
	} `json:"relay"`
	EnrollTokens string `json:"enroll_token"`
}

func (s *Stack) CreateRelay(t *testing.T, name, addr, sni, dnsAddr, zone string) (id, token string) {
	t.Helper()
	var r relayCreated
	body := map[string]string{"name": name, "addr": addr, "sni": sni, "dns_addr": dnsAddr, "dns_zone": zone}
	if code := AdminDo(t, s, "POST", "/v1/admin/relays", body, &r); code != http.StatusCreated {
		t.Fatalf("create relay: %d", code)
	}
	return r.Relay.ID, r.EnrollTokens
}

const RelaySNI = "cdn.example.com"
const DNSZone = "t.example.com"

// StartStack brings up control, one enrolled relay, and one hidden node that
// joined control and dials the relay out. It returns when the node's tunnel
// is parked at the relay.
func StartStack(t *testing.T, o StackOpts) *Stack {
	t.Helper()
	s := &Stack{AdminTok: "admin-secret-for-e2e"}
	dir := t.TempDir()

	// Control plane.
	cpub, cpriv, _ := auth.GenerateKey()
	s.CtlPub = cpub
	ctlAddr, admAddr := FreeAddr(t), FreeAddr(t)
	s.CtlURL, s.AdminURL = "http://"+ctlAddr, "http://"+admAddr
	ctlCfg := filepath.Join(dir, "control.yaml")
	WriteFile(t, ctlCfg, fmt.Sprintf(`data_dir: %q
control:
  listen: %s
  admin_listen: %s
  admin_token: %s
  private_key: %s
  token_ttl: 15m
`, dir, ctlAddr, admAddr, s.AdminTok, auth.EncodeKey(cpriv)))
	Run(t, Bins.Core, "control", "-config", ctlCfg)
	WaitTCP(t, ctlAddr)
	WaitTCP(t, admAddr)

	// Relay: its own key, a real TLS decoy, enrolled with a one-time token.
	decoy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = io.WriteString(w, "decoy "+r.URL.Path)
	}))
	t.Cleanup(decoy.Close)
	s.DecoyAddr = decoy.Listener.Addr().String()
	rpub, rpriv, _ := auth.GenerateKey()
	s.RelayPub = rpub
	s.RelayReal, s.RelayDNS, s.RelayAdmin = FreeAddr(t), FreeUDP(t), FreeAddr(t)
	s.RelayAddr, s.RelayDNSAddr = s.RelayReal, s.RelayDNS
	if o.Front != nil {
		s.RelayAddr = o.Front(s.RelayReal)
	}
	if o.FrontDNS != nil {
		s.RelayDNSAddr = o.FrontDNS(s.RelayDNS)
	}
	s.RelayCfg = filepath.Join(dir, "relay.yaml")
	WriteFile(t, s.RelayCfg, fmt.Sprintf(`listen: %s
dns_listen: %s
dns_zone: %s
identity_key: %s
decoy: %s
admin_listen: %s
`, s.RelayReal, s.RelayDNS, DNSZone, auth.EncodeKey(rpriv), s.DecoyAddr, s.RelayAdmin))
	var tok string
	s.RelayID, tok = s.CreateRelay(t, "r1", s.RelayAddr, RelaySNI, s.RelayDNSAddr, DNSZone)
	if out, err := RunOnce(Bins.Relay, "enroll", "-config", s.RelayCfg, "-control", s.CtlURL, "-token", tok); err != nil {
		t.Fatalf("enroll: %v\n%s", err, out)
	}
	s.RelayLog = Run(t, Bins.Relay, "run", "-config", s.RelayCfg)
	WaitTCP(t, s.RelayReal)
	WaitTCP(t, s.RelayAdmin)

	// Hidden node: joins control, then dials the relay out.
	var jt struct {
		JoinToken string `json:"join_token"`
	}
	if code := AdminDo(t, s, "POST", "/v1/admin/join-tokens", nil, &jt); code != http.StatusCreated {
		t.Fatalf("join token: %d", code)
	}
	_, npriv, _ := auth.GenerateKey()
	s.NodeAddr = FreeAddr(t)
	nodeCfg := filepath.Join(dir, "node.yaml")
	WriteFile(t, nodeCfg, fmt.Sprintf(`data_dir: %q
node:
  name: hidden
  listen: %s
  admin_listen: %s
  hidden: true
  identity_key: %s
  allowed_ports: [%d]
  allowed_udp_ports: [%d]
  join:
    url: %s
    token: %s
`, dir, s.NodeAddr, FreeAddr(t), auth.EncodeKey(npriv), o.OriginPort, o.OriginPort, s.CtlURL, jt.JoinToken))
	Run(t, Bins.Core, "node", "-config", nodeCfg)

	var acc struct {
		Key string `json:"account_key"`
	}
	zero := 0
	if code := AdminDo(t, s, "POST", "/v1/admin/accounts", map[string]any{"name": "alice", "quota_gb": &zero}, &acc); code != http.StatusCreated {
		t.Fatalf("account: %d", code)
	}
	s.AccountKey = acc.Key
	if o.NoWaitParked {
		// Wait for control to list endpoints (the node registered), but
		// tolerate a censor that stops the tunnel from parking.
		for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(250 * time.Millisecond) {
			if r, err := s.Discovery().Refresh(context.Background()); err == nil && len(r.Endpoints) > 0 {
				break
			}
		}
	} else {
		WaitFor(t, 40*time.Second, "node tunnel parked at relay", func() bool { return s.Parked(t) >= 1 })
	}
	return s
}

func (s *Stack) Parked(t *testing.T) int {
	t.Helper()
	resp, err := http.Get("http://" + s.RelayAdmin + "/metrics")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "dotvpn_relay_parked "); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return -1
}

// engine is a client that learns everything from control, like a real one,
// and keeps only endpoints of the given kinds (all when none are given).
func (s *Stack) Engine(t *testing.T, kinds ...transport.Kind) *client.Engine {
	t.Helper()
	keep := func(eps []transport.Endpoint) []transport.Endpoint {
		if len(kinds) == 0 {
			return eps
		}
		var out []transport.Endpoint
		for _, ep := range eps {
			for _, k := range kinds {
				if ep.Kind == k {
					out = append(out, ep)
				}
			}
		}
		return out
	}
	tm := &client.TokenManager{Source: s.Discovery()}
	eng := client.NewEngine(client.EngineConfig{
		Dialers: Dialers(), Token: tm.Token, OnUnauthorized: tm.Refresh, Stagger: 100 * time.Millisecond,
	})
	tm.OnEndpoints = func(r discovery.Result) { eng.SetEndpoints(keep(r.Endpoints)) }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = eng.Close() })
	if err := tm.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return eng
}

func (s *Stack) Discovery() *discovery.Client {
	return &discovery.Client{
		Channels: []discovery.ControlChannel{{URL: s.CtlURL}}, Verifier: auth.NewVerifier(s.CtlPub), AccountKey: s.AccountKey,
	}
}

func (s *Stack) Endpoints(t *testing.T) []transport.Endpoint {
	t.Helper()
	r, err := s.Discovery().Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r.Endpoints
}
