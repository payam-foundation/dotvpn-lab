package functional

import (
	"context"
	"crypto/tls"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	sfproxy "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/proxy/lib"
	"golang.org/x/net/proxy"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/snowflake"
)

func tryDial(e interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}, addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, "tcp", addr)
	if err == nil {
		c.Close()
	}
	return err
}

// Every carrier a direct node serves carries a request to the origin.
func TestDirectCarriers(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	tok := d.Token(t, "alice")
	cases := []struct {
		name string
		ep   transport.Endpoint
		want string
	}{
		{"h2", transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin}, "h2@"},
		{"h3", transport.Endpoint{Kind: transport.KindH3, Addr: d.Addr, Pin: d.Pin}, "h3@"},
		{"cdnws", transport.Endpoint{Kind: transport.KindCDNWS, Addr: d.Addr, Path: harness.WSPath, Pin: d.Pin}, "cdnws@"},
		{"webtunnel", transport.Endpoint{Kind: transport.KindWebTunnel, Addr: d.Addr, Path: harness.WTPath, Pin: d.Pin}, "webtunnel@"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := harness.StaticEngine(tok, c.ep)
			defer e.Close()
			for range 2 {
				if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
					t.Fatalf("body %q", body)
				}
			}
			if !strings.HasPrefix(e.Status(), c.want) {
				t.Fatalf("status %q, want prefix %q", e.Status(), c.want)
			}
		})
	}
}

func TestSOCKS5AndConnect(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	e := harness.StaticEngine(d.Token(t, "alice"), transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin})
	defer e.Close()
	addr := harness.LocalProxy(t, e)

	pu, _ := url.Parse("http://" + addr)
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 10 * time.Second}
	resp, err := hc.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "origin-ok" {
		t.Fatalf("http proxy body %q", b)
	}
	sd, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	sc := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, n, a string) (net.Conn, error) { return sd.Dial(n, a) }}, Timeout: 10 * time.Second}
	resp, err = sc.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "origin-ok" {
		t.Fatalf("socks body %q", b)
	}
}

func TestAuthRejection(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	ep := transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin}

	bad := harness.StaticEngine("junk", ep)
	defer bad.Close()
	if err := tryDial(bad, harness.HostPort(origin.URL)); err != transport.ErrUnauthorized {
		t.Fatalf("junk token: %v", err)
	}
	// A token signed by a key the node does not trust.
	_, other, _ := auth.GenerateKey()
	forged, _ := auth.NewSigner(other).Mint(auth.Claims{Sub: "mallory"}, time.Minute)
	f := harness.StaticEngine(forged, ep)
	defer f.Close()
	if err := tryDial(f, harness.HostPort(origin.URL)); err != transport.ErrUnauthorized {
		t.Fatalf("forged token: %v", err)
	}
	// A pool token is not a user token.
	pool, _ := auth.NewSigner(d.Priv).Mint(auth.Claims{Sub: "n", Aud: auth.AudPool}, time.Minute)
	p := harness.StaticEngine(pool, ep)
	defer p.Close()
	if err := tryDial(p, harness.HostPort(origin.URL)); err != transport.ErrUnauthorized {
		t.Fatalf("wrong-audience token: %v", err)
	}
	g := harness.StaticEngine(d.Token(t, "bob"), ep)
	defer g.Close()
	if err := tryDial(g, harness.HostPort(origin.URL)); err != nil {
		t.Fatalf("good token: %v", err)
	}
}

func TestPortAllowlist(t *testing.T) {
	origin, _ := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, 443) // origin port is not allowed
	e := harness.StaticEngine(d.Token(t, "bob"), transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin})
	defer e.Close()
	if err := tryDial(e, harness.HostPort(origin.URL)); err != transport.ErrForbidden {
		t.Fatalf("port policy: %v", err)
	}
}

// The released core (no -tags e2e) must refuse loopback, private and
// metadata destinations even for an authenticated user on an allowed port.
func TestSSRFGuard(t *testing.T) {
	origin, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.CoreProd, port, 80)
	e := harness.StaticEngine(d.Token(t, "bob"), transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin})
	defer e.Close()
	for _, dst := range []string{harness.HostPort(origin.URL), "127.0.0.1:80", "10.0.0.1:80", "192.168.1.1:80", "[::1]:80", "169.254.169.254:80"} {
		if err := tryDial(e, dst); err != transport.ErrForbidden {
			t.Errorf("egress to %s: %v, want forbidden", dst, err)
		}
	}
}

func TestDirectNodeServesDecoy(t *testing.T) {
	_, port := harness.StartOrigin(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	hc := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second} // probe with no pin: we are the censor
	get := func(path string) (int, string) {
		resp, err := hc.Get("https://" + d.Addr + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, body := get("/"); code != 200 || !strings.Contains(body, "Welcome") {
		t.Fatalf("decoy: %d %q", code, body)
	}
	// A secret carrier path must look exactly like a path that does not exist.
	wantCode, wantBody := get("/nope")
	for _, path := range []string{harness.WSPath, harness.WTPath} {
		if code, body := get(path); code != wantCode || body != wantBody {
			t.Errorf("%s: %d %q differs from an unknown path (%d %q)", path, code, body, wantCode, wantBody)
		}
	}
}

// directBackend is a node backend for the in-process snowflake server.
type directBackend struct{ v *auth.Verifier }

func (b directBackend) Authenticate(tok string) (transport.User, error) {
	c, err := b.v.Verify(tok)
	if err != nil {
		return transport.User{}, transport.ErrUnauthorized
	}
	return transport.User{ID: c.Sub}, nil
}

func (directBackend) Dial(ctx context.Context, _ transport.User, a string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", a)
}

// Snowflake: broker, server, a volunteer proxy and the client, all on
// loopback with local ICE candidates. The server side is the wire library's.
func TestSnowflake(t *testing.T) {
	if testing.Short() {
		t.Skip("webrtc test")
	}
	origin, _ := harness.StartOrigin(t)
	pub, priv, _ := auth.GenerateKey()
	sfAddr := harness.FreeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = snowflake.Serve(ctx, sfAddr, nil, directBackend{auth.NewVerifier(pub)}) }()
	br, err := snowflake.NewBroker("ws://" + sfAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	bs := httptest.NewServer(br.Handler())
	defer bs.Close()
	p := &sfproxy.SnowflakeProxy{
		EventDispatcher: event.NewSnowflakeEventDispatcher(), BrokerURL: bs.URL, RelayURL: "ws://" + sfAddr + "/",
		STUNURL: "stun:127.0.0.1:1", Capacity: 4, KeepLocalAddresses: true, AllowProxyingToPrivateAddresses: true,
		AllowNonTLSRelay: true, PollInterval: 200 * time.Millisecond, MinPollInterval: 200 * time.Millisecond,
		NATProbeURL: "http://127.0.0.1:1/probe", RelayDomainNamePattern: "$",
	}
	go func() { _ = p.Start() }()
	t.Cleanup(p.Stop)

	tok, _ := auth.NewSigner(priv).Mint(auth.Claims{Sub: "hank"}, time.Minute)
	e := harness.StaticEngine(tok, transport.Endpoint{Kind: transport.KindSnowflake, Addr: sfAddr, Params: map[string]string{
		snowflake.ParamBroker: bs.URL + "/", snowflake.ParamLocal: "1",
	}})
	defer e.Close()
	if body := harness.FetchVia(t, e, origin.URL); body != "origin-ok" {
		t.Fatalf("body %q", body)
	}
	if !strings.HasPrefix(e.Status(), "snowflake@") {
		t.Fatalf("status %q", e.Status())
	}
}
