package functional

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/reverse"
)

// udpEcho answers every datagram with the same bytes.
func udpEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], a)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func roundTrip(t *testing.T, c net.Conn, msg []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:n]) != string(msg) {
		t.Fatalf("echo %d bytes, want %d", n, len(msg))
	}
}

// UDP flows ride every carrier a direct node serves, keep datagram
// boundaries, and are refused for ports outside the node's UDP allow-list.
func TestUDPOverCarriers(t *testing.T) {
	port := udpEcho(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	tok := d.Token(t, "alice")
	udp := map[string]string{transport.ParamUDP: "1"}
	cases := []struct {
		name string
		ep   transport.Endpoint
	}{
		{"h2", transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin, Params: udp}},
		{"h3", transport.Endpoint{Kind: transport.KindH3, Addr: d.Addr, Pin: d.Pin, Params: udp}},
		{"cdnws", transport.Endpoint{Kind: transport.KindCDNWS, Addr: d.Addr, Path: harness.WSPath, Pin: d.Pin, Params: udp}},
		{"webtunnel", transport.Endpoint{Kind: transport.KindWebTunnel, Addr: d.Addr, Path: harness.WTPath, Pin: d.Pin, Params: udp}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := harness.StaticEngine(tok, c.ep)
			defer e.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := e.DialPacket(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			roundTrip(t, conn, []byte("one"))
			big := make([]byte, 1400)
			for i := range big {
				big[i] = byte(i)
			}
			roundTrip(t, conn, big)
			roundTrip(t, conn, []byte("three"))

			// A port outside the UDP allow-list is refused.
			if bad, err := e.DialPacket(ctx, "127.0.0.1:9"); err == nil {
				_ = bad.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = bad.Write([]byte("x"))
				if _, err := bad.Read(make([]byte, 16)); err == nil {
					t.Fatal("port outside allow-list answered")
				}
				bad.Close()
			}
		})
	}
}

// Without the udp capability the engine refuses instead of mis-splicing.
func TestUDPNeedsCapability(t *testing.T) {
	port := udpEcho(t)
	d := harness.StartDirect(t, harness.Bins.Core, port)
	e := harness.StaticEngine(d.Token(t, "alice"), transport.Endpoint{Kind: transport.KindH2, Addr: d.Addr, Pin: d.Pin})
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.DialPacket(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		t.Fatal("DialPacket succeeded without udp capability")
	}
}

// The stealth path carries UDP too: relay and node never see a client, and
// the datagrams still reach the target through the reverse tunnel.
func TestUDPOverReverseRelay(t *testing.T) {
	port := udpEcho(t)
	s := harness.StartStack(t, harness.StackOpts{OriginPort: port})
	e := s.Engine(t, reverse.KindReverse)
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := e.DialPacket(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, []byte("via relay"))
}
