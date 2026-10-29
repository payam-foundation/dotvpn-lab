package dpi

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// clientHello captures the first flight of a real crypto/tls client.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: sni}).Handshake()
	}()
	buf := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	return buf[:n]
}

func TestClientHelloSNI(t *testing.T) {
	h := clientHello(t, "blocked.example")
	for _, strict := range []bool{false, true} {
		got, err := ParseClientHello(h, strict)
		if err != nil || got.SNI != "blocked.example" || got.Fragmented {
			t.Errorf("strict=%v: %+v %v", strict, got, err)
		}
	}
}

// Split into two TLS records inside the SNI: naive DPI misses the name,
// strict DPI reassembles it (row IR-7).
func TestClientHelloFragmentation(t *testing.T) {
	h := clientHello(t, "blocked.example")
	body := h[5:]
	cut := bytes.Index(body, []byte("blocked.example")) + 4
	split := append([]byte{0x16, 3, 1, byte(cut >> 8), byte(cut)}, body[:cut]...)
	rest := body[cut:]
	split = append(split, 0x16, 3, 1, byte(len(rest)>>8), byte(len(rest)))
	split = append(split, rest...)

	n, err := ParseClientHello(split, false)
	if err != nil || n.SNI == "blocked.example" {
		t.Errorf("naive should not see the SNI: %+v %v", n, err)
	}
	s, err := ParseClientHello(split, true)
	if err != nil || s.SNI != "blocked.example" || !s.Fragmented {
		t.Errorf("strict: %+v %v", s, err)
	}
	if _, err := ParseClientHello(split[:len(split)-40], true); err != ErrShort {
		t.Errorf("truncated strict: %v", err)
	}
	if _, err := ParseClientHello([]byte("GET / HTTP/1.1\r\n"), true); err != ErrNotTLS {
		t.Errorf("http: %v", err)
	}
}

// A real quic-go client Initial: the censor must read the SNI.
func TestQUICInitialSNI(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		_, _ = quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: "quic.blocked.example", NextProtos: []string{"h3"}}, nil)
	}()
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	var frags []Frag
	for range 3 { // quic-go spreads the hello over several datagrams
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if !IsQUICv1Initial(buf[:n]) {
			t.Fatal("not recognised as QUIC v1 Initial")
		}
		f, err := QUICInitialFrags(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		frags = append(frags, f...)
	}
	if sni := SNIFromFrags(frags); sni != "quic.blocked.example" {
		t.Fatalf("sni %q from %d frags", sni, len(frags))
	}
}

func TestFullyEncrypted(t *testing.T) {
	rnd := make([]byte, 200)
	for i := range rnd {
		rnd[i] = byte(i*131 + 7) // spread over all bit densities
	}
	if !FullyEncrypted(rnd) {
		t.Error("random-looking payload should be flagged")
	}
	if FullyEncrypted([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) {
		t.Error("HTTP is exempt")
	}
	if FullyEncrypted(clientHello(t, "x.example")) {
		t.Error("TLS is exempt")
	}
	if FullyEncrypted(make([]byte, 100)) { // popcount 0: Ex1
		t.Error("low entropy is exempt")
	}
}

func TestDNS(t *testing.T) {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'y', 'o', 'u', 't', 'u', 'b', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	name, err := DNSQuestion(q)
	if err != nil || name != "youtube.com" {
		t.Fatalf("%q %v", name, err)
	}
	r := DNSReply(q, 3)
	if r[3]&0xf != 3 || r[0] != 0x12 || r[2]&0x80 == 0 {
		t.Fatalf("reply % x", r[:12])
	}
	if h, ok := HTTPHost([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")); !ok || h != "a.example" {
		t.Fatalf("host %q", h)
	}
}
