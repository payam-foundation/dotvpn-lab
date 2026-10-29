// Command fpcheck measures what an observer sees of the mimic carrier.
//
//	fpcheck listen ADDR        print JA3/JA4 of each ClientHello that arrives (point a real browser at it)
//	fpcheck ours               print JA3/JA4 of the knock ClientHello the client sends
//	fpcheck server ADDR [SNI]  send a Chrome-like hello (no knock) and describe the server's first bytes
//
// It is a lab tool for the fingerprint rows of docs/REPORT.md.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/measure"
	"github.com/payam-foundation/dotvpn-wire/mimic"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fpcheck listen ADDR | ours | server ADDR [SNI]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "listen":
		err = listen(os.Args[2])
	case "knock":
		err = knock(os.Args[2], os.Args[3], os.Args[4])
	case "ours":
		err = ours()
	case "server":
		sni := "cdn.example.com"
		if len(os.Args) > 3 {
			sni = os.Args[3]
		}
		err = server(os.Args[2], sni)
	default:
		err = errors.New("unknown mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func listen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			rec, err := measure.ReadRecord(c)
			if err != nil {
				return
			}
			if h, err := measure.ParseHello(rec); err == nil {
				fmt.Println(h.Describe())
			}
		}()
	}
}

func knock(addr, sni, keyB64 string) error {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := mimic.Dial(c, sni, key); err != nil {
		return err
	}
	// A parked node answers nothing until we speak; send a handshake-shaped hello.
	junk := make([]byte, 33)
	_, _ = rand.Read(junk)
	junk[32] = junk[31] // padlen 0
	_, _ = c.Write(junk)
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	b := make([]byte, 64)
	n, err := io.ReadAtLeast(c, b, 33)
	if err != nil {
		return fmt.Errorf("read %d bytes: %w", n, err)
	}
	pl := int(b[32] ^ b[31])
	fmt.Printf("got %d bytes, first=%x, padlen-field=%d (handshake-shaped=%v)\n", n, b[:6], pl, pl <= 64)
	return nil
}

func ours() error {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rec, err := mimic.Hello(a, "cdn.example.com", mimic.KnockKey("x", []byte("y")), time.Now())
	if err != nil {
		return err
	}
	h, err := measure.ParseHello(rec)
	if err != nil {
		return err
	}
	fmt.Println(h.Describe())
	return nil
}

func server(addr, sni string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	// An ordinary (non-knock) Chrome hello: the relay must answer it as the decoy would.
	rec, err := mimic.Hello(c, sni, []byte("not-a-valid-knock-key-000000000000"), time.Now())
	if err != nil {
		return err
	}
	if _, err := c.Write(rec); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	first, err := measure.ReadRecord(c)
	if err != nil {
		return fmt.Errorf("no TLS record back: %w", err)
	}
	fmt.Println(measure.DescribeServer(first))
	return nil
}
