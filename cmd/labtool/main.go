// labtool is run inside lab namespaces by the netns suites, where the test
// process itself cannot be: an origin server, a TLS pin reader and a client
// probe.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/probe"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labtool origin|pin|probe ...")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	url := fs.String("url", "", "get: URL, direct from this namespace")
	name := fs.String("name", "", "lookup: host name")
	dur := fs.Duration("for", 30*time.Second, "loop: how long")
	size := fs.Int64("bytes", 64<<20, "bench: bytes to download")
	addr := fs.String("addr", "127.0.0.1:0", "origin listen address, or node address for pin")
	eps := fs.String("endpoints", "", "probe: JSON endpoint list")
	token := fs.String("token", "", "probe: access token")
	origin := fs.String("origin", "", "probe: origin base URL")
	budget := fs.Duration("budget", 10*time.Second, "probe: time budget")
	bulk := fs.Bool("bulk", true, "probe: fetch the bulk object")
	_ = fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "origin":
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/big" { // streamed, size from ?n=
				n, _ := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
				w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
				buf := make([]byte, 64<<10)
				for ; n > 0; n -= int64(len(buf)) {
					if _, err := w.Write(buf[:min(int64(len(buf)), n)]); err != nil {
						return
					}
				}
				return
			}
			if r.URL.Path == harness.BulkPath {
				w.Header().Set("Content-Length", strconv.Itoa(harness.BulkSize))
				_, _ = w.Write(make([]byte, harness.BulkSize))
				return
			}
			fmt.Fprint(w, "origin-ok")
		})
		fatal(http.ListenAndServe(*addr, nil))
	case "pin":
		c, err := tls.Dial("tcp", *addr, &tls.Config{InsecureSkipVerify: true}) // learning the pin of our own lab node
		fatal(err)
		fmt.Print(transport.SPKIPin(c.ConnectionState().PeerCertificates[0]))
	case "get": // plain GET without any tunnel: what a leaking app would do
		hc := &http.Client{Timeout: 3 * time.Second}
		resp, err := hc.Get(*url)
		fatal(err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		fmt.Print(string(b))
	case "dl": // plain download of n bytes, prints MB/s; goes through whatever the namespace routes to
		hc := &http.Client{Timeout: 3 * time.Minute}
		t0 := time.Now()
		resp, err := hc.Get(*url)
		fatal(err)
		got, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"mbps": float64(got) / 1e6 / time.Since(t0).Seconds()})
	case "udp": // one datagram, no reply expected (STUN-like leak probe)
		c, err := net.Dial("udp4", *addr)
		fatal(err)
		_, err = c.Write([]byte("\x00\x01\x00\x00\x21\x12\xa4\x42leakprobe!"))
		fatal(err)
	case "lookup": // what the OS resolver says
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		ips, err := (&net.Resolver{PreferGo: true}).LookupHost(ctx, *name)
		fatal(err)
		fmt.Println(ips)
	case "loop", "bench":
		var list []transport.Endpoint
		fatal(json.Unmarshal([]byte(*eps), &list))
		eng := harness.StaticEngine(*token, list...)
		defer eng.Close()
		hc := &http.Client{Transport: &http.Transport{
			DialContext:       func(ctx context.Context, _, a string) (net.Conn, error) { return eng.DialContext(ctx, "tcp", a) },
			DisableKeepAlives: true,
		}, Timeout: 5 * time.Second}
		if os.Args[1] == "loop" {
			loop(hc, *origin, *dur)
		} else {
			bench(hc, *origin, *size)
		}
	case "probe":
		var list []transport.Endpoint
		fatal(json.Unmarshal([]byte(*eps), &list))
		eng := harness.StaticEngine(*token, list...)
		defer eng.Close()
		c := probe.Probe(eng, *origin, *budget, *bulk)
		c.Landed = eng.Status()
		fatal(json.NewEncoder(os.Stdout).Encode(c))
	default:
		fatal(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

// loop fetches the small page every 200 ms and prints one JSON line per try,
// so a test can measure an outage from the outside.
func loop(hc *http.Client, origin string, d time.Duration) {
	enc := json.NewEncoder(os.Stdout)
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		t0 := time.Now()
		resp, err := hc.Get(origin + "/")
		ok := err == nil && resp.StatusCode == 200
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		_ = enc.Encode(map[string]any{"t": t0.UnixMilli(), "ok": ok, "ms": time.Since(t0).Milliseconds()})
	}
}

// bench prints throughput of one big download and the median latency of small requests.
func bench(hc *http.Client, origin string, n int64) {
	hc.Timeout = 2 * time.Minute
	var lat []time.Duration
	for range 20 {
		t0 := time.Now()
		resp, err := hc.Get(origin + "/")
		fatal(err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		lat = append(lat, time.Since(t0))
	}
	slices.Sort(lat)
	t0 := time.Now()
	resp, err := hc.Get(origin + "/big?n=" + strconv.FormatInt(n, 10))
	fatal(err)
	got, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fatal(err)
	if got != n {
		fatal(fmt.Errorf("short download %d of %d", got, n))
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mbps": float64(got) / 1e6 / time.Since(t0).Seconds(), "latency_us": lat[len(lat)/2].Microseconds(),
	})
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
