// Package probe classifies what a client engine can do through a censor.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/payam-foundation/dotvpn-client/client"
	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/report"
)

// Probe fetches the bulk object through the engine until it succeeds or the
// budget runs out, and classifies what it saw.
func Probe(e *client.Engine, origin string, budget time.Duration, bulk bool) report.Cell {
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return e.DialContext(ctx, "tcp", addr) },
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
	start := time.Now()
	var lastErr error
	slow := false // an attempt ran into its timeout
	for time.Since(start) < budget {
		t0 := time.Now()
		path, want := harness.BulkPath, harness.BulkSize
		if !bulk { // the DNS carrier is far too slow for a bulk body
			path, want = "/", len("origin-ok")
		}
		n, err := fetch(hc, origin+path)
		if err == nil && n == want {
			d := time.Since(start)
			v := report.Works
			if d > 12*time.Second {
				v = report.Degraded
			}
			return report.Cell{Verdict: v, TTFBms: d.Milliseconds()}
		}
		lastErr = err
		if err == nil {
			lastErr = fmt.Errorf("short body %d", n)
		}
		if time.Since(t0) > 3*time.Second || isTimeout(err) {
			slow = true
		}
		time.Sleep(200 * time.Millisecond)
	}
	v := report.FailsFast
	if slow {
		v = report.Hangs
	}
	return report.Cell{Verdict: v, Detail: strings.TrimSpace(fmt.Sprint(lastErr))}
}

func fetch(hc *http.Client, u string) (int, error) {
	resp, err := hc.Get(u)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	return int(n), err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}
