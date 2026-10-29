//go:build linux && lab

// Package chaos damages the path under a running client: netem impairment,
// node restarts, link flaps, relay restarts. The bound for each is an outage
// ceiling, not a pass/fail on exact timing.
package chaos

import (
	"bufio"
	"bytes"
	"encoding/json"
	"syscall"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-lab/internal/labworld"
	"github.com/payam-foundation/dotvpn-lab/internal/netlab"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

const nodeIP = "203.0.113.10"

type try struct {
	T  int64 `json:"t"`
	OK bool  `json:"ok"`
	MS int64 `json:"ms"`
}

// loop runs labtool loop in the inside namespace for d, while act runs
// beside it, and returns every try.
func loop(t *testing.T, w *labworld.World, eps []transport.Endpoint, d time.Duration, act func()) []try {
	t.Helper()
	b, _ := json.Marshal(eps)
	cmd := w.Lab.Cmd(w.Lab.In, harness.Bins.Labtool, "loop", "-endpoints", string(b), "-token", w.D.TokenFor(t, "chaos", time.Hour),
		"-origin", labworld.OriginURL(), "-for", d.String())
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if act != nil {
		time.Sleep(4 * time.Second) // let the first connection settle
		act()
	}
	if err := <-done; err != nil {
		t.Fatalf("labtool loop: %v", err)
	}
	var res []try
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var x try
		if json.Unmarshal(sc.Bytes(), &x) == nil {
			res = append(res, x)
		}
	}
	return res
}

// stats returns the success ratio and the longest stretch without a success,
// counted from the first success.
func stats(r []try) (ratio float64, outage time.Duration, last bool) {
	var ok int
	var lastOK, first int64
	var gap int64
	for _, x := range r {
		if x.OK {
			ok++
			if first == 0 {
				first = x.T
			} else if g := x.T - lastOK; g > gap {
				gap = g
			}
			lastOK = x.T
		}
	}
	if len(r) > 0 {
		last = r[len(r)-1].OK
		if first != 0 && !last {
			gap = max(gap, r[len(r)-1].T-lastOK)
		}
		ratio = float64(ok) / float64(len(r))
	}
	return ratio, time.Duration(gap) * time.Millisecond, last
}

func setup(t *testing.T) (*labworld.World, []transport.Endpoint) {
	t.Helper()
	w := labworld.New(t, nodeIP)
	w.StartNode(t)
	return w, []transport.Endpoint{w.Endpoints(nodeIP)["h2"]}
}

// Impaired links: the carrier keeps working, at a cost the log shows.
func TestNetemPresets(t *testing.T) {
	for _, n := range []netlab.Netem{netlab.NetemMobile, netlab.NetemCongested, netlab.NetemLossy} {
		t.Run(n.Name, func(t *testing.T) {
			w, eps := setup(t)
			if err := w.Lab.SetNetem(n); err != nil {
				t.Fatal(err)
			}
			r := loop(t, w, eps, 15*time.Second, nil)
			ratio, outage, last := stats(r)
			t.Logf("%s: %d tries, success %.0f%%, longest outage %s", n.Name, len(r), ratio*100, outage)
			if ratio < 0.6 || !last {
				t.Errorf("success %.0f%%, last ok %v: carrier did not survive %s", ratio*100, last, n.Name)
			}
		})
	}
}

// The node is killed and started again with the same identity; the client
// must come back by itself.
func TestNodeRestart(t *testing.T) {
	w, eps := setup(t)
	var down time.Duration
	r := loop(t, w, eps, 30*time.Second, func() {
		w.Node.Stop(syscall.SIGKILL)
		time.Sleep(3 * time.Second)
		t0 := time.Now()
		w.RunNode(t)
		down = time.Since(t0)
	})
	_, outage, last := stats(r)
	t.Logf("node restart: restart took %s, client outage %s", down, outage)
	if !last {
		t.Error("client never recovered after the node restarted")
	}
	if outage > 20*time.Second {
		t.Errorf("outage %s after restart, ceiling 20s", outage)
	}
}

// The border link goes down and up again.
func TestLinkFlap(t *testing.T) {
	w, eps := setup(t)
	r := loop(t, w, eps, 30*time.Second, func() {
		if err := w.Lab.SetLink(false); err != nil {
			t.Error(err)
		}
		time.Sleep(4 * time.Second)
		if err := w.Lab.SetLink(true); err != nil {
			t.Error(err)
		}
	})
	_, outage, last := stats(r)
	t.Logf("link flap (4s down): client outage %s", outage)
	if !last {
		t.Error("client never recovered after the link came back")
	}
	if outage > 20*time.Second {
		t.Errorf("outage %s after a 4 s flap, ceiling 20s", outage)
	}
}
