//go:build linux

// Package netlab builds the lab topology out of Linux network namespaces:
//
//	in (client, relay)  --veth--  border (censor, router)  --veth--  out (core, origin, CDN)
//
// Everything needs root and CAP_NET_ADMIN; run it in the lab container
// (docker/Dockerfile.lab) or on a CI runner under sudo. Names carry a per-run
// prefix, so parallel and aborted runs do not collide (see `make lab-clean`).
package netlab

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Addresses inside the lab. The inside net is the "country"; everything else
// is abroad. v6 is only on the inside link: it exists so leak tests can see
// IPv6 that should never be sent.
const (
	InNet     = "10.77.1.0/24"
	InAddr    = "10.77.1.2"
	BorderIn  = "10.77.1.1"
	BorderOut = "10.77.2.1"
	OutAddr   = "10.77.2.2"
	InAddr6   = "fd00:77::2"
	BorderIn6 = "fd00:77::1"
)

// Lab is one topology.
type Lab struct {
	abroad           []string // addresses added by Abroad, re-routed after a link flap
	t                testing.TB
	Prefix           string
	In, Border, Out  string // namespace names
	inI, bdI, bdO, o string // veth names
}

// Available reports why the lab cannot run here, or nil.
func Available() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("needs root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("needs iproute2: %w", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("needs nftables: %w", err)
	}
	return nil
}

func sh(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// New creates the topology and removes it when the test ends. The test is
// skipped (not failed) when the host cannot run namespaces.
func New(t testing.TB) *Lab {
	t.Helper()
	if err := Available(); err != nil {
		t.Skip("netns lab unavailable: ", err)
	}
	var b [3]byte
	_, _ = rand.Read(b[:])
	p := "dvl" + hex.EncodeToString(b[:])
	l := &Lab{t: t, Prefix: p, In: p + "-in", Border: p + "-bd", Out: p + "-out",
		inI: p + "-i0", bdI: p + "-i1", bdO: p + "-o0", o: p + "-o1"}
	t.Cleanup(l.Close)
	// ip netns exec bind-mounts this over /etc/resolv.conf, so a client that
	// rewrites DNS settings in the inside namespace cannot touch the host's.
	// The border address stands in for the ISP resolver.
	if err := os.MkdirAll("/etc/netns/"+l.In, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/netns/"+l.In+"/resolv.conf", []byte("nameserver "+BorderIn+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmds := [][]string{
		{"ip", "netns", "add", l.In}, {"ip", "netns", "add", l.Border}, {"ip", "netns", "add", l.Out},
		{"ip", "link", "add", l.inI, "type", "veth", "peer", "name", l.bdI},
		{"ip", "link", "add", l.bdO, "type", "veth", "peer", "name", l.o},
		{"ip", "link", "set", l.inI, "netns", l.In}, {"ip", "link", "set", l.bdI, "netns", l.Border},
		{"ip", "link", "set", l.bdO, "netns", l.Border}, {"ip", "link", "set", l.o, "netns", l.Out},
	}
	for _, c := range cmds {
		if err := sh(c[0], c[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	ns := func(n string, args ...string) []string { return append([]string{"ip", "netns", "exec", n}, args...) }
	steps := [][]string{
		ns(l.In, "ip", "link", "set", "lo", "up"), ns(l.Border, "ip", "link", "set", "lo", "up"), ns(l.Out, "ip", "link", "set", "lo", "up"),
		ns(l.In, "ip", "addr", "add", InAddr+"/24", "dev", l.inI),
		ns(l.In, "ip", "-6", "addr", "add", InAddr6+"/64", "dev", l.inI, "nodad"),
		ns(l.In, "ip", "link", "set", l.inI, "up"),
		ns(l.In, "ip", "route", "add", "default", "via", BorderIn),
		ns(l.In, "ip", "-6", "route", "add", "default", "via", BorderIn6),
		ns(l.Border, "ip", "addr", "add", BorderIn+"/24", "dev", l.bdI),
		ns(l.Border, "ip", "-6", "addr", "add", BorderIn6+"/64", "dev", l.bdI, "nodad"),
		ns(l.Border, "ip", "addr", "add", BorderOut+"/24", "dev", l.bdO),
		ns(l.Border, "ip", "link", "set", l.bdI, "up"), ns(l.Border, "ip", "link", "set", l.bdO, "up"),
		ns(l.Border, "sysctl", "-qw", "net.ipv4.ip_forward=1"),
		ns(l.Border, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"),
		ns(l.Out, "ip", "addr", "add", OutAddr+"/24", "dev", l.o),
		ns(l.Out, "ip", "link", "set", l.o, "up"),
		ns(l.Out, "ip", "route", "add", "default", "via", BorderOut),
		// The border must not send ICMP redirects or filter by reverse path:
		// the abroad addresses are local to a neighbour.
		ns(l.Border, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0"),
	}
	for _, c := range steps {
		if err := sh(c[0], c[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

// Abroad adds addresses on the outside namespace (stand-ins for the hosts and
// prefixes named in a profile's placements) and routes to them from the
// border.
func (l *Lab) Abroad(ips ...string) {
	l.t.Helper()
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		l.abroad = append(l.abroad, ip)
		for _, c := range [][]string{
			{"ip", "netns", "exec", l.Out, "ip", "addr", "add", ip + "/32", "dev", "lo"},
			{"ip", "netns", "exec", l.Border, "ip", "route", "replace", ip + "/32", "via", OutAddr},
		} {
			if err := sh(c[0], c[1:]...); err != nil {
				l.t.Fatal(err)
			}
		}
	}
}

// Cmd returns a command that runs inside namespace ns.
func (l *Lab) Cmd(ns, name string, args ...string) *exec.Cmd {
	return exec.Command("ip", append([]string{"netns", "exec", ns, name}, args...)...)
}

// Run runs a command in ns to completion and returns its combined output.
func (l *Lab) Run(ns, name string, args ...string) (string, error) {
	out, err := l.Cmd(ns, name, args...).CombinedOutput()
	return string(out), err
}

// Nft loads an nftables script into namespace ns.
func (l *Lab) Nft(ns, script string) error {
	cmd := l.Cmd(ns, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s\n%s", err, out, script)
	}
	return nil
}

// Ifaces returns the border's interface toward the inside and the outside.
func (l *Lab) Ifaces() (toIn, toOut string) { return l.bdI, l.bdO }

// NetNSFile opens the namespace for netlink sockets (nfqueue). Close it when done.
func (l *Lab) NetNSFile(ns string) (*os.File, error) { return os.Open("/var/run/netns/" + ns) }

// InNS runs fn on a thread that has entered namespace ns. Sockets that fn
// creates stay in ns after it returns (raw sockets for the censor).
func (l *Lab) InNS(ns string, fn func() error) error {
	f, err := l.NetNSFile(ns)
	if err != nil {
		return err
	}
	defer f.Close()
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // a thread that failed to return to its namespace is never unlocked, so it dies with the goroutine
		self, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			errc <- err
			return
		}
		defer self.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- err
			runtime.UnlockOSThread()
			return
		}
		ferr := fn()
		if err := unix.Setns(int(self.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("leave namespace: %v (%v)", err, ferr)
			return
		}
		runtime.UnlockOSThread()
		errc <- ferr
	}()
	return <-errc
}

// Close removes the namespaces; deleting them frees the veth ends inside.
func (l *Lab) Close() {
	for _, n := range []string{l.In, l.Border, l.Out} {
		_ = sh("ip", "netns", "del", n)
	}
	_ = os.RemoveAll("/etc/netns/" + l.In)
}
