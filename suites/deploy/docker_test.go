package deploy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
	"github.com/payam-foundation/dotvpn-wire/auth"
)

// The images are built from the repos' own Dockerfiles, exactly as the release
// does, around a binary compiled for the Docker host's architecture. The
// "previous release" is LAB_PREV_DIR/{dotvpn-core,dotvpn-relay} when set (real
// release binaries for linux/<arch>); otherwise the same source stamped with an
// older version.
// ponytail: with no previous release binaries the drill proves the volume,
// identity and config survive a version swap, not that two real releases are
// compatible. Set LAB_PREV_DIR once a tag exists.
const (
	oldVer = "v0.0.0-prev"
	newVer = "v0.0.1-lab"
)

func docker(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errb.String())
	}
	return strings.TrimSpace(out.String())
}

func needDocker(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker CLI (the lab container has none; run on the host or a CI runner)")
	}
	out, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Skip("docker daemon not reachable")
	}
	switch a := strings.TrimSpace(string(out)); a {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "amd64":
		return "amd64"
	default:
		t.Skipf("unsupported docker architecture %q", a)
	}
	return ""
}

// image builds repo's Dockerfile around bin and returns the tag.
func image(t *testing.T, arch, repo, name, ver, prevDir string) string {
	t.Helper()
	root := filepath.Join(harness.Root(), "..", repo)
	ctx := t.TempDir()
	dist := filepath.Join(ctx, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dist, fmt.Sprintf("%s_linux_%s", name, arch))
	if ver == oldVer && prevDir != "" {
		b, err := os.ReadFile(filepath.Join(prevDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, b, 0o755); err != nil {
			t.Fatal(err)
		}
	} else {
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.version="+ver, "-o", bin, "./cmd/"+name)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, out)
		}
	}
	for _, f := range []string{"deploy/docker/Dockerfile"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ctx, "Dockerfile"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The Dockerfile pre-owns /data from this directory (a fresh named volume
	// must be writable by nonroot); take it from the repo so a missing one fails.
	if d := filepath.Join(root, "deploy/docker/data"); exists(d) {
		if err := os.MkdirAll(filepath.Join(ctx, "deploy/docker/data"), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(ctx, "deploy/docker/data/.keep"), nil, 0o644)
	}
	tag := fmt.Sprintf("dotvpn-lab/%s:%s-%d", name, strings.ReplaceAll(ver, "+", "-"), time.Now().UnixNano())
	docker(t, "build", "-q", "--build-arg", "TARGETARCH="+arch, "-t", tag, ctx)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func volume(t *testing.T) string {
	t.Helper()
	v := docker(t, "volume", "create")
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", v).Run() })
	return v
}

// run starts a container with the compose file's hardening and returns its
// name and published loopback port.
func run(t *testing.T, img, vol string, args ...string) (name, port string) {
	t.Helper()
	a := []string{"run", "-d", "--read-only", "--tmpfs", "/tmp:size=8m,mode=1777", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--pids-limit", "256", "--memory", "512m",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
		"--add-host", "host.docker.internal:host-gateway",
		"-v", vol + ":/data", "-p", "127.0.0.1::443/tcp", img}
	name = docker(t, append(a, args...)...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	p := docker(t, "port", name, "443/tcp")
	_, port, _ = net.SplitHostPort(strings.Split(p, "\n")[0])
	return name, port
}

func healthy(t *testing.T, name, bin string) {
	t.Helper()
	harness.WaitFor(t, 30*time.Second, name+" healthcheck", func() bool {
		return exec.Command("docker", "exec", name, bin, "healthcheck").Run() == nil
	})
}

func stop(t *testing.T, name string) {
	t.Helper()
	docker(t, "stop", "-t", "5", name)
	docker(t, "rm", name)
}

// readFile copies a file out of a volume through a throwaway container
// (the images are distroless: no shell, no cat).
func readFile(t *testing.T, img, vol, path string) []byte {
	t.Helper()
	c := docker(t, "create", "-v", vol+":/data", img)
	defer exec.Command("docker", "rm", "-f", c).Run()
	tmp := filepath.Join(t.TempDir(), "f")
	docker(t, "cp", c+":"+path, tmp)
	b, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, img, vol, path string, b []byte) {
	t.Helper()
	c := docker(t, "create", "-v", vol+":/data", img)
	defer exec.Command("docker", "rm", "-f", c).Run()
	tmp := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	docker(t, "cp", tmp, c+":"+path)
}

func version(t *testing.T, img string) string { return docker(t, "run", "--rm", img, "version") }

// decoyServer is a TLS web server on all interfaces, standing in for the
// stock nginx an operator puts behind a relay.
func decoyServer(t *testing.T) (hostPort string) {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "decoy-ok") }))
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Listener.Close()
	s.Listener = l
	s.StartTLS()
	t.Cleanup(s.Close)
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return "host.docker.internal:" + p
}

func tlsGet(addr, sni string) (string, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) // prober, not a client
	if err != nil {
		return "", err
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	return string(b), nil
}

var reKey = regexp.MustCompile(`(?m)^identity_key:.*$`)

// The relay image on a fresh named volume: init as the nonroot user (the
// fresh-volume /data bug), run with the compose hardening, answer visitors
// with the decoy, then upgrade and roll back over the same volume without
// losing the identity.
func TestRelayImageUpgradeRollback(t *testing.T) {
	arch := needDocker(t)
	prev := os.Getenv("LAB_PREV_DIR")
	oldImg := image(t, arch, "dotvpn-relay", "dotvpn-relay", oldVer, prev)
	newImg := image(t, arch, "dotvpn-relay", "dotvpn-relay", newVer, "")
	if got := version(t, oldImg); prev == "" && got != oldVer {
		t.Fatalf("old image reports %q", got)
	}
	if got := version(t, newImg); got != newVer {
		t.Fatalf("new image reports %q", got)
	}

	vol := volume(t)
	out := docker(t, "run", "--rm", "-v", vol+":/data", oldImg, "init", "-config", "/data/config.yaml", "-decoy", decoyServer(t))
	if !strings.Contains(out, "identity public key:") {
		t.Fatalf("init output %q", out)
	}
	// Enrollment needs a control plane; here the trusted key is written
	// directly, which is all `run` needs (the enroll flow itself is covered
	// by the functional suite).
	ctlPub, _, _ := auth.GenerateKey()
	cfg := readFile(t, oldImg, vol, "/data/config.yaml")
	cfg = regexp.MustCompile(`(?m)^trusted_keys:.*$`).ReplaceAll(cfg, []byte("trusted_keys: ["+auth.EncodeKey(ctlPub)+"]"))
	writeFile(t, oldImg, vol, "/data/config.yaml", cfg)
	identity := string(reKey.Find(cfg))
	if identity == "" || strings.Contains(identity, `""`) {
		t.Fatalf("no identity key in the written config: %q", identity)
	}

	for _, step := range []struct{ name, img string }{{"old", oldImg}, {"upgrade", newImg}, {"rollback", oldImg}} {
		t.Run(step.name, func(t *testing.T) {
			name, port := run(t, step.img, vol, "run", "-config", "/data/config.yaml")
			healthy(t, name, "/usr/local/bin/dotvpn-relay")
			body, err := tlsGet("127.0.0.1:"+port, "www.example.com")
			if err != nil || !strings.Contains(body, "decoy-ok") {
				t.Fatalf("visitor did not get the decoy: %v %q", err, body)
			}
			if got := string(reKey.Find(readFile(t, step.img, vol, "/data/config.yaml"))); got != identity {
				t.Fatal("identity key changed across the version swap")
			}
			if u := docker(t, "inspect", "-f", "{{.Config.User}}", name); u != "nonroot" {
				t.Fatalf("container user %q", u)
			}
			stop(t, name)
		})
	}
}

// The core image, all-in-one, on a fresh volume: same drill. The TLS identity
// (the pin clients hold) must survive both swaps.
func TestCoreImageUpgradeRollback(t *testing.T) {
	arch := needDocker(t)
	prev := os.Getenv("LAB_PREV_DIR")
	oldImg := image(t, arch, "dotvpn-core", "dotvpn-core", oldVer, prev)
	newImg := image(t, arch, "dotvpn-core", "dotvpn-core", newVer, "")
	if got := version(t, newImg); got != newVer {
		t.Fatalf("new image reports %q", got)
	}
	vol := volume(t)
	docker(t, "run", "--rm", "-v", vol+":/data", oldImg, "init", "-role", "allinone", "-config", "/data/config.yaml", "-data-dir", "/data", "-advertise", "127.0.0.1:443")

	var pin string
	for _, step := range []struct{ name, img string }{{"old", oldImg}, {"upgrade", newImg}, {"rollback", oldImg}} {
		t.Run(step.name, func(t *testing.T) {
			name, port := run(t, step.img, vol, "allinone", "-config", "/data/config.yaml")
			healthy(t, name, "/usr/local/bin/dotvpn-core")
			harness.WaitTCP(t, "127.0.0.1:"+port)
			got := harness.PinOf(t, "127.0.0.1:"+port)
			if pin == "" {
				pin = got
			} else if got != pin {
				t.Fatalf("TLS pin changed across the version swap: %s -> %s", pin, got)
			}
			body, err := tlsGet("127.0.0.1:"+port, "www.example.com")
			if err != nil || !strings.HasPrefix(body, "HTTP/1.1 ") {
				t.Fatalf("visitor got no HTTP answer: %v %q", err, body)
			}
			stop(t, name)
		})
	}
}
