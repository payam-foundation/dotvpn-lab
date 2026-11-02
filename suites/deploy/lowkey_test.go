package deploy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-lab/internal/harness"
)

// ADR-016: deploy/install.sh --lowkey on a real systemd, driven end to end.
// The relay is the garble "neutral" build; control and the decoy are small
// TLS servers inside the container. Skips without Docker or garble.
// ponytail: runs a privileged container (systemd needs it); CI runners and a
// dev host are fine, a locked-down Docker host skips via the first check.

const systemdDockerfile = `FROM debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus iproute2 procps curl ca-certificates openssl python3 \
 && rm -rf /var/lib/apt/lists/* && systemctl mask getty.target console-getty.service systemd-logind.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
`

const fixtures = `
import http.server, ssl, json, sys
port, body = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def reply(self):
        if body == "ctl":
            ok = self.headers.get("Authorization") == "Bearer tok-123"
            self.send_response(200 if ok else 401); self.end_headers()
            if ok: self.wfile.write(json.dumps({"trusted_keys": ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"]}).encode())
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
    do_GET = do_POST = reply
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("/root/c.pem", "/root/k.pem")
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
`

func sh(t *testing.T, ctr, script string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command("docker", "exec", ctr, "bash", "-c", script)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func mustSh(t *testing.T, ctr, script string) string {
	t.Helper()
	out, err := sh(t, ctr, script)
	if err != nil {
		t.Fatalf("%s\n%v\n%s", script, err, out)
	}
	return out
}

func TestLowkeyInstall(t *testing.T) {
	arch := needDocker(t)
	garble, err := exec.LookPath("garble")
	if err != nil {
		t.Skip("garble not on PATH (go install mvdan.cc/garble@<version built with go.mod's Go>)")
	}
	root := filepath.Join(harness.Root(), "..", "dotvpn-relay")
	dist := t.TempDir()
	bin := filepath.Join(dist, "dotvpn-relay-neutral_linux_"+arch)
	b := exec.Command(garble, "-literals", "-tiny", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X main.version=v0.0.0-lab", "-o", bin, "./cmd/dotvpn-relay")
	b.Dir = root
	b.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("garble build: %v\n%s", err, out)
	}
	sum, err := exec.Command("sha256sum", bin).Output()
	if err != nil { // macOS host
		sum, err = exec.Command("shasum", "-a", "256", bin).Output()
		if err != nil {
			t.Fatal(err)
		}
	}
	line := strings.Fields(string(sum))[0] + "  " + filepath.Base(bin) + "\n"
	if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte(systemdDockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	img := fmt.Sprintf("dotvpn-lab/systemd:%d", time.Now().UnixNano())
	docker(t, "build", "-q", "-t", img, ctx)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", img).Run() })

	ctr := docker(t, "run", "-d", "--privileged", "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"--tmpfs", "/run", "--tmpfs", "/run/lock", img)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", ctr).Run() })
	harness.WaitFor(t, 30*time.Second, "systemd up", func() bool {
		out, _ := exec.Command("docker", "exec", ctr, "systemctl", "is-system-running").Output()
		s := strings.TrimSpace(string(out))
		return s == "running" || s == "degraded"
	})

	docker(t, "cp", filepath.Join(root, "deploy/install.sh"), ctr+":/root/install.sh")
	docker(t, "cp", dist, ctr+":/root/dist")
	fx := filepath.Join(ctx, "fx.py")
	if err := os.WriteFile(fx, []byte(fixtures), 0o644); err != nil {
		t.Fatal(err)
	}
	docker(t, "cp", fx, ctr+":/root/fx.py")
	mustSh(t, ctr, `cd /root && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout k.pem -out c.pem -subj /CN=site.example.test -days 2 2>/dev/null
openssl x509 -in c.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 > pin`)
	docker(t, "exec", "-d", "-w", "/root", ctr, "python3", "fx.py", "9443", "ctl")
	docker(t, "exec", "-d", "-w", "/root", ctr, "python3", "fx.py", "8443", "decoy-ok")
	harness.WaitFor(t, 10*time.Second, "fixtures", func() bool {
		_, e := sh(t, ctr, `ss -tln | grep -q :9443 && ss -tln | grep -q :8443`)
		return e == nil
	})

	const name = "quiet-fox"
	install := `cd /root && ENROLL_TOKEN=tok-123 bash install.sh --lowkey --name ` + name +
		` --quiet-logs --from-dir /root/dist --control https://127.0.0.1:9443 --pin "$(cat pin)"` +
		` --decoy 127.0.0.1:8443 --listen 0.0.0.0:443 2>&1`

	t.Run("failed enrollment leaves nothing", func(t *testing.T) {
		out, err := sh(t, ctr, strings.Replace(install, "tok-123", "wrong", 1))
		if err == nil {
			t.Fatalf("install with a wrong token succeeded:\n%s", out)
		}
		if o, e := sh(t, ctr, "id "+name+" 2>/dev/null; ls /etc/"+name+" /usr/local/bin/"+name+" 2>/dev/null"); e == nil && strings.TrimSpace(o) != "" {
			t.Fatalf("failed install left files behind:\n%s", o)
		}
	})

	t.Run("install and self-audit", func(t *testing.T) {
		out := mustSh(t, ctr, install)
		if !strings.Contains(out, "self-audit passed") || strings.Contains(out, "FAIL") {
			t.Fatalf("self-audit:\n%s", out)
		}
	})

	t.Run("outside view carries no project name", func(t *testing.T) {
		mustSh(t, ctr, `P=$(systemctl show -p MainPID --value `+name+`)
! { ps -o args= -p $P; ss -tlnp; systemctl cat `+name+`; journalctl -u `+name+` --no-pager -o cat; cat /etc/`+name+`/config.yaml | grep -v identity_key; } | grep -Eqi 'dotvpn|payam|relay|vpn'`)
		if out := mustSh(t, ctr, `stat -c '%a %U:%G' /etc/`+name+` /etc/`+name+`/config.yaml`); out != "750 root:"+name+"\n640 root:"+name+"\n" {
			t.Fatalf("modes/owners: %q", out)
		}
		// Admin port is loopback only, and randomized (not the 9101 default).
		out := mustSh(t, ctr, `ss -tlnp | grep '"`+name+`"'`)
		if strings.Contains(out, ":9101") || strings.Contains(out, "0.0.0.0:2") {
			t.Fatalf("admin listener exposed or default: %s", out)
		}
		if m := mustSh(t, ctr, `curl -s http://$(grep admin_listen /etc/`+name+`/config.yaml | cut -d' ' -f2)/metrics`); !strings.Contains(m, "quiet_fox_parked") {
			t.Fatalf("metric not derived from the name: %q", m)
		}
	})

	t.Run("visitor gets the decoy, byte for byte", func(t *testing.T) {
		got := mustSh(t, ctr, `curl -sk --max-time 5 https://127.0.0.1:443/`)
		want := mustSh(t, ctr, `curl -sk --max-time 5 https://127.0.0.1:8443/`)
		if got != want || got != "decoy-ok" {
			t.Fatalf("relay %q, decoy %q", got, want)
		}
		cert := func(p string) string {
			return mustSh(t, ctr, `echo | openssl s_client -connect 127.0.0.1:`+p+` 2>/dev/null | openssl x509 -noout -fingerprint -sha256`)
		}
		if cert("443") != cert("8443") {
			t.Fatal("relay presented a different certificate than the decoy")
		}
	})

	t.Run("upgrade, rollback", func(t *testing.T) {
		out := mustSh(t, ctr, "cd /root && bash install.sh --lowkey --name "+name+" --upgrade --from-dir /root/dist 2>&1")
		if !strings.Contains(out, "self-audit passed") {
			t.Fatalf("upgrade:\n%s", out)
		}
		mustSh(t, ctr, "bash /root/install.sh --lowkey --name "+name+" --rollback && systemctl is-active "+name)
	})

	t.Run("uninstall removes everything", func(t *testing.T) {
		mustSh(t, ctr, "bash /root/install.sh --lowkey --name "+name+" --uninstall")
		if out, err := sh(t, ctr, `ls /etc/`+name+` /usr/local/bin/`+name+`* /etc/systemd/system/`+name+`.service 2>/dev/null; id `+name+` 2>/dev/null; getent group `+name); err == nil || strings.TrimSpace(out) != "" {
			t.Fatalf("leftovers:\n%s", out)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		for _, c := range []struct{ args, want string }{
			{"--name dotvpn-x --decoy 127.0.0.1:8443", "must not contain"},
			{"--name my-relay --decoy 127.0.0.1:8443", "must not contain"},
			{"--name ok-name", "--decoy"},
			{"--name ok-name --decoy 127.0.0.1:8443 --control http://x", "https"},
			{"--name ok-name --decoy 127.0.0.1:443", "collides"},
		} {
			out, err := sh(t, ctr, "cd /root && bash install.sh --lowkey --from-dir /root/dist "+c.args+" 2>&1")
			if err == nil || !strings.Contains(out, c.want) {
				t.Errorf("%s: want refusal containing %q, got err=%v\n%s", c.args, c.want, err, out)
			}
		}
		tampered := mustSh(t, ctr, `cd /root && cp -r dist d2 && echo 00 >> d2/`+filepath.Base(bin)+`; bash install.sh --lowkey --name ok-name --decoy 127.0.0.1:8443 --from-dir d2 2>&1 || true`)
		if !strings.Contains(tampered, "checksum mismatch") {
			t.Errorf("tampered binary not refused:\n%s", tampered)
		}
	})
}
