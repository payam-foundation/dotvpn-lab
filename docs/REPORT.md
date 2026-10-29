# dotvpn security and leak gate report

Scope: `dotvpn-wire`, `dotvpn-core`, `dotvpn-relay`, `dotvpn-client`, `dotvpn-lab`.
Verification at time of writing: `go vet` clean and `go test -race -count=1 ./...` passing in all five repos; `govulncheck` 0 vulnerabilities in all repos.

## Findings (severity-ranked)

| # | Sev | Finding | Status | Fix |
|---|-----|---------|--------|-----|
| 1 | High | Relay mode B used static replayable `X-Relay-Key`; relay terminated TLS and saw control-plane plaintext | Fixed | Replaced by signed short-lived enrollment token + per-relay Ed25519 identity, offline verification, per-relay revocation (ADR-012). Reverse mode is default (ADR-013). |
| 2 | High | Silent close/RST on non-allowlisted SNI/non-TLS was a probing fingerprint; allowed-SNI hello was forwarded to node decoy | Fixed | Every invalid, replayed or probe connection gets the decoy response; timing normalised (ADR-014). `TestProbeResistanceAndReplay` checks knock replay and timing spread within 40 ms. |
| 3 | Medium | SPKI pin checked in `VerifyPeerCertificate` (gosec G123): bypassable via TLS session resumption | Fixed | Moved to `VerifyConnection` in `dotvpn-wire/transport/transport.go`. |
| 4 | Medium | Admin/metrics listeners not enforced loopback | Fixed | Core refuses non-loopback `AdminListen` at startup; covered in `reverse_relay_test.go` (admin lockdown). |
| 5 | Medium | Single binary shipped client+admin code on relay host | Fixed | Separate minimal `dotvpn-relay` binary, distroless non-root image (ADR-002 superseded by ADR-010). |
| 6 | Low | Config dirs created 0755 (G301) | Fixed | 0750. |
| 7 | Low | Unbounded field lengths cast to uint16 in `muxstream` (G115) | Fixed | Bounds check before cast. |
| 8 | Low | TUN MTU unvalidated | Fixed | 576–9000 enforced. |
| 9 | Info | `#nosec G407` (ephemeral one-shot AEAD seal in handshake) and `G402` (pinned TLS) | Accepted | Reviewed; annotated in code. |

## Checklist coverage

- Active probing (non-TLS, wrong SNI, valid SNI, replayed auth, decoy vs invalid knock): covered by `replay_probe_test.go`, `middlebox_test.go`. Partial hello and slow-read: handled by handshake read deadline (`relay.go`), not separately asserted.
- Identification: relay keeps no access logs, client IPs or version banner; no key material in errors/metrics (code review).
- Relay compromise model: reverse mode, relay stores only its own identity key; `reverse_relay_test.go` compromise checks.
- Replay/downgrade: X25519 forward secrecy per session, knock seen-cache, token expiry and revocation tested; KDF binds wire version (ADR-011).
- Client leaks: kill switch rules per OS in `internal/leak` + `internal/tun` (default deny, IPv6 blackholed, non-DNS UDP dropped to stop STUN/WebRTC leaks, bypass sockets marked/bound). Rule generation is unit-tested.
- SSRF/egress: RFC1918, loopback, `169.254.169.254` blocked on core; `e2e_test.go`.
- Admin: loopback only; authn on routes; tested.
- Dependencies/supply chain: govulncheck 0 vulns; CI runs govulncheck, gosec, gitleaks, trivy; goreleaser SBOM (Syft) + keyless cosign; Docker base pinned by digest.
- Race/fuzz: `-race` passes everywhere. Fuzz targets: `frame.FuzzRead`, `handshake.FuzzRespond`, `mimic.FuzzParseKnock`, `reverse.FuzzReadAuth`, `dnscarrier.FuzzDecode`; run as seed corpus in `go test`, smoke-fuzzed in CI.

## Needs-validation (deployment facts required)

Lab results (`lab/lab.md`) are mechanism checks against dated models of reported behaviour (`lab/documented-behaviours.md`). They narrow these items; none is closed by the lab alone.

- JA3/JA4 and packet sizes of relay/client vs a stock web server: measured on a real host against Chrome 156 and nginx 1.28 (see `hetzner-test-report.md`); JA4 now matches Chrome, ServerHello and probe replies match nginx. The lab repeats this on every run (`dotvpn-lab/suites/fingerprint`: JA4 and extension set of knock and relay-path hellos, first-packet entropy and classification, decoy ServerHello vs the decoy server) and records size and timing to `fingerprint.json` without a tolerance yet. Still open: client-side packet-size and idle-timing tolerance, and a capture from a real censor path.
- Decoy choice: valid certificate and content similarity depend on the chosen domain/decoy site. Not testable in the lab.
- Reverse mode needs core to reach the relay's public IP; if that direction is filtered, fall back to client-direct/CDN carriers (documented risk). The lab places the relay inside the censored side, so the reverse tunnel crosses the censor; read the `reverse` cells of `profiles/baseline.json` (`dotvpn-lab/suites/matrix`) for which profiles block it. Whether real operators allowlist the core address is unknown.
- DNS-shaped UDP carrier plausibility on the target ISP resolvers. The lab covers the DNS-hijack rules only (`russia-2026-10`, RU-DNS-1); real resolver behaviour is unverified.
- Per-OS kill switch behaviour on real hosts: Linux is now exercised end to end in netns (`dotvpn-lab/suites/leak`: TUN plus kill switch, tunnel or node killed mid-flow, zero non-endpoint IPv4, no IPv6, no non-DNS UDP, no local-resolver DNS). macOS pf and Windows firewall remain unit-tested rule sets only. nftables-only hosts without iptables compat remain untested.
- Timing uniformity under production load and network jitter (test tolerance 40 ms on loopback). `suites/chaos` adds netem loss, delay, jitter and reorder, node and relay restart and link flap, but does not assert decoy timing under load.
- Production-build SSRF guard: now asserted in `dotvpn-lab/suites/deploy` against the non-`e2e` core binary (loopback, RFC1918, CGNAT, link-local, metadata, `0.0.0.0` rejected).
- Throughput regression: `dotvpn-lab/suites/perf` (nightly, `LAB_PERF=1`) compares against `profiles/perf-baseline.json`; the band is provisional until several nightly runs set the spread. Veth numbers are not Hetzner numbers.

## Not covered

- iOS/Android (gomobile binding and native shells out of scope this round).
- Linux nftables-only hosts without iptables compat; macOS: other root processes can exit the physical interface (pf has no per-socket mark; `ponytail:` note in `sys_darwin.go`).
- ICMP and raw-socket fake-SNI desync carriers (explicitly excluded in plan).
- Third-party penetration test, hardware/physical compromise, traffic-analysis resistance beyond padding/jitter/rotation.
- Dependency audit beyond known-vuln DB (no manual review of transitive code, e.g. uTLS, quic-go).
- Rollback: the lab drills upgrade and rollback of the relay and core Docker images over preserved volumes (`dotvpn-lab/suites/deploy`; key, config and pin survive). Previous-release binaries are used when `LAB_PREV_DIR` is set; until a release tag exists the drill swaps the current source stamped with two versions, so version-skew behaviour is not yet exercised. Non-Docker (systemd) rollback is not drilled.
- Real censor networks. All lab verdicts come from simulated profiles; see `lab/lab.md`.
