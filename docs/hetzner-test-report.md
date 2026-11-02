# Hetzner test deployment report (anonymised)

Date: 2026-10-28. Host names and IPs are replaced with documentation values. Throwaway test server, to be deleted. Security hardening was deliberately skipped; this run checks that the code works, not that the host is locked down.

## Setup

| Item | Value |
| --- | --- |
| Host | Hetzner, Ubuntu 26.04.1 LTS, aarch64, 2 vCPU, 3.7 GiB RAM, 38 GB disk |
| Direct name | `direct.example.com` (DNS only, port 443 straight to core) |
| CDN name | `cdirect.example.com` (Cloudflare proxied, port 443) |
| Firewall | none (all ports open, by request) |
| Core | `dotvpn-core allinone`, systemd, built locally (`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 -trimpath`), copied with `scp`, installed with `deploy/install.sh --from-dir` |
| Relay | `dotvpn-relay` in Docker (image built on the host from the repo `Dockerfile`, distroless nonroot), published on `8443/tcp` |
| TLS | core: self-signed, clients pin the SPKI. Relay decoy: self-signed `CN=decoy.local`. No ACME. |
| Client | `dotvpn` built from `dotvpn-client` on the Mac, SOCKS5/HTTP mode only |

### Server changes

- 2 GiB `/swapfile` (in `fstab`), `vm.swappiness=10` (`/etc/sysctl.d/98-swap.conf`).
- Full `apt upgrade`; installed `docker.io`, `chrony`, `iperf3`, `htop`, `jq`, `sqlite3`, `dnsutils`.
- `install.sh` created user `dotvpn`, `/etc/dotvpn/config.yaml`, `/var/lib/dotvpn`, the hardened `dotvpn-core.service`, and `/etc/sysctl.d/99-dotvpn.conf` (BBR, `fq`).
- Relay: named volume `relay-data`, decoy cert in `/root/relay`, container `relay` (`--read-only`, `--cap-drop ALL`, `no-new-privileges`, 512 MB, 1 CPU, `unless-stopped`).
- Core config: `node.advertise=direct.example.com:443`, `transports.cdnws_path` set to a random path. `h3` was switched on for one test and set back to `false`.

## Results

### Functional

| Test | Result |
| --- | --- |
| Direct h2 via `direct` (SOCKS5 and HTTP proxy) | Pass, egress IP = server IP |
| CDN WebSocket via `cdn` (Cloudflare) | Pass |
| Relay path: client -> Docker relay -> reverse tunnel -> core | Pass; relay holds 4 parked tunnels |
| HTTP/3 (`h3: true`) | Pass |
| 20 parallel connections (h2, relay) | 20/20 OK |
| Relay enrollment, token replay | First enroll OK, replay refused with 401 |
| Unit tests `-race` (wire, core, relay, client) | All pass |
| `dotvpn-lab` full suite (`-race`, includes Snowflake) | 20/20 pass, 41 s in the first pass; 30/30 after the second-pass tests were added |

### Security behaviour (observed from outside)

| Check | Result |
| --- | --- |
| Plain GET and unknown paths on core | Built-in decoy page (200, or 404 with same body) |
| Tunnel `CONNECT` without a token | Decoy 404 page, no reset |
| Response time of valid path vs junk paths | 107-120 ms average for all four, no timing tell |
| Egress to `127.0.0.1`, `169.254.169.254`, `10.0.0.1`, server's own `8081` | All refused |
| Admin (`8081`) and metrics (`9100`) from the internet | Connection refused (loopback only) |
| Relay: plain GET, unknown TLS client, random bytes | Decoy TLS server answers, no reset |

### Performance (Mac on a roughly 100 Mbit link, test file 50 MB from Cloudflare)

| Path | Throughput | Small-request latency |
| --- | --- | --- |
| Mac direct (reference) | 12.4 MB/s | n/a |
| h2 tunnel | 10.5 MB/s | 47 ms |
| CDN WebSocket (Cloudflare) | 9.9 MB/s | 62 ms |
| Relay (Docker) | 12.6 MB/s | 49 ms |
| HTTP/3 | 6.7 MB/s | n/a |

- 8 simultaneous 50 MB downloads: about 12 MB/s total, so the Mac's link is the limit, not the server.
- During that load: core about 30% of one core, 33 MB RSS; relay 11% CPU, 22 MiB. Swap stayed at 0 B used.
- Idle: core 14 MB, relay 2-6 MiB.
- Tunnel overhead versus direct is about 15% (h2) to about 20% (CDN). The relay path showed none.

### Resilience

| Event | Outcome |
| --- | --- |
| `systemctl restart dotvpn-core` | h2 and CDN clients recover within a request or two; relay path fails for a few seconds, fine after the pool refills (about 8 s) |
| `kill -9` core | systemd restarts it (`NRestarts=1`), clients recover within about 10 s |
| `docker restart relay` | Core re-parks 4 tunnels, all paths work |
| Full host reboot | Core, Docker, relay and swap all return on their own; all three client paths work after about 1 min |

## Findings and fixes

Status after the second pass. Every code fix has a test and passes `go test -race` in all five modules.

| # | Finding | Status |
| --- | --- | --- |
| 1 | Relay Docker `init` failed on a fresh volume (`/data` root-owned, image runs as 65532) | **Fixed.** `dotvpn-relay/deploy/docker/Dockerfile` now ships `/data` owned by `nonroot`. Verified on the server: `init` on a new named volume works with no chown. |
| 2 | `dotvpn-relay enroll` could not reach a self-signed core | **Fixed.** New `-pin` flag (SPKI SHA-256, checked in `VerifyConnection`). Test `TestEnrollPin` covers no pin, wrong pin, good pin. On the server: no pin and wrong pin refused, good pin enrolled, token reuse refused (401). |
| 3 | `invite` carried only the h2 endpoint; the `cdnws` entry copied the direct address and pin and could not reach Cloudflare | **Fixed.** New `node.transports.cdn_host` (`init -cdn-host`) makes the `cdnws` endpoint use the CDN host with no pin. `invite` now includes h3, cdnws and webtunnel. Test `TestExtraEndpointsCDNHost`. One invite now drives the whole fallback ladder (see below). |
| 4 | **DNS carrier downloads ran at about 1.7 KB/s** (found this pass) | **Fixed** in `dotvpn-wire/dnscarrier`. The server's KCP MTU was the upload size (96 B), so each answer carried one small segment instead of up to 700 B. Server side now uses `MaxDown`. Measured 1.7 KB/s to 17 KB/s on the VPS, which is the design ceiling (25 polls/s x 700 B). Regression test `TestDownstreamThroughput` fails (9.7 s) without the fix. |
| 5 | Relay path blank a few seconds after a core restart | Expected (tunnel pool refills). With a full invite the client falls back to other carriers meanwhile. |
| 6 | HTTP/3 about 35% slower than h2 | Open. Not investigated. |
| 7 | Docker `CMD-SHELL` healthcheck fails on distroless | Test artefact only; repo Dockerfile and compose use `CMD`. |
| 8 | `install.sh` opens `80/tcp` and `443/udp` in `ufw`; core listens only on 443 | Open, harmless. |

The relay `knock` key still has no operator command; hidden-node deployments get it from control's expanded server list.

## Second pass results

All on the redeployed binaries (core, relay container, client built from the fixed repos).

| Test | Result |
| --- | --- |
| Client from one `invite`, nothing blocked | h2 |
| Block TCP/443 to the server | falls back to **h3** |
| Block TCP and UDP/443 | falls back to **cdnws** via Cloudflare |
| WebTunnel alone | works, egress is the server |
| Reverse TCP via relay (Docker) | works, 9.1 MB/s |
| DNS carrier via relay (`-dns-listen :5353`) | works, 17 KB/s after fix (a last-resort carrier) |
| Account-key flow, control reached through Cloudflare | works |
| 200 parallel requests (h2) / 100 parallel (relay) | 200/200 and 100/100 HTTP 200 |
| 50 MB download over h2 | 16 MB/s |
| SSRF: `127.0.0.1`, `[::1]`, `10.0.0.1`, `169.254.169.254` through the tunnel | all blocked |
| Probe of `/` and of the secret CDN path without upgrade, on both hostnames | decoy 200 and 404, no reset |
| Garbage UDP at the DNS carrier port | random bytes get no reply; non-zone queries get NXDOMAIN |
| Full host reboot | core, Docker, relay, swap and BBR all return; reverse and DNS paths work again |
| `go vet` and `go test -race` | wire, core, relay, client all pass; e2e 30/30 |
| Fuzz, 20 s each: `FuzzDecode`, `FuzzRead`, `FuzzRespond`, `FuzzParseKnock`, `FuzzReadAuth` | no crashes |

A 100 MB request to `speed.cloudflare.com` returns 403 with or without the VPN; that is Cloudflare's size cap, not a tunnel fault.

## Not tested

Status after the third pass. TUN, kill switch, leak guards on Linux, Snowflake (own broker) and ACME (staging) are now covered, see the third-pass section.

- macOS (`pf`) and Windows (`netsh`) TUN and kill switch. Only the rule-set unit tests ran. They rewrite the host's routing and firewall, so they need a disposable machine or VM, not this Linux VPS.
- TUN throughput. The netns runs only checked routing, DNS and leaks, not speed.
- Public Snowflake pool. Only our own broker, server and volunteer proxy ran.
- ACME inside the running core (domain set, TLS-ALPN on 443), certificate renewal, production CA. The staging test covers the `newCerts` code path with HTTP-01.
- Real restricted-country network. The relay was exercised for code correctness and performance only.
- Real-network JA3/JA4 and packet-size comparison of relay and client against a stock web server (also open in `REPORT.md`).

## Cleanup when done

The test server, its DNS records and all test tokens were destroyed after the run. Treat any token printed during testing as burned.

## Third pass: TUN, kill switch, leak guards, Snowflake, ACME

Method: client ran inside a throwaway Linux netns on the VPS (veth to host, nft counters on the host side count any packet that is not for the core or the veth peer, v4 and v6). Host routes, DNS and firewall were not changed.

| Check | Result |
| --- | --- |
| Control (no client): counters see v4/v6 egress | 3/3 packets, counter works |
| `-tun`: exit IP, DNS, HTTPS by name | exit `203.0.113.10`, fakedns answers, 200 |
| `-tun`: direct DNS to `1.1.1.1`, IPv6, STUN-style UDP | captured or blocked, 0 leaked |
| Graceful stop | routes, `resolv.conf`, device restored |
| `-kill-switch` rules | v4 and v6 chains as in `leak.Linux`, 0 leaked |
| Tunnel path cut (core 443 tcp+udp dropped, 35 s) | exit-IP lookup, direct v4/v6 HTTP and ICMP failed, 0 packets leaked; DNS got fakedns answers (inside the tunnel); tunnel recovered after path restored |
| `kill -9` client | rules persist, 0 leaked |
| `-unblock` | chains removed, traffic flows |
| Socket with `SO_MARK 0x6476` while kill switch is on | bypasses it (2 packets); arbitrary marks are rejected. Setting a mark needs CAP_NET_ADMIN, which can also flush the rules, so not a remote leak. |
| `TestSnowflake` (broker, server, volunteer proxy, client) | pass with real network (15 s); fails in a network-restricted sandbox (WebRTC needs UDP/STUN) |
| ACME (new `TestACMELive`, Let's Encrypt staging, HTTP-01, `direct.example.com`) | issued in 7 s, hostname verifies, restart reuses stored cert |

Harness note: a netns client that finds `resolvectl` talks to the host's systemd-resolved over shared D-Bus, and the netns `dotvpn0` ifindex collided with host `docker0`, leaving host DNS broken until `resolvectl revert docker0`. Test artifact, but it shows the client does not check which namespace it is in.

Not covered: see "Not tested" above.

Details of the ACME run: the live core owns 443, so the test used a temporary data dir, the Let's Encrypt staging CA and HTTP-01 on port 80. Validation came from seven Let's Encrypt vantage points, the certificate was issued in 7 s (issuer `(STAGING) Artificial Amaranth YE1`), and a second `newCerts` call on the same data dir reused the stored certificate in under 10 s. The test is `dotvpn-core/internal/node/acme_live_test.go`. It skips unless `DOTVPN_ACME_DOMAIN` is set, so normal runs are unchanged.

Details of the kill-switch cut test: after the core path was dropped for 35 s, exit-IP lookup, direct v4 HTTP, IPv6 HTTP and ICMP all failed, and host counters saw no packet outside the core and veth peer. DNS to 1.1.1.1 and 8.8.8.8 still returned `198.18.0.16`: that is the client's fakedns inside the tunnel, not a leak. TCP connects to 1.1.1.1:443 and :53 and a UDP send to :19302 returned success because the packets enter `dotvpn0` and the client's local stack accepts them; they cannot go further with the core path down. Not verified: what the application sees when it then sends data (expected: stall or reset).

## Relay exposure audit (code review plus live probes)

Question: can an in-country relay reveal sensitive data or operational patterns?

Clean:

- Logs: the container log holds only `relay started`, before and after probes. HTTP and TLS error logs are discarded in `decoy.go` and `main.go`. No IP, SNI, key or node ID is logged.
- Disk: `config.yaml` is 330 B; the `Config` struct has only listen, DNS, identity key, trusted control keys and decoy fields. `enroll` never writes the control URL.
- Admin `:9101` is unreachable from outside (loopback only).
- The relay splices ciphertext only; it never sees tokens, accounts or destinations.
- Probes: 5 non-knock TLS requests answered in 85-187 ms with the decoy page; plain HTTP to the TLS port gets a 400, not a close or reset.

Exposed:

1. Core's IP is visible to the relay host while the reverse tunnel is up (long-lived connection, 25 s cover traffic). "Knows no core address" holds for disk, not for the live socket table or memory. Use a dedicated egress IP for relay links.
2. Client knock key derives from public values (relay public key, node ID). Anyone holding an invite can confirm the relay and consume parked tunnels. Give each user cohort its own relay set and rotate.
3. The built-in decoy is fingerprintable (Go `net/http` headers and 400 text, one static "under construction" page, test cert `CN=decoy.local`). Production should use `decoy: 127.0.0.1:443` pointing at a real nginx with a real certificate.
4. Random bytes to the TLS port got an empty reply; compare against a real nginx before relying on it.
5. Padding exists only in the handshake (0-64 B); tunnelled traffic keeps its packet-size and timing shape.
6. Hosting-provider netflow, payment identity and host conntrack link the relay back to its operator; the code cannot hide that.

Not verified: a grep of the relay volume for the core hostname and IP was blocked by the approval gate; the code has no field that could hold them.

## Fixes after the report

- Kill switch mark: `dotvpn-client/internal/tun/sys_linux.go` generates a random `fwMark` per process. Live check on the VPS (netns, host nftables counters): with the kill switch on and the client killed, sockets with the old mark `0x6476` and with `0x1` were refused, a socket with the process's own mark was let through, and the tunnel itself worked before the kill.
- Namespace check: same file, `inInitNetNS`. Live check: client in a netns now writes `nameserver 198.18.0.2` to the netns `resolv.conf` and leaves host systemd-resolved alone. One thing to note in the output: host link `vch0` appeared in `resolvectl dns` (empty) after the run. That is the veth being created in the host namespace by the test harness, not a client change; the link list returned to normal after cleanup.
- Docs: `dotvpn-relay/docs/adr/015-relay-operational-exposure.md`, relay README production note. A first draft added a `relay_source_ip` option; it was removed because a node has one IP.
- Re-run after changes: `go vet` and tests for wire, core, relay, client; e2e `-short` passes.

## Fingerprint and traffic-shape pass (real deployment)

Tool: `dotvpn-lab/cmd/fpcheck` (JA3, JA4, ServerHello, knock probe). Baselines: real Chrome 156 and Firefox 154 on the Mac, stock nginx 1.28 on the VPS. Test relay and nginx were removed afterwards.

| Check | Result |
| --- | --- |
| Knock ClientHello JA4 vs Chrome 156 | **Was different**: `t13d1516h2_8daaf6152771_d8a2da3f94cd` against Chrome's `t13d1517h2_8daaf6152771_cb7bf5808d99`. The utls Chrome 133 preset lacks extension 51764 and signature schemes 0x0904-0x0906. Fixed (`mimic.ChromeCurrent`, also used by `DialTLS`); now identical to Chrome, 20/20 hellos |
| JA3 | Varies per connection for both (Chrome shuffles extensions); ours too, 20 of 20 distinct |
| Relay ServerHello vs nginx behind it | Identical: TLS 1.3, `0x1301`, extensions 43 and 51, 1210-byte record; same for a wrong SNI |
| Non-TLS probes (HTTP GET, garbage, random bytes, SSH banner) | Reply bytes and close behaviour identical to nginx, 5 runs each |
| Truncated TLS hello, empty connection | Both wait and send nothing, same 2 s idle |
| Timing | Median response identical to the resolution measured (0.00 s, 2.00 s) |
| Valid knock but wrong node ID | Gets the decoy (old unit test, reconfirmed live) |
| Many nodes on one relay | New test `TestRelayServesManyNodes`: three nodes parked, each client reaches only its own node |

Traffic shape, offloads off so sizes are wire sizes (10 MB download plus 8 small requests plus 30 s idle, relay path vs nginx over h2):

| | Relay path | nginx h2 |
| --- | --- | --- |
| Server to client packets | 99% at full MSS (1448), p50 1448 | 99% at full MSS, p50 1448 |
| Client to server packets | mean 159 B, p50 89, 24% in 256-512 B, 33% under 64 B | mean 85 B, p50 58, 14% in 256-512 B, 58% under 64 B |
| Idle | cover records every 2-15 s (mean about 10 s) | one 30 s silence |

Reading: bulk download is indistinguishable by size. Two shape differences remain. The client-to-server side is larger (relay framing adds a record header, up to 31 padding bytes and a 16-byte tag per record, and requests are batched differently). And a quiet relay link emits a small record every 2-15 s where a real web connection goes silent. A statistical classifier on timing could use either. Not fixed: matching an h2 session's timing would need a traffic-shaping design, not a parameter. The 25 s cover interval is already configurable in code (`reverse.DefaultIdle`).

Side findings during this pass:

- `net.ipv4.ip_forward` on the VPS had become 0, which silently broke the Docker-published relay port (SYNs arrived, no SYN-ACK). Cause not found; the earlier netns tests and Docker do not set it off in this repo. Set to 1 and persisted in `/etc/sysctl.d/99-forward.conf`. Operator note: a relay in Docker needs forwarding on, and a health check from outside would have caught this (the container's own check stayed healthy).
- A client config with the wrong node ID or relay key gets `handshake: bad padding` or `responder authentication failed`, which looks like a protocol fault. The relay is behaving as designed (that node has no parked tunnel, so a knock gets the decoy), but the client message could say "relay did not answer as a dotvpn node".
- `TestMintVerify` in `dotvpn-wire/auth` failed about 6% of runs (251 of 4000 fresh tokens already end in `AA`, so the tamper edit changed nothing). Test bug, not a verifier bug. Fixed: the test now edits a middle character; 600 runs with `-race` pass.

## Open items

| # | Item | Severity | Next step |
| --- | --- | --- | --- |
| 1 | ~~`SO_MARK 0x6476` bypasses the Linux kill switch~~ | Fixed (partly) | Mark is now random per process, so the old fixed value no longer bypasses. Root can still read it from `iptables -S` or use a mark it knows; industry check: WireGuard (`wg-quick`) and Mullvad both exempt traffic by fwmark (Mullvad's is a fixed constant, plus a cgroup2 match for split tunnel), and both accept that root can bypass or flush the rules. Ours is now stricter than a fixed mark. A cgroup match would only matter for split tunnel. macOS: all root sockets still bypass `pf` (platform limit) |
| 2 | ~~Client does not check its network namespace before calling `resolvectl`~~ | Fixed | `resolvectl` is used only when the client shares PID 1's network namespace, otherwise `/etc/resolv.conf` |
| 3 | Relay exposure items 1-5 above | Partly fixed | 1: not fixable (one IP per node); mitigated by many nodes per relay and many relays per node (ADR-015). 2, 3: operator rules (ADR-015). 4: closed, matches nginx. 5: measured, residual (see fingerprint pass) |
| 4 | HTTP/3 about 35% slower than h2 | Low | Investigate |
| 7 | Relay link timing and client-side packet sizes differ from a real h2 session | Medium | Needs a shaping design (ADR) and a classifier-style test |
| 5 | macOS and Windows kill switch untested end to end | Medium | Test on a VM or spare machine |
| 6 | Production ACME inside core and renewal untested | Medium | Run core with a domain on staging for more than one renewal window |

## 2026-10-29: hardening pass (wire v0.2.0) live check

Same host (`203.0.113.10`, aarch64). Only `dotvpn-core` was redeployed (built `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 -trimpath`, no `-tags e2e`). The relay container was not touched: it is an L4 passthrough and holds no client code.

Rollback kept on the host: `/usr/local/bin/dotvpn-core.prev` (previous binary), `/etc/dotvpn/config.yaml.pre-v020`, `/var/lib/dotvpn.pre-v020` (copy of data dir). Command: `cp /usr/local/bin/dotvpn-core.prev /usr/local/bin/dotvpn-core && systemctl restart dotvpn-core`. Not needed; nothing regressed. Delete the `.pre-v020` copies with the server (they hold keys).

| Check | Result |
| --- | --- |
| Service after restart, decoy on `:443` (plain GET, h2) | Pass, 200 |
| h2, h3, cdnws (Cloudflare), webtunnel via client (SOCKS5 and HTTP) | Pass, egress IP = server IP |
| Data-plane verify (`/generate_204` through the new session) before "connected" | Pass on all four carriers |
| Persistence: `state.json` written; restart reconnects to the same endpoint | Pass |
| Local proxy auth, non-loopback bind: no auth refused at startup; with `listen_auth` SOCKS5/HTTP good creds pass, wrong or missing creds refused | Pass |
| UDP over the tunnel (`Engine.DialPacket`): DNS to `9.9.9.9:53` on h2, h3, cdnws | Pass (reply with answers) |
| UDP STUN (`stun.cloudflare.com:3478`) on h2 and h3: reflexive address is the server's | Pass |
| UDP to `10.0.0.1:53` | Refused (`destination not allowed`) |
| UDP to a port outside 53/123/443/3478 (`:19302`) | Refused by policy |
| Node advertises `udp=1` in the invite endpoints | Pass |
| **ECH** `ech=require` on `cdirect.example.com` (Cloudflare publishes an ECH config in its HTTPS record) via cdnws | Pass, egress = server IP |
| `ech=auto` on `cdirect.example.com` | Pass |
| `ech=require` on `direct.example.com` (no HTTPS record, no ECH) | Fails closed: `ech required but not available: no ech in HTTPS record`, no traffic leaves |
| **TUN mode** (`-tun -kill-switch`, Linux container on the Mac, real TUN + iptables), carrier cdnws and carrier h2 | Pass: TCP egress = server; DNS to `9.9.9.9` answered by fakedns; STUN to `162.159.207.0:3478` reports `203.0.113.10` (the tunnel exit, not the Mac's IP); NTP over UDP/123 answered; UDP/9999 blocked |

Lab (Docker on the Mac, `make lab-docker PKGS="./suites/netns ./suites/leak ./suites/fingerprint"`): all pass. Fingerprint suite includes `TestECHHelloMatchesChrome` (GREASE and real ECH); leak suite shows 0 packets on the physical NIC with the tunnel up. New functional suite `suites/functional/udp_test.go` covers h2, h3, cdnws, webtunnel and the reverse relay, the UDP port allow-list, and the missing-capability refusal. `suites/censor` gained `TestMiddleboxUDPFallsBackOffH3` (QUIC cut and SNI blocked, UDP lands on cdnws).

Android (arm64 API 34 emulator, headless, `SmokeTest.kt` against `203.0.113.10` with a fresh static invite): pass. The VPN service connected, an HTTPS 204 fetch and a DNS query to `9.9.9.9:53` both came back through the tunnel. Findings fixed on the way: `DotvpnService` overwrote the `Failed` state with `Off` (error now kept and logged), and the test now calls `VpnService.prepare()` and uses HTTPS (cleartext is blocked by the platform on API 34). Run it with the install, `appops set ... ACTIVATE_VPN allow`, then `am instrument -e invite <invite>` (Gradle's `connectedDebugAndroidTest` uninstalls the app, which drops the appop).

Not verified live:
- Relay path with the new client against the live host (relay container left on the old build; the lab covers the reverse path with UDP).
- ECH with a distinct inner/outer name on a self-run front: only Cloudflare's ECH was exercised live; the split is lab-covered.
- No in-country testing; `REPORT.md` "needs-validation" items stay open.

## 2026-10-31: relay lowkey install live check

Host `91.98.137.183`, Ubuntu 26.04 aarch64, existing `dotvpn-core` service and `relay-test` container left running. Installer: `dotvpn-relay/deploy/install.sh --lowkey` with the `neutral` artifact and nginx 1.30.6 as the operator decoy (ADR-016 in `dotvpn-relay`).

- Install, enroll and start: service user, `/etc/<name>/config.yaml` (`root:<name>`, 0640) and unit created under the random name; self-audit passed (no forbidden token in created files, `ps`, `ss -tlnp`, `systemctl cat`, journald or binary strings). `systemd-analyze security` exposure 1.9.
- Failed enrollment: rollback trap removed user, files and unit; nothing left behind.
- Probe parity, relay port versus nginx direct: plain HTTP, garbage bytes, partial ClientHello, silent connect, TLS alert, HTTP/2 preface and SNI variants. 0 differences.
- Upgrade, rollback and uninstall by `--name`: clean. Uninstall leaves firewall rules, as documented.
- `dotvpn-core` and `relay-test` unaffected. `/root/install.sh` on the host is core's (dated Oct 28) and was not touched. Test files and containers removed afterwards.

Not verified live: a relay-path session from a real client through the lowkey install (lab `suites/deploy/lowkey_test.go` covers it).
