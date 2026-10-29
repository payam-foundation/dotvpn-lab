# Censorship lab

`dotvpn-lab` models reported censor behaviour and shows which carriers survive it. Design: ADR-016. Evidence behind every rule: `documented-behaviours.md`.

**Standing disclaimer.** Lab results are mechanism checks. A green matrix never means "works in Iran" or "works in Russia". Censors differ by ISP, region, mobile versus fixed, and week. Validate with in-country testers or OONI-style probes before claiming anything.

## Run it

All commands run in `dotvpn-lab`, with the six repos side by side.

| Goal | Command | Needs |
| --- | --- | --- |
| Userspace suites and matrix (any OS) | `make test` | Go, Docker only for `suites/deploy` |
| Skip Snowflake/WebRTC | `go test -short ./...` | |
| Packet-level suites (netns, nft, netem, NFQUEUE, TUN) | `sudo make lab` | Linux, root, `nftables`, `iproute2`, `iptables` |
| Same, from a Mac | `make lab-docker PKGS="./suites/netns ./suites/leak"` | Docker Desktop |
| Matrix to `out/matrix.json` and `out/matrix.md` | `make matrix` | |
| Diff a matrix against the baseline | `make report` | |
| Remove leftover namespaces after an abort | `sudo make lab-clean` | |

Useful variables: `LAB_OUT=dir` (write JSON results under `dir`), `LAB_UPDATE=1` (rewrite `profiles/baseline.json`, review the diff), `LAB_PERF=1` (enable the throughput suite), `LAB_PREV_DIR` (previous release binaries for the upgrade drill), `LAB_BINS` (prebuilt binaries), `LAB_RUN` (test name filter inside the container).

## What each suite answers

| Suite | Question | Tags |
| --- | --- | --- |
| `suites/functional` | Do carriers, auth, SSRF guard, decoy, reverse relay and replay/probe resistance work with no censor? | none |
| `suites/censor` | Does the fallback ladder move off a blocked carrier, and does the stealth path survive a middlebox? | none |
| `suites/matrix` | Profile x placement x carrier: which verdict (`works`, `degraded`, `fails-fast`, `hangs`)? Diffed against `profiles/baseline.json`. | none |
| `suites/netns` | Same matrix and the Iran ICMP rules, enforced by nft and NFQUEUE in network namespaces. Must agree with the userspace matrix. | `lab` |
| `suites/leak` | With the TUN client and kill switch running, does anything other than the tunnel endpoint leave the client (IPv4, IPv6, non-DNS UDP/STUN, local resolver) when the tunnel or node dies? Linux only. | `lab` |
| `suites/chaos` | Loss, delay, jitter and reorder presets; core restart; relay restart and pool refill; link flap. | `lab` |
| `suites/perf` | Throughput and small-request latency per carrier against `profiles/perf-baseline.json`. Nightly (`LAB_PERF=1`). | `lab` |
| `suites/fingerprint` | JA3/JA4 against Chrome 156, first-packet entropy and classification, decoy ServerHello against stock nginx. | none |
| `suites/deploy` | Real relay and core Docker images: hardened run, upgrade and rollback over preserved volumes, production-build SSRF guard. | Docker |

## Read the matrix

Each row is `profile / placement / carrier`.

- `works`: fetch succeeded promptly. `degraded`: succeeded but slowly (throttle, delay).
- `fails-fast`: connection reset or refused. `hangs`: a `drop` rule; the dial waits for its timeout. A hang is a product risk even when another carrier succeeds, because the ladder pays that timeout first.
- `ladder` cells also record which carrier the ladder landed on.
- The confidence column carries the lowest confidence among the rules that decided the cell. `assumed` means our guess, not a report.
- An expected non-`works` verdict in `baseline.json` carries a reason (for example h3 under the Russian QUIC rule).
- Any change in either direction fails CI. Fixing a failure is a baseline change too: regenerate with `LAB_UPDATE=1`, read the diff, edit reasons by hand, commit.

## Add a profile

1. Add a row to `documented-behaviours.md` first: mechanism, source URL and date, confidence, lab fidelity. No source, no rule.
2. Create `profiles/<name>-<yyyy-mm>.json`. Every rule needs `id` (the row), `source` and `confidence` (`observed`, `reported`, `derived`, `assumed`); `Validate` rejects the profile otherwise. Set `reviewed` to the date you re-read the sources. Use documentation prefixes (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 198.18.0.0/15) as stand-ins for real ones. Use `extends` to layer on another profile and `dpi: "naive"` or `"strict"` for DPI strictness.
3. Rules are first-match. Put L3/L4 and volume rules first, payload rules next, catch-alls last.
4. Add the name to `profileNames` in `suites/matrix/matrix_test.go` (and to the list in `suites/netns/matrix_test.go` if packet level can enforce it), run `make matrix`, review, then `LAB_UPDATE=1`.
5. Add the profile to `profiles/SOURCES.md`, including the rows not encoded and why.
6. Treat thresholds marked `assumed` as parameters to sweep. Report the breaking point, not one pass/fail.

A profile older than a few weeks needs its sources re-read before it is trusted.

## CI

`dotvpn-lab/.github/workflows/ci.yml`:

- `userspace`: userspace suites with `-race`, on every push and PR. Includes the matrix baseline gate.
- `lab-linux`: `ubuntu-latest`, `sudo`, `-tags lab`, serial packages. Uploads `lab-out` (JSON results) and `lab-report` (`matrix.md`, `lab.log`) artifacts, and runs `lab-clean` at the end. If the runner kernel lacks NFQUEUE or netns support, suites skip with a reason in the log; the userspace matrix still gates.
- Nightly (`17 3 * * *`): same jobs with `LAB_PERF=1`, so the perf regression gate runs too. Snowflake runs in every non-`-short` `userspace` job; chaos runs in every `lab-linux` job.
- Cross-repo: wire, core, relay and client CI each have a `lab` job that runs `gh workflow run lab -R payam-foundation/dotvpn-lab -f <repo>_ref=<PR sha>`. It needs an `LAB_DISPATCH_TOKEN` secret (fine-grained, `actions: write` on `dotvpn-lab` only) and does nothing without it. The lab run is not reported back on the PR; read it in the `dotvpn-lab` Actions tab. `repository_dispatch` type `component-changed` with `client_payload.{wire,core,relay,client}_ref` does the same.

## Known limits

- macOS and Windows kill switches are covered only by rule-set unit tests, not by the lab.
- The `ubuntu-latest` runner has not been verified for NFQUEUE yet (ADR-016, spike).
- Fingerprint and perf tolerance bands are provisional until a few nightly runs set the spread.
- Lab links are veth. Real censor paths, mobile networks and residential lines are not modelled.
