# ADR-016: Censorship lab architecture and test-only dependency

Status: accepted

(The lab plan called this ADR-015; that number was taken by relay operational exposure.)

## Context

`dotvpn-lab` (formerly `dotvpn-e2e`) started as black-box tests with one TLS middlebox. We cannot test inside Iran or Russia, so we want a repeatable lab that models reported censor behaviour (`docs/lab/documented-behaviours.md`) and shows which carriers survive. The lab proves mechanisms, not outcomes.

## Decision

1. Same repo and module (`dotvpn-lab`), layered: `internal/censor` (profile, engine, DPI parsers, userspace proxy), `internal/netlab` and the `*_linux.go` backends (netns, nft, tc netem, nfqueue), `internal/report`, `suites/*`.
2. Profiles are JSON data. Every rule carries `id`, `source`, `confidence` (`observed`, `reported`, `derived`, `assumed`); `Validate` rejects a rule without them. Profiles are dated models, never "Iran".
3. Two enforcement backends share one engine. The userspace proxy is portable (any OS, default `go test`). The Linux backend is gated with `//go:build linux && lab` and needs root.
4. Packet-level backend: network namespaces (`inside`, `border`, `outside`) joined by veth; `nftables` for static rules, `tc netem` for link impairment, `NFQUEUE` for stateful verdicts (QUIC Initial SNI, entropy, residual blocks). The userspace TPROXY-style fallback stays available if a kernel lacks NFQUEUE.
5. Dependency: `github.com/florianl/go-nfqueue/v2` (MIT, pure Go, netlink only), imported only from `_linux.go` files under the `lab` tag. It never enters a released binary. Everything else is stdlib (`crypto/hkdf`, `crypto/aes`, `crypto/cipher` decrypt QUIC Initial packets).

## Spike result (2026-10-28)

Docker Desktop (kernel 7.0.12-linuxkit, arm64), container with only `--cap-add NET_ADMIN --cap-add SYS_ADMIN`, no `--privileged`:

- `ip netns`, veth pairs and moving links between namespaces: work.
- `nft` tables, forward hooks and `queue num N` rules: work.
- `tc qdisc ... netem delay loss`: works.
- `go-nfqueue` cross-built `CGO_ENABLED=0`: received queued UDP packets in a namespace and applied accept and drop verdicts (4 packets sent, 3 seen, the dropped one never reached the app).
- No `modprobe` and no `/lib/modules` in the container: kernel features must be built in or preloaded on the host. They were.

Not yet verified: the `ubuntu-latest` GitHub runner. The CI job installs `nftables` and `iproute2` and runs under sudo; if NFQUEUE is missing there, the netns suites skip with a clear reason and the userspace matrix still gates.

## Consequences

- Lab results never say "works in <country>". Reports carry a banner and a confidence column.
- A new Linux-only dependency exists in a test module; it must stay out of core, relay, client and wire.
- Lab images are never pushed to a public registry.
