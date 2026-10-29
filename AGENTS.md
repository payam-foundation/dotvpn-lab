# dotvpn-lab

Censorship lab and black-box tests. Module `github.com/payam-foundation/dotvpn-lab` (formerly `dotvpn-e2e`). Builds and runs core, relay and client against documented censor profiles. Mechanism checks only: a green matrix never means "works in Iran" or "works in Russia".

Needs the six repos side by side. `replace` points at `../dotvpn-wire` and `../dotvpn-client`; core and relay are built as binaries by `harness.Main` (called from each suite's `TestMain`). Core is built with `-tags e2e` (loopback egress) plus an untagged build that proves the SSRF guard.

## Commands

```sh
go build ./... && go vet ./...
go test -race -count=1 ./...        # about a minute; -short skips Snowflake/WebRTC
make lab                            # packet-level suites, -tags lab, Linux and root only
make lab-docker PKGS="./suites/netns ./suites/leak"   # same, from a Mac
make matrix && make report          # profile x carrier matrix, diff against profiles/baseline.json
```

## Invariants

- Every profile rule carries `id`, `source`, `confidence` and cites a row of `docs/lab/documented-behaviours.md`. No source, no rule.
- Anything needing root, netns, nft or tc is gated with `//go:build linux && lab`. `go-nfqueue` is imported only from those files and never enters a released binary.
- Lab images are never pushed to a public registry.
- `LAB_UPDATE=1` rewrites baselines; review the diff.

## Shared rules

- Static builds: `CGO_ENABLED=0`, `-trimpath`. Docker base images pinned by digest, distroless, non-root.
- Secrets never go in the repo, unit files, env files or CI. Keys are written 0600/0640.
- Go style: stdlib first, no new dependency for what a few lines do, no placeholder code. Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and the upgrade path.
- Each repo is its own git repo and Go module. Sibling repos live next to this one; do not import across core, relay and client. Anything two of them must agree on goes in `dotvpn-wire`.

## Docs

`docs/architecture.md`, `docs/REPORT.md` (security gate, needs-validation and not-covered lists), `docs/hetzner-test-report.md`, `docs/lab/`, `docs/adr/README.md` (index of every repo's ADRs).
