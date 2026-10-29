# ADR-010: Split into core, relay, client and a shared wire library

Status: accepted. Supersedes ADR-002.

## Context

One binary held every role, so a relay host in a restricted country shipped client and admin code, and a seized relay exposed the whole attack surface. One `go.mod` also coupled dependencies of unrelated roles.

## Decision

Five modules, separate repos:

- `dotvpn-wire`: library only. Frame codec, tokens, handshake, mimic, DNS carrier, `Endpoint`/`Pin`, `Dialer`/`Listener`.
- `dotvpn-core`: node, control, admin, reverse listener. Binary `dotvpn-core`.
- `dotvpn-relay`: restricted-country hop. Binary `dotvpn-relay`, no client or admin code.
- `dotvpn-client`: library, `dotvpn` CLI, TUN. Linux, macOS, Windows.
- `dotvpn-lab`: black-box tests and the censorship lab that build and run the others (renamed from `dotvpn-e2e`; the shared docs repo `dotvpn-docs` was dissolved, each repo now keeps its own `docs/`).

Each repo has its own CI, release, signature and rollback path. Cost: more release surface and coordination, accepted because the relay must be minimal and independently replaceable. Coordination is held down by ADR-011.

## Rejected

Keeping one binary with build tags: the relay still shares a repo, deps and release key with admin code.
Three repos with no wire library: token format and framing drift.
