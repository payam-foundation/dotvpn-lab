# ADR index

Each decision record lives in the repo that owns the decision. Paths are relative to the workspace root (the six repos side by side).

| ADR | Title | Status | Location |
| --- | --- | --- | --- |
| 001 | Go | accepted | `dotvpn-lab/docs/adr/001-go.md` |
| 002 | Single binary with role subcommands | superseded by 010 | `dotvpn-lab/docs/adr/002-single-binary.md` |
| 003 | Ed25519 JWT with offline verification | accepted | `dotvpn-wire/docs/adr/003-ed25519-jwt.md` |
| 004 | CONNECT for direct, WebSocket + smux for CDN | accepted | `dotvpn-wire/docs/adr/004-connect-direct-websocket-cdn.md` |
| 005 | Relay as L4 passthrough | superseded by 012, 013 | `dotvpn-lab/docs/adr/005-relay-as-l4-passthrough.md` |
| 006 | SQLite default, Postgres behind a store seam | accepted | `dotvpn-core/docs/adr/006-sqlite-default.md` |
| 007 | Own infrastructure for Snowflake and WebTunnel | accepted | `dotvpn-wire/docs/adr/007-own-infra-snowflake-webtunnel.md` |
| 008 | Signed server list and multi-channel discovery | accepted | `dotvpn-wire/docs/adr/008-signed-server-list-discovery.md` |
| 009 | gVisor netstack for the TUN front | accepted | `dotvpn-client/docs/adr/009-gvisor-netstack.md` |
| 010 | Split into core, relay, client and a shared wire library | accepted | `dotvpn-lab/docs/adr/010-repo-split.md` |
| 011 | Wire library versioning and golden vectors | accepted | `dotvpn-wire/docs/adr/011-wire-versioning.md` |
| 012 | Relay enrollment replaces the shared relay key | accepted | `dotvpn-relay/docs/adr/012-relay-enrollment.md` |
| 013 | Reverse-first relay | accepted | `dotvpn-relay/docs/adr/013-reverse-first-relay.md` |
| 014 | Probe-resistance policy | accepted | `dotvpn-relay/docs/adr/014-probe-resistance.md` |
| 015 | Relay operational exposure | accepted | `dotvpn-relay/docs/adr/015-relay-operational-exposure.md` |
| 016 | Censorship lab architecture | accepted | `dotvpn-lab/docs/adr/016-censorship-lab.md` |
| 017 | ECH policy: DoH resolver, `auto`/`require`, GREASE | accepted | `dotvpn-wire/docs/adr/017-ech-policy.md` |
| 018 | UDP over tunnel streams | accepted | `dotvpn-wire/docs/adr/018-udp-over-tunnel-streams.md` |
| 019 | Android shell and gomobile boundary | accepted | `dotvpn-android/docs/adr/019-android-shell.md` |
