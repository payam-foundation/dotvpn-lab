# dotvpn operator guide

Operations live with the code that ships them:

- Server install, upgrade, rollback, Docker: `dotvpn-core/README.md`, `dotvpn-core/deploy/`
- Relay deployment (reverse mode, enrollment): `dotvpn-relay/README.md`
- Client usage, TUN, kill switch, split routing: `dotvpn-client/README.md`
- Android app build, install, always-on VPN: `dotvpn-android/README.md`
- UDP over the tunnel: nodes advertise `udp=1` in the signed server list; port allow-list and per-user flow cap are in `dotvpn-core/README.md` (ADR-018)
- ECH (`ech=auto|require`) and local proxy auth (`listen_auth`): `dotvpn-client/README.md` (ADR-017)
- Release verification (`cosign verify-blob`): each repo README
- Security posture and gaps: `dotvpn-lab/docs/REPORT.md`
