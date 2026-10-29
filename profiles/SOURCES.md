# Profile sources

Every rule in these profiles carries `id`, `source` and `confidence`. The ids index rows of `docs/lab/documented-behaviours.md`, which holds the full reading notes. `Validate` refuses a rule without a source or with an unknown confidence.

Profiles are dated models of reported behaviour, never "Iran" or "Russia". Lab placements use documentation address ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 198.18.0.0/15) as stand-ins for real prefixes. Lab host names (`node.lab.example`, `cdn.lab.example`) stand for blocklisted names.

| Profile | Rows encoded | Not encoded yet (and why) |
| --- | --- | --- |
| `baseline-pass` | none, control | n/a |
| `iran-2026-10` | IR-6, IR-7 | IR-2..IR-5 are ICMP-only (netns phase); IR-3 volume trigger needs packet counters |
| `iran-allowlist` | IR-A1, IR-A2 (assumed) | n/a |
| `iran-partition` | IR-1 | n/a |
| `russia-2026-10` | RU-IP-1, RU-TCP-1, RU-QUIC-1 (with RU-QUIC-2 residual), RU-DNS-1 | RU-QUIC-3 (historic 2022), RU-IP-2 (trigger sequence unknown), RU-TLS-1 (fingerprint list unknown; waits for Phase 5), RU-DNS-2 (TTL tricks need packet level) |
| `russia-mobile-whitelist` | RU-WL-1 mechanism | real allowlists |
| `china-reference` | CN-ENT-1 | active probing (CN-LEAK-1 is architecture only) |

Review date per profile is in its `reviewed` field. Re-read the sources before trusting a profile older than a few weeks.
