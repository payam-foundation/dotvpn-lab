# ADR-005: Relay as L4 passthrough

Status: superseded by ADR-012 and ADR-013

## Context

The in-country relay never holds keys.

## Decision

Mode A forwards TCP and preserves TLS end to end, with an optional SNI allowlist, so a seized relay exposes nothing. Mode B forwards control-plane HTTP only. Relays hide node addresses from users and stay reachable under whitelist-style filtering.

## Rejected

TLS-terminating relay: simpler to inspect, but the relay would see plaintext and need certificates.
