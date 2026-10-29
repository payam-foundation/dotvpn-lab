# ADR-002: Single binary with role subcommands

Status: superseded by ADR-010

## Context

`dotvpn allinone|control|node|relay|client|proxy|init|token|doctor`.

## Decision

One artifact to build, sign and install. Any role combination can share a process (`allinone`), and moving a role to its own host is a config change, not a new install.

## Rejected

One binary per role: more release surface, more install paths, nothing gained.
