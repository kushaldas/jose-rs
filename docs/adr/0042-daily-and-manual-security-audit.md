# ADR 0042 — Run dependency security audits daily and on demand

## Date

2026-11-11

## Status

Accepted

## Context

New advisories can affect pinned dependencies without a repository change.
The security audit currently runs weekly and cannot be started manually from
GitHub Actions.

## Decision

Schedule the Security Audit workflow daily at 06:00 UTC and enable
`workflow_dispatch` so maintainers can start it from GitHub Actions. Retain
the existing push and pull-request triggers.

## Security boundaries

Every trigger runs the existing `cargo audit --deny warnings` job with the
same advisory configuration. This changes no dependency or advisory exception.

## Consequences

Scheduled audits consume runner time daily instead of weekly. Maintainers can
request a fresh audit on demand once the workflow is on the default branch.
Scheduled runs depend on GitHub Actions scheduling and may start later than
06:00 UTC.
