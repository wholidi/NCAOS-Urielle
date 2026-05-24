# ADR-003: Shell Process Isolation Strategy

**Date:** 2026-04-28
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

ADR-002 established that the EGS must fail SAFE — any shell failure defaults
to BLOCK. This only holds if the shell and the protected core run as separate
processes. If they share a process, an OS-level crash takes both down simultaneously,
and there is no watchdog left to enforce the FAIL_SAFE.

## Decision

The EGS shell (`@ncaos/shell`) runs as a **separate Node.js process** from:
- The protected AI runtime / core
- The API gateway (`@ncaos/api`)

**Phase 2 (current):** `ShellLoop` is an in-process class within the API process.
This is acceptable for development and testing. The Watchdog is also in-process.

**Phase 3 (target):** The ShellLoop is extracted to its own process:

```
┌─────────────────┐     IPC / Unix socket     ┌──────────────────────┐
│   @ncaos/api    │ ◄────────────────────────► │   @ncaos/shell       │
│   Fastify       │                            │   ShellLoop process  │
│   Port 3000     │                            │   Port 3001 (IPC)    │
└─────────────────┘                            └──────────────────────┘
                                                         │
                                              Watchdog (systemd / PM2)
                                              restarts on crash
                                                         │
                                              ┌──────────────────────┐
                                              │  Protected Core      │
                                              │  (AI runtime)        │
                                              └──────────────────────┘
```

During shell restart window:
- API returns `503 GOVERNANCE_UNAVAILABLE`
- Protected core output is blocked at the API level
- No request passes without an active shell verdict

## Watchdog Restart Policy

- Max 3 restarts in a 60-second window
- Exponential backoff: 500ms → 1000ms → 2000ms
- After max restarts: permanent FAIL_SAFE until manual intervention
- Alert emitted on each restart and on permanent FAIL_SAFE

## Consequences

- Phase 2 tests use in-process ShellLoop — acceptable, tests the logic
- Phase 3 requires IPC protocol design (JSON over Unix socket)
- Phase 6 chaos test: kill the shell process, verify API returns 503
- PM2 or systemd config lives in `infra/`

## What This Does NOT Cover

- Network-level isolation (firewall rules, VPC) — infra responsibility
- Container isolation (Docker) — `infra/docker-compose.yml` Phase 3
- Core process hardening — enterprise responsibility per Architecture Guide §5
