# ADR-008: v1.0-rc Scope and Remaining Hardening Items

**Date:** 2026-05-16
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

Phase 06 completed the STRIDE threat model, AI/ML threat model, JWT/Rate
limiting hardening, ISO 42001 mapping, pen testing, and chaos validation.

Four pen test items were DEFERRED to Phase 07:
- PT-003 (S-003): WebSocket stream unauthenticated
- PT-006 (T-003): String sanitization in ProcessRequestSchema
- PT-009 (I-001): Stack trace stripping in production
- PT-010 (I-003): /v1/mttd admin-role restriction

One item was PARTIAL:
- PT-007 (D-001): Rate limiter functional in unit tests but PowerShell
  loop too slow to hit burst threshold in manual test. RateLimiter unit
  tests (8/8 PASS) confirm correct behavior.

## Decision — v1.0-rc Scope

The v1.0-rc tag includes Phases 01–07 as a complete, demonstrable system.
The following items are MUST for any production deployment but are not
blockers for the stakeholder demo and pilot proposal:

### MUST for production (6 items, ~4 days effort)
1. WebSocket authentication (S-003) — 1 day
2. Stack trace stripping production mode (I-001) — 0.5 day
3. HMAC-signed evidence handles (R-001) — 1 day
4. String sanitization ProcessRequestSchema (T-003) — 0.5 day
5. activatedBy bound to JWT sub (R-002) — 0.5 day
6. /v1/mttd restricted to admin role (I-003) — 0.5 day

### SHOULD for production (5 items, ~7 days effort)
1. TimescaleDB EventStore persistence
2. Redis TenantDetectorRegistry (multi-node)
3. RS256 JWT key rotation
4. GitHub Pages demo deployment
5. ADR documentation complete

### Why tag v1.0-rc now

The EGS system is functionally complete and demonstrable:
- 229+ automated tests passing across 7 packages
- 11 pen tests (6 PASS, 1 PARTIAL, 4 DEFERRED with documented rationale)
- ISO 42001 coverage ≥ 70% (8 IMPLEMENTED controls)
- MTTD SLA baseline established (p99 ≤ 1ms for all layers in test env)
- AuditSignal interface defined and usable by Urielle
- React Admin Terminal running with live data

The deferred items are security hardening improvements, not functional gaps.
The architecture is sound. The v1.0-rc tag communicates this honestly.

## Consequences

1. Stakeholder demo (Phase 07) runs against the current v1.0-rc build.
2. Production deployment requires MUST items before go-live.
3. Pilot Tier 1 (Observe mode) can proceed with v1.0-rc as-is.
4. Pilot Tier 2 and Tier 3 require the MUST items completed.
5. The STRIDE threat model and all deferred items are documented in
   ADR-007 and the Phase 06 test report — no hidden technical debt.
