# ADR-007: Phase 06 Security Hardening Strategy

**Date:** 2026-05-09
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

Phase 01–05 built a functionally complete EGS with tenant isolation,
detection layers, MTTD instrumentation, React Admin Terminal, and the
formal AuditSignal interface for Urielle.

The STRIDE threat model (15 threats) and AI/ML threat model (adversarial
ML threats) identified three HIGH-risk items requiring Phase 06 action:

1. **S-001 (HIGH):** Unauthenticated X-Partner-ID — any string accepted
2. **T-002 / E-001 (HIGH):** POST /v1/policy unauthenticated — any client can change governance policy
3. **D-001 (HIGH):** No rate limiting on /v1/process — DoS via request flood

## Decisions

### JWT Authentication (fixes S-001, T-002, E-001)

A `verifyJwt()` Fastify preHandler hook validates HS256 Bearer tokens.
In development/test mode (JWT_SECRET undefined), it falls back to the
Phase 02–05 X-Partner-ID header behavior. In production, JWT is mandatory.

JWT payload structure:
```json
{ "sub": "PARTNER_ID", "role": "operator|admin|auditor", "iss": "ncaos-egs", "exp": ... }
```

RBAC role assignments:
- `operator` — POST /v1/process, read-only routes
- `admin` — + POST /v1/policy, GET /v1/detectors (governance config)
- `auditor` — read-only event/audit/sequence routes

**Why manual HS256 over @fastify/jwt:**
Minimal dependencies for Phase 06. Phase 07 upgrade: RS256 with key rotation.

### Rate Limiting (fixes D-001)

Token bucket per PARTNER_ID: 100 req/s, burst 150. Implemented as a
Fastify preHandler on /v1/process. Returns 429 Too Many Requests.

Per-tenant isolation: TENANT_A exhausting its rate limit does not affect
TENANT_B. This is consistent with ADR-005 (per-tenant isolation).

Phase 07: Replace in-memory bucket with Redis for multi-node deployments.

### Chaos Testing (validates ADR-002)

Five chaos scenarios validate the FAIL_SAFE invariant under failure:
- CHAOS-001: Shell kill → must return 503, never pass ungoverned
- CHAOS-002: Rate limit exhaustion → must return 429
- CHAOS-003: Concurrent storm → zero 500 errors
- CHAOS-004: Invalid payload flood → 400 not 500
- CHAOS-005: Policy change during active processing → no stale policy

CHAOS-001 is the most critical — it directly validates ADR-002.

### MTTD SLA Regression Baseline

1000-iteration per-layer MTTD tests establish the performance baseline.
All four layers must meet p99 ≤ SLA (gate: 50ms, premise: 200ms,
authority: 100ms, continuity: 500ms) with breach rate < 1%.

This baseline is used in Phase 07 to detect performance regressions
after code changes.

### ISO 42001 Control Mapping

14 controls from ISO/IEC 42001:2023 mapped to EGS components, evidence
sources, API endpoints, and AuditSignal fields. Status:
- IMPLEMENTED: 8 controls (core detection, scoring, audit trail)
- PARTIAL: 4 controls (audit trail depth, incident response)
- PLANNED: 2 controls (human oversight documentation, training records)

## Consequences

1. **Backward compatibility:** JWT is opt-in via JWT_SECRET env var.
   All existing Phase 01–05 tests continue to pass unchanged.

2. **Test count:** Phase 06 adds ~45 new automated tests across 4 files.

3. **No new API routes:** All Phase 06 changes are middleware and hardening.
   The API surface defined in Phase 04 remains unchanged.

4. **AI/ML threat model:** 8 adversarial ML threats documented. None are
   fully mitigated by the current EGS — they represent the boundary of
   what a governance shell can detect without internal model access.
   This is architecturally correct and documented honestly.
