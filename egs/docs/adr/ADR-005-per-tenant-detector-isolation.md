# ADR-005: Per-Tenant Detector Isolation

**Date:** 2026-05-03
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

In Phase 02 and Phase 03, all requests shared a single set of detector instances
regardless of tenant. This created two structural problems:

1. **Rule set contamination** — custom gate rules added for one tenant would
   apply to all tenants sharing the same GateDetector instance.

2. **Audit log bleed** — the AuthorityAuditLog held entries for all tenants
   in a single list. A query for tenant A could theoretically return entries
   from tenant B if scoped incorrectly.

3. **MTTD stats conflation** — the DetectionRegistry held rolling stats across
   all tenants. A high-volume tenant could skew SLA breach rates for a
   low-volume tenant sharing the same registry.

## Decision

Phase 04 introduces the `TenantDetectorRegistry` — a factory that creates and
holds one `TenantDetectorSet` per tenant, identified by `PARTNER_ID`.

Each `TenantDetectorSet` contains:
- One `GateDetector` (with a copy of the default rules — mutable per tenant)
- One `PremiseDetector` with its own `PremiseRegistry`
- One `AuthorityDetector` with its own `AuthorityAuditLog`
- One `ContinuityDetector` (independent score history)
- One `DetectionRegistry` (independent MTTD stats per layer)

Instances are created lazily on first request and held in a `Map<partnerId, TenantDetectorSet>`.

## Consequences

**Positive:**
- Tenant isolation is enforced at the detector level, not just at the API level.
- Custom gate rules for a tenant are isolated to that tenant's GateDetector.
- MTTD SLA health checks are meaningful per tenant.
- AuthorityAuditLog entries are structurally separated by tenant.

**Negative / Costs:**
- Memory scales linearly with active tenants. At 1000 tenants with large
  PremiseRegistries, this could be significant. Phase 05 mitigation: evict
  inactive tenant detector sets after a configurable idle period.
- Policy changes require calling `registry.reset(partnerId)` to recreate the
  set with updated SLA thresholds. This is handled by the `PolicyStore`
  `policy:changed` event listener in `server.ts`.

## Phase 05 Upgrade Path

Replace the in-memory `Map` with a Redis-backed store:
- Detector configuration (rule sets, policy thresholds) persisted in Redis
- Instances recreated on API restart from persisted config
- Cross-instance consistency for multi-node deployments

The interface (`registry.get(partnerId)`) remains unchanged — the Redis
implementation is a drop-in replacement.
