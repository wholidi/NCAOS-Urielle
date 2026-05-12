# ADR-006: AuditSignal Schema as the Urielle Interface Contract

**Date:** 2026-05-08
**Status:** Accepted
**Authors:** William (Urielle) / Toru (NCAOS Audit Layer)

---

## Context

The Toru-William discussion following Phase 03 identified that:

> "The depth of audit is largely a function of how well events are defined
>  and structured. The key is not increasing internal visibility, but
>  increasing the structure and quality of the signals themselves."

Phase 04 implemented the sequence interface (`/v1/events/sequence/:id/summary`)
which produced the first behavioral pattern evidence: `patternType=CONTAINED`,
`escalationDetected=True`, `consistencyScore=94` for a DOWNGRADE→BLOCK sequence.

Phase 05 formalizes this into a typed schema — the `AuditSignal` — that defines
the complete interface between the NCAOS EGS boundary layer and the Urielle
audit interpretation layer.

## Decision

The `AuditSignal` schema is the **canonical contract** between NCAOS and Urielle.
It is defined in `@ncaos/audit-signal` and is the ONLY way Urielle accesses
governance evidence. Direct access to `@ncaos/shell`, `@ncaos/detection`, or
`@ncaos/core` by Urielle is forbidden by this ADR.

### Three-Layer Structure

**Core layer (always present):**
The minimum viable signal layer Toru described. Contains:
evidenceHandle, sequenceNumber, layer, severity, action, authority,
integrityScore, detectionMode, routingHint, mttdMs, detectedAt, storedAt,
policyProfileId, partnerId.

These 14 fields are sufficient for meaningful governance evidence without
any internal visibility.

**Sequence layer (present when workflowId provided):**
Enables behavioral pattern analysis:
sequenceId, patternType, escalationDetected, consistencyScore,
eventCount, firstDetectedAt, actionChain, layersInvolved.

This layer implements the "sequence-level interpretation" Toru identified
as the next level beyond event-by-event mapping.

**Enrichment layer (optional):**
Enhances audit depth without breaking the boundary:
identityRef, assetRef, sessionId, serviceComponent, tags.

These are opaque references — Urielle receives them but does not resolve
or access the referenced entities. The boundary is strictly maintained.

### Why Zod

Same rationale as ADR-001: Zod schemas provide runtime validation and
TypeScript types from a single definition. Urielle can call `.parse()` on
API responses and get a validated `AuditSignal` with full type safety.

## Consequences

1. **For NCAOS (EGS):** The API must expose data that can be mapped to
   `AuditSignal`. The `fromEventRecord()` factory function in
   `@ncaos/audit-signal` defines this mapping explicitly.

2. **For Urielle:** All audit findings must be derivable from `AuditSignal`
   fields only. If Urielle needs data not in the schema, the schema must
   be extended — not the access method.

3. **Schema versioning:** The `schemaVersion: '1.0'` field enables Urielle
   to handle future schema changes gracefully. Breaking changes require a
   version bump.

4. **ISO 42001 mapping:** The `ISO42001_CONTROL_MAP` in `audit-signal.ts`
   maps each containment layer to relevant ISO 42001 controls. This is the
   starting point for structured compliance evidence generation.

5. **Future enrichment:** As Toru noted, optional enrichment fields
   (identity, asset, session) can be added to the schema without breaking
   existing Urielle consumers, as long as they remain optional.

## What This Does NOT Cover

- **Urielle audit finding format:** How Urielle represents conclusions
  from AuditSignals is Urielle's internal concern — not defined here.
- **Urielle storage:** Where Urielle persists audit findings is Urielle's
  internal concern.
- **Cross-tenant analysis:** AuditSignals are always scoped to a single
  tenant. Cross-tenant pattern analysis requires explicit authorization.
