# ADR-004: Detection Layer Independence and MTTD SLA Enforcement

**Date:** 2026-04-30
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

Phase 02 implemented the Observer → Judge → Enforcer loop. The Judge called
all four detection functions from `@ncaos/core` in sequence. This was correct
for the prototype but has two structural weaknesses:

1. **Shared implementation space** — all four layers lived in one file
   (`core/src/detection/layers.ts`), making them harder to evolve independently.

2. **No rule configurability** — gate rules were hardcoded flag strings with
   no mechanism for enterprise teams to add custom rules.

3. **No MTTD SLA enforcement** — MTTD was measured but never validated against
   policy thresholds in a structured way.

## Decision

Phase 03 extracts the detection logic into `@ncaos/detection` — a dedicated
package with one module per layer. Each module is independently testable,
independently deployable, and independently configurable.

**Key design decisions:**

### 1. Each detector is a class, not a function

```typescript
// Phase 02 (function)
export function detectGate(input: GateInput): DetectionResult { ... }

// Phase 03 (class)
export class GateDetector {
  constructor(rules?: GateRule[]) { ... }
  detect(input: GateDetectionInput): GateDetectionResult { ... }
}
```

Classes allow detectors to hold configuration (rule sets, registries, audit
logs) without global state. This enables per-tenant detector instances in
Phase 04.

### 2. MTTD is measured inside each detector, not by the caller

Each detector calls `startTimer()` at the top of `detect()` and records
`mttdMs` in the result. The `DetectionRegistry` tracks rolling stats and
breach rates per layer.

This means MTTD measurement is atomic with the detection — it cannot be
accidentally omitted by a caller.

### 3. Rule sets are configurable at construction time

`GateDetector` accepts a `GateRule[]` parameter. Enterprise teams can:
- Start with `DEFAULT_GATE_RULES`
- Add custom rules via `detector.addRule()`
- Phase 04: load rules from DB at startup

### 4. MTTD SLA health check is part of the registry

`DetectionRegistry.isSlaHealthy()` returns false if any layer has a breach
rate > 5%. This feeds into `GET /v1/health` in Phase 04.

## Consequences

- `@ncaos/core` detection functions remain as the simple, typed baseline.
  `@ncaos/detection` wraps them with richer behavior for production.
- `@ncaos/shell` Judge module will be updated in Phase 04 to use
  `@ncaos/detection` detectors instead of `@ncaos/core` functions.
- Per-tenant detector instances require the shell to maintain a
  `Map<PartnerId, DetectorSet>` — Phase 04 task.
- MTTD SLA benchmarks from Phase 03 testing become the performance baseline
  for Phase 06 hardening regression tests.
