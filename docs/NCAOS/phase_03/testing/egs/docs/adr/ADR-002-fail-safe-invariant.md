# ADR-002: Fail-Safe Default-Deny as an Unconditional Invariant

**Date:** 2026-04-26
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

The Architecture Interpretation Guide states:

> "FAIL_SAFE: Confirms the shell defaults to a safe/blocked state upon failure,
> preventing unmanaged output propagation."

This is one of the three core conceptual capabilities of the EGS (alongside
Boundary Governance and Visibility). It must be an unconditional invariant —
not a configurable option that could be accidentally disabled.

## Decision

**The EGS fails SAFE (blocked) by default in all error conditions.**

This is implemented at two levels:

1. **`failSafeVerdict()` in `@ncaos/core/src/engine/verdict.ts`:**
   Any uncaught exception in the Enforcer module calls `failSafeVerdict()`,
   which returns action=`FAIL_SAFE`, authority=`invalid`, integrity.score=0.
   The caller receives a valid `Verdict` object — it never receives an exception
   that could be silently swallowed.

2. **Process isolation (Phase 2, Shell module):**
   The EGS runs as a separate process from the AI runtime. If the EGS process
   crashes, a watchdog restarts it. During the restart window, all requests are
   rejected with a `503 GOVERNANCE_UNAVAILABLE` response.
   The protected core **cannot** serve output without an active governance shell.

## Consequences

- Enterprise teams cannot configure `blockOnContainment: false` and also disable
  the fail-safe. These are independent controls:
  - `blockOnContainment` governs what happens on a **detected** anomaly.
  - The fail-safe governs what happens on a **shell failure**.

- Performance implications: the fail-safe path adds ~0ms overhead (it is the
  no-op branch of normal execution). The process isolation requirement adds
  ~0.5–2ms IPC overhead per request, which must be within MTTD SLA.

- Testing requirement: CI must include a chaos test that kills the shell process
  and verifies that all in-flight requests receive a `503` (not a stale `200`).
  This test is scheduled for Phase 6 (Hardening).
