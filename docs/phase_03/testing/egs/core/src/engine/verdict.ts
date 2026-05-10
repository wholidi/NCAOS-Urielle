/**
 * @ncaos/core — Verdict Engine (Enforcer)
 *
 * The Enforcer is the final stage of the observe → judge → enforce loop.
 * It takes a GovEvent and a PolicyProfile and produces a Verdict —
 * the structural decision that determines what the external environment receives.
 *
 * Design invariants:
 * - FAIL_SAFE: any error in this module defaults to BLOCK + FAIL_SAFE verdict
 * - Verdicts are deterministic given event + policy
 * - No internal model state is accessed
 */

import type {
  GovEvent,
  PolicyProfile,
  RequestId,
  Verdict,
  VerdictAction,
} from '../types/contracts.js';
import { computeRouting } from './routing.js';

/**
 * Determines the VerdictAction based on event severity and policy govLevel.
 *
 * Policy govLevel controls how aggressively the shell enforces:
 * - CRITICAL_STRICT:    block on ANY severity (low, med, high)
 * - ENTERPRISE_STRICT:  block on med or high; downgrade on low
 * - ENTERPRISE_RELAXED: block on high; downgrade on med; pass on low
 * - PILOT:              downgrade on high; pass otherwise (observe mode)
 */
function resolveAction(
  severity: GovEvent['severity'],
  policy: PolicyProfile,
  blockOnContainment: boolean,
): VerdictAction {
  if (!blockOnContainment) {
    // Observe-and-report mode: never block, only downgrade or pass
    return severity === 'high' ? 'DOWNGRADE' : 'PASS';
  }

  switch (policy.govLevel) {
    case 'CRITICAL_STRICT':
      return 'BLOCK';

    case 'ENTERPRISE_STRICT':
      if (severity === 'high' || severity === 'med') return 'BLOCK';
      return 'DOWNGRADE';

    case 'ENTERPRISE_RELAXED':
      if (severity === 'high') return 'BLOCK';
      if (severity === 'med') return 'DOWNGRADE';
      return 'PASS';

    case 'PILOT':
      if (severity === 'high') return 'DOWNGRADE';
      return 'PASS';
  }
}

/**
 * Enforces a GovEvent against a PolicyProfile and produces a Verdict.
 * This is the primary entry point for the Enforcer module.
 *
 * The verdict is structurally granted — it is based entirely on the
 * governance shell's assessment, never on internal self-reporting.
 */
export function enforce(event: GovEvent, policy: PolicyProfile): Verdict {
  const start = Date.now();

  const action = resolveAction(event.severity, policy, policy.blockOnContainment);

  // Map action to authority
  const authorityForAction = (() => {
    switch (action) {
      case 'PASS': return event.authority.authority;
      case 'DOWNGRADE': return 'reference-only' as const;
      case 'BLOCK': return 'invalid' as const;
      case 'FAIL_SAFE': return 'invalid' as const;
    }
  })();

  const verdict: Verdict = {
    requestId: event.requestId,
    action,
    authority: authorityForAction,
    integrity: event.integrity,
    routing: action !== 'PASS' ? computeRouting(event.layer, event.scope) : undefined,
    policyProfileId: policy.profileId,
    enforcedAt: new Date().toISOString(),
    processingMs: Date.now() - start,
  };

  return verdict;
}

/**
 * Fail-safe verdict — produced when the Enforcer itself encounters an error.
 * Defaults to BLOCK + invalid authority, as per the FAIL_SAFE design invariant.
 * This ensures that an EGS failure cannot result in unmanaged output propagation.
 */
export function failSafeVerdict(requestId: RequestId, policyProfileId: string): Verdict {
  return {
    requestId,
    action: 'FAIL_SAFE',
    authority: 'invalid',
    integrity: { level: 'Critical', score: 0 },
    policyProfileId,
    enforcedAt: new Date().toISOString(),
    processingMs: 0,
  };
}
