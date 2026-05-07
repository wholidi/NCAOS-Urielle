/**
 * @ncaos/shell — Enforcer Module
 *
 * The Enforcer is the third and final stage of the observe → judge → enforce loop.
 * It receives a JudgmentResult from the Judge and:
 *   1. Produces a Verdict (PASS / DOWNGRADE / BLOCK / FAIL_SAFE)
 *   2. Updates the live GovState for the Admin Terminal
 *   3. Emits the Verdict + GovState for the API WebSocket layer
 *
 * Design invariants:
 * - Enforcer is the ONLY module that produces Verdicts
 * - FAIL_SAFE is triggered if Enforcer itself throws — never silently passes
 * - GovState is rebuilt from scratch on every request — no mutable accumulation
 * - Enforcer emits events; it does not push to the API directly
 */

import { EventEmitter } from 'node:events';
import {
  enforce,
  failSafeVerdict,
  computeContainmentMetrics,
  scoreToContinuityState,
  generateRequestId,
  nowIso,
  DEFAULT_POLICY,
} from '@ncaos/core';
import type {
  GovEvent,
  GovState,
  PolicyProfile,
  TenantContext,
  Verdict,
} from '@ncaos/core';
import type { JudgmentResult } from '../judge/judge.js';

// ─────────────────────────────────────────────────────────
// ENFORCER EVENTS
// ─────────────────────────────────────────────────────────

export interface EnforcerOutput {
  verdict: Verdict;
  event: GovEvent | null;       // null on PASS (no containment event)
  state: GovState;
}

// ─────────────────────────────────────────────────────────
// ENFORCER CLASS
// ─────────────────────────────────────────────────────────

export class Enforcer extends EventEmitter {
  private readonly policy: PolicyProfile;
  private readonly tenant: TenantContext;
  private lastState: GovState | null = null;

  constructor(tenant: TenantContext, policy: PolicyProfile = DEFAULT_POLICY) {
    super();
    this.tenant = tenant;
    this.policy = policy;
  }

  /**
   * enforce() — converts a JudgmentResult into a Verdict + GovState.
   *
   * Wraps the core enforce() function with:
   * - GovEvent construction (for non-PASS verdicts)
   * - GovState reconstruction
   * - FAIL_SAFE fallback on any internal error
   *
   * Emits 'enforcer:output' with the EnforcerOutput.
   * Returns the EnforcerOutput synchronously.
   */
  enforce(judgment: JudgmentResult): EnforcerOutput {
    try {
      return this._enforce(judgment);
    } catch (err) {
      // FAIL_SAFE: any internal error → unconditional block
      console.error('[Enforcer] Internal error — FAIL_SAFE triggered:', err);
      const verdict = failSafeVerdict(
        judgment.requestId as `REQ-${string}`,
        this.policy.profileId,
      );
      const state = this._buildFailSafeState();
      const output: EnforcerOutput = { verdict, event: null, state };
      this.emit('enforcer:output', output);
      return output;
    }
  }

  get currentState(): GovState | null {
    return this.lastState;
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private _enforce(judgment: JudgmentResult): EnforcerOutput {
    // Build a minimal GovEvent for the core enforce() function
    const govEvent = this._buildGovEvent(judgment);

    // Core enforce: policy × severity → verdict action
    const verdict = enforce(govEvent, this.policy);

    // Build containment event (only for non-PASS verdicts)
    const event: GovEvent | null = verdict.action !== 'PASS' ? govEvent : null;

    // Rebuild GovState from judgment + verdict
    const state = this._buildGovState(judgment, verdict);
    this.lastState = state;

    const output: EnforcerOutput = { verdict, event, state };
    this.emit('enforcer:output', output);
    return output;
  }

  private _buildGovEvent(j: JudgmentResult): GovEvent {
    const dominantLayer = j.dominantLayer ?? 'gate';
    return {
      requestId: j.requestId as `REQ-${string}`,
      evidenceHandle: j.evidenceHandle as `EVD-${string}`,
      tenant: this.tenant,
      type: j.type,
      layer: dominantLayer,
      scope: j.scope,
      severity: j.severity,
      detectionMode: j.layers.find((l) => l.layer === dominantLayer)?.detectionMode
        ?? 'Real-time Gate Enforcement',
      integrity: j.integrity as GovEvent['integrity'],
      authority: j.authority as GovEvent['authority'],
      routing: j.routing ?? {
        hint: 'SOC / Security Queue',
        recommendedAction: 'Review and validate.',
      },
      detectedAt: j.judgedAt,
      mttdMs: j.totalMttdMs,
    };
  }

  private _buildGovState(j: JudgmentResult, verdict: Verdict): GovState {
    const metrics = computeContainmentMetrics(
      j.integrity as { level: import('@ncaos/core').IntegrityLevel; score: number },
    );

    const continuityScore = 85; // Phase 3: derive from continuity layer result
    const continuityState = scoreToContinuityState(continuityScore, this.policy);

    const operationalMode = (() => {
      if (verdict.action === 'BLOCK' || verdict.action === 'FAIL_SAFE') return 'CONTAINMENT' as const;
      if (verdict.action === 'DOWNGRADE') return 'LIMITED' as const;
      return 'NORMAL' as const;
    })();

    const systemStatus = (() => {
      if (verdict.action === 'FAIL_SAFE') return 'FAIL_SAFE' as const;
      if (operationalMode === 'CONTAINMENT') return 'ENFORCING (STRICT)' as const;
      if (operationalMode === 'LIMITED') return 'ENFORCING (LIMITED)' as const;
      return 'ENFORCING' as const;
    })();

    return {
      tenant: this.tenant,
      systemStatus,
      operationalMode,
      shellIntegrity: true,
      failSafeEnabled: true,
      integrity: j.integrity as GovState['integrity'],
      authority: j.authority as GovState['authority'],
      rawExposurePct: metrics.rawExposurePct,
      governedOutputPct: metrics.governedOutputPct,
      coreIsolationPct: metrics.coreIsolationPct,
      contextDriftPressurePct: metrics.contextDriftPressurePct,
      latencyOverheadMs: metrics.latencyOverheadMs,
      updateState: continuityState,
      continuityScore,
      changeWindowActive: false,
      equivalenceTests: { passed: 12, total: 12 }, // Phase 3: real values
      activeEvent: j.triggered
        ? `${j.type} / ${j.severity.toUpperCase()}`
        : undefined,
      lastRouting: j.routing?.hint,
      blockedLayer: j.dominantLayer ?? undefined,
      updatedAt: nowIso(),
    };
  }

  private _buildFailSafeState(): GovState {
    return {
      tenant: this.tenant,
      systemStatus: 'FAIL_SAFE',
      operationalMode: 'CONTAINMENT',
      shellIntegrity: false,
      failSafeEnabled: true,
      integrity: { level: 'Critical', score: 0 },
      authority: { authority: 'invalid', score: 0 },
      rawExposurePct: 100,
      governedOutputPct: 0,
      coreIsolationPct: 0,
      contextDriftPressurePct: 100,
      latencyOverheadMs: 0,
      updateState: 'UNSTABLE',
      continuityScore: 0,
      changeWindowActive: false,
      equivalenceTests: { passed: 0, total: 0 },
      activeEvent: 'FAIL_SAFE / CRITICAL',
      updatedAt: nowIso(),
    };
  }
}
