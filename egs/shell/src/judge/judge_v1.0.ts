/**
 * @ncaos/shell — Judge Module
 *
 * The Judge is the second stage of the observe → judge → enforce loop.
 * It receives an ObservedRequest from the Observer, runs it through all
 * four detection layers, and returns a JudgmentResult for the Enforcer.
 *
 * Design invariants:
 * - Judge is stateless — it holds no memory between requests
 * - All four layers run independently; worst severity wins
 * - Judge never accesses internal model state
 * - MTTD is measured per layer and in aggregate
 */

import {
  detectGate,
  detectPremise,
  detectAuthority,
  detectContinuity,
  computeIntegrity,
  computeAuthority,
  computeRouting,
  DEFAULT_POLICY,
} from '@ncaos/core';
import type {
  ContainmentLayer,
  DetectionMode,
  GovEvent,
  ImpactScope,
  PolicyProfile,
  RoutingDecision,
  Severity,
} from '@ncaos/core';
import type { ObservedRequest } from '../observer/observer.js';
import type { DetectionResult } from '@ncaos/core';

// ─────────────────────────────────────────────────────────
// JUDGMENT RESULT
// ─────────────────────────────────────────────────────────

export interface LayerResult {
  layer: ContainmentLayer;
  triggered: boolean;
  severity: Severity;
  scope: ImpactScope;
  type: string;
  detectionMode: DetectionMode;
  mttdMs: number;
  note: string;
}

export interface JudgmentResult {
  requestId: string;
  evidenceHandle: string;

  // Aggregate verdict inputs
  triggered: boolean;               // Any layer triggered
  dominantLayer: ContainmentLayer | null;
  severity: Severity;               // Worst across all layers
  scope: ImpactScope;               // Widest across all layers
  type: string;                     // Type from dominant layer

  // Per-layer breakdown
  layers: LayerResult[];

  // Computed signals (policy-driven)
  integrity: { level: string; score: number };
  authority: { authority: string; score: number };
  routing: RoutingDecision | null;

  // Timing
  totalMttdMs: number;
  judgedAt: string;
}

// ─────────────────────────────────────────────────────────
// SEVERITY ORDERING
// ─────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<Severity, number> = { low: 1, med: 2, high: 3 };
const SCOPE_RANK: Record<ImpactScope, number> = { req: 1, flow: 2, sys: 3 };

function worseSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function widerScope(a: ImpactScope, b: ImpactScope): ImpactScope {
  return SCOPE_RANK[a] >= SCOPE_RANK[b] ? a : b;
}

// ─────────────────────────────────────────────────────────
// JUDGE CLASS
// ─────────────────────────────────────────────────────────

export class Judge {
  private readonly policy: PolicyProfile;

  constructor(policy: PolicyProfile = DEFAULT_POLICY) {
    this.policy = policy;
  }

  /**
   * judge() — runs an ObservedRequest through all four detection layers.
   * Returns a JudgmentResult for the Enforcer to act upon.
   *
   * All four layers always run — no short-circuit.
   * This ensures all triggered layers are recorded for audit purposes.
   */
  judge(req: ObservedRequest): JudgmentResult {
    const start = Date.now();

    // ── Run all four detection layers ────────────────────────────────────────

    const gateResult = detectGate({
      sourceId: req.sourceId,
      inputHash: req.inputHash,
      flags: req.inputFlags,
    });

    const premiseResult = detectPremise({
      workflowId: req.workflowId ?? 'WF-UNSET',
      contractVersion: req.contractVersion,
      claimedPremises: req.claimedPremises,
      validatedPremises: req.validatedPremises,
    });

    const authorityResult = detectAuthority({
      requestedAuthority: req.requestedAuthority,
      policyGrantedAuthority: req.policyGrantedAuthority,
      overrideAttempted: req.overrideAttempted,
    });

    const continuityResult = req.updateId
      ? detectContinuity({
          updateId: req.updateId,
          equivalenceTestResults: req.equivalenceTestResults ?? [],
          continuityScore: req.continuityScore ?? 100,
          stableThreshold: this.policy.continuityThresholds.stable,
        })
      : null;

    // ── Collect layer results ────────────────────────────────────────────────

    const rawLayers: Array<DetectionResult & { layer: ContainmentLayer }> = [
      { ...gateResult, layer: 'gate' as ContainmentLayer },
      { ...premiseResult, layer: 'premise' as ContainmentLayer },
      { ...authorityResult, layer: 'authority' as ContainmentLayer },
      ...(continuityResult ? [{ ...continuityResult, layer: 'continuity' as ContainmentLayer }] : []),
    ];

    const layers: LayerResult[] = rawLayers.map((r) => ({
      layer: r.layer,
      triggered: r.triggered,
      severity: r.severity,
      scope: r.scope,
      type: r.type,
      detectionMode: r.detectionMode,
      mttdMs: r.mttdMs,
      note: r.note,
    }));

    // ── Aggregate across triggered layers ────────────────────────────────────

    const triggeredLayers = layers.filter((l) => l.triggered);
    const anyTriggered = triggeredLayers.length > 0;

    let dominantLayer: ContainmentLayer | null = null;
    let aggSeverity: Severity = 'low';
    let aggScope: ImpactScope = 'req';
    let aggType = 'NO_EVENT';

    if (anyTriggered) {
      // Dominant = layer with worst severity (continuity wins ties — always sys)
      const dominant = triggeredLayers.reduce((prev, curr) =>
        SEVERITY_RANK[curr.severity] > SEVERITY_RANK[prev.severity] ? curr : prev,
      );
      dominantLayer = dominant.layer;
      aggType = dominant.type;

      // Aggregate severity and scope across ALL triggered layers
      for (const l of triggeredLayers) {
        aggSeverity = worseSeverity(aggSeverity, l.severity);
        aggScope = widerScope(aggScope, l.scope);
      }
    }

    // ── Compute integrity + authority from aggregate severity ─────────────────

    const integrity = computeIntegrity(anyTriggered ? aggSeverity : null, this.policy);
    const authority = computeAuthority(anyTriggered ? aggSeverity : null, this.policy);
    const routing = anyTriggered && dominantLayer
      ? computeRouting(dominantLayer, aggScope)
      : null;

    const totalMttdMs = Date.now() - start;

    // ── Check MTTD SLA violations ─────────────────────────────────────────────
    // Log SLA breaches — Phase 6 will add alerting
    for (const l of layers) {
      const sla = this.policy.mttdSlaMs[l.layer];
      if (l.mttdMs > sla) {
        console.warn(
          `[Judge] MTTD SLA breach: layer=${l.layer} mttd=${l.mttdMs}ms sla=${sla}ms`,
        );
      }
    }

    return {
      requestId: req.requestId,
      evidenceHandle: req.evidenceHandle,
      triggered: anyTriggered,
      dominantLayer,
      severity: aggSeverity,
      scope: aggScope,
      type: aggType,
      layers,
      integrity,
      authority,
      routing,
      totalMttdMs,
      judgedAt: nowIso(),
    };
  }
}

function nowIso(): string {
  return new Date().toISOString();
}
