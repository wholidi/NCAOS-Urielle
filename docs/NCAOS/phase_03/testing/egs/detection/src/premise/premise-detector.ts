/**
 * @ncaos/detection — Premise Detection Module
 *
 * Layer 2: Premise Consistency
 * Validates that the request's claimed context matches structural reality.
 * Legitimacy is revoked before decision authority is granted.
 *
 * Phase 03 upgrades:
 * - Workflow-scoped premise registry (premises are tracked per workflow)
 * - Premise versioning — contract version mismatches are flagged
 * - Weighted premises — critical premises carry higher violation weight
 * - Temporal validity — premises can have expiry windows
 * - Full MTTD instrumentation
 *
 * Design invariants:
 * - Premise evaluation never accesses internal model state
 * - Unverifiable claims are treated as violations, not as neutral
 * - Registry is scoped per workflow — isolation between workflows
 */

import { LAYER_DETECTION_MODE } from '@ncaos/core';
import type { ContainmentLayer, ImpactScope, Severity } from '@ncaos/core';
import { startTimer } from '../mttd/tracker.js';

// ─────────────────────────────────────────────────────────
// PREMISE TYPES
// ─────────────────────────────────────────────────────────

export type PremiseWeight = 'critical' | 'standard' | 'informational';

export interface PremiseDefinition {
  id: string;
  label: string;
  weight: PremiseWeight;
  expiryMs?: number;            // Optional: premise expires after N ms
}

export interface ValidatedPremise {
  id: string;
  validatedAt: number;          // performance.now() timestamp
  expiryMs?: number;
}

export interface PremiseDetectionInput {
  workflowId: string;
  contractVersion: string;
  expectedContractVersion: string;
  claimedPremiseIds: string[];
  validatedPremises: ValidatedPremise[];
  premiseDefinitions: PremiseDefinition[];
}

export interface PremiseViolation {
  premiseId: string;
  reason: 'unvalidated' | 'expired' | 'unknown_claim';
  weight: PremiseWeight;
}

export interface PremiseDetectionResult {
  triggered: boolean;
  layer: ContainmentLayer;
  type: string;
  severity: Severity;
  scope: ImpactScope;
  detectionMode: string;
  violations: PremiseViolation[];
  contractVersionMismatch: boolean;
  mismatchRatio: number;         // 0.0–1.0
  criticalViolations: number;
  mttdMs: number;
  note: string;
  detectedAt: string;
}

// ─────────────────────────────────────────────────────────
// PREMISE REGISTRY
// ─────────────────────────────────────────────────────────

/**
 * PremiseRegistry — maintains validated premises per workflow.
 * Scoped to a workflow ID; cross-workflow contamination is prevented.
 *
 * Phase 04: Replace in-memory Map with Redis for distributed deployments.
 */
export class PremiseRegistry {
  private readonly store: Map<string, Map<string, ValidatedPremise>> = new Map();

  /**
   * register() — records a validated premise for a workflow.
   */
  register(workflowId: string, premise: ValidatedPremise): void {
    if (!this.store.has(workflowId)) {
      this.store.set(workflowId, new Map());
    }
    this.store.get(workflowId)!.set(premise.id, premise);
  }

  /**
   * isValid() — checks if a premise is still valid for a workflow.
   * Considers expiry windows if defined.
   */
  isValid(workflowId: string, premiseId: string): boolean {
    const workflow = this.store.get(workflowId);
    if (!workflow) return false;
    const premise = workflow.get(premiseId);
    if (!premise) return false;
    if (premise.expiryMs) {
      const age = performance.now() - premise.validatedAt;
      if (age > premise.expiryMs) return false;
    }
    return true;
  }

  /**
   * clear() — removes all premises for a workflow (e.g. on workflow completion).
   */
  clear(workflowId: string): void {
    this.store.delete(workflowId);
  }

  workflowCount(): number {
    return this.store.size;
  }
}

// ─────────────────────────────────────────────────────────
// PREMISE DETECTOR
// ─────────────────────────────────────────────────────────

export class PremiseDetector {
  private readonly registry: PremiseRegistry;

  constructor(registry?: PremiseRegistry) {
    this.registry = registry ?? new PremiseRegistry();
  }

  get premiseRegistry(): PremiseRegistry {
    return this.registry;
  }

  /**
   * detect() — validates claimed premises against the registry.
   * Returns a PremiseDetectionResult with violation breakdown.
   */
  detect(input: PremiseDetectionInput): PremiseDetectionResult {
    const stop = startTimer();

    const violations: PremiseViolation[] = [];

    // Contract version check
    const contractVersionMismatch =
      input.contractVersion !== input.expectedContractVersion;

    // Build lookup for registered validated premises
    const registeredIds = new Set(
      input.validatedPremises
        .filter(vp => this.registry.isValid(input.workflowId, vp.id))
        .map(vp => vp.id),
    );

    // Also accept directly provided validatedPremises (Phase 02 compatibility)
    for (const vp of input.validatedPremises) {
      this.registry.register(input.workflowId, vp);
    }

    // Check each claimed premise
    for (const claimedId of input.claimedPremiseIds) {
      const def = input.premiseDefinitions.find(d => d.id === claimedId);

      if (!def) {
        // Claimed a premise the system has no definition for
        violations.push({
          premiseId: claimedId,
          reason: 'unknown_claim',
          weight: 'standard',
        });
        continue;
      }

      const isValidated = input.validatedPremises.some(vp => vp.id === claimedId);
      const isExpired = isValidated &&
        !this.registry.isValid(input.workflowId, claimedId);

      if (isExpired) {
        violations.push({ premiseId: claimedId, reason: 'expired', weight: def.weight });
      } else if (!isValidated) {
        violations.push({ premiseId: claimedId, reason: 'unvalidated', weight: def.weight });
      }
    }

    const totalClaimed = input.claimedPremiseIds.length;
    const mismatchRatio = totalClaimed > 0 ? violations.length / totalClaimed : 0;
    const criticalViolations = violations.filter(v => v.weight === 'critical').length;

    const triggered = violations.length > 0 || contractVersionMismatch;
    const severity = this._computeSeverity(mismatchRatio, criticalViolations);
    const scope: ImpactScope = severity === 'high' ? 'flow' : 'req';

    const mttdMs = stop();

    return {
      triggered,
      layer: 'premise',
      type: triggered ? 'PREMISE_MISMATCH' : 'PREMISE_VALIDATED',
      severity,
      scope,
      detectionMode: LAYER_DETECTION_MODE['premise'],
      violations,
      contractVersionMismatch,
      mismatchRatio,
      criticalViolations,
      mttdMs,
      note: triggered
        ? `${violations.length} premise violation(s) detected. Legitimacy revoked.`
        : 'All premises validated. Legitimacy confirmed.',
      detectedAt: new Date().toISOString(),
    };
  }

  private _computeSeverity(ratio: number, criticalCount: number): Severity {
    if (criticalCount > 0 || ratio >= 0.7) return 'high';
    if (ratio >= 0.3) return 'med';
    return 'low';
  }
}
