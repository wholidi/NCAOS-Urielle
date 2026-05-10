/**
 * @ncaos/detection — Authority Detection Module
 *
 * Layer 3: Authority Boundary
 * Enforces the output authority state machine.
 * Authority is structurally granted by the shell — never by internal self-reporting.
 *
 * Phase 03 upgrades:
 * - Full authority state machine (decision-ready → reference-only → invalid)
 * - Override attempt classification (escalation vs boundary test vs attack)
 * - Authority grant history per request chain
 * - Audit log entry generation for every authority decision
 * - Full MTTD instrumentation
 *
 * Authority state machine:
 *
 *   DECISION-READY ──(degradation)──► REFERENCE-ONLY ──(degradation)──► INVALID
 *        ▲                                                                   │
 *        └──────────────────── (never) ────────────────────────────────────┘
 *
 * Authority can only be downgraded, never upgraded within a request chain.
 * Override attempts that try to upgrade authority are flagged as HIGH severity.
 */

import { LAYER_DETECTION_MODE } from '@ncaos/core';
import type { ContainmentLayer, ImpactScope, OutputAuthority, Severity } from '@ncaos/core';
import { startTimer } from '../mttd/tracker.js';

// ─────────────────────────────────────────────────────────
// AUTHORITY STATE MACHINE
// ─────────────────────────────────────────────────────────

const AUTHORITY_RANK: Record<OutputAuthority, number> = {
  'decision-ready': 2,
  'reference-only': 1,
  'invalid': 0,
};

export type OverrideClassification =
  | 'none'
  | 'escalation_attempt'       // Tried to gain higher authority than granted
  | 'boundary_test'            // Tried same-level authority when downgraded
  | 'invalid_state_claim';     // Claimed authority when already invalid

export interface AuthorityAuditEntry {
  requestId: string;
  workflowId?: string;
  requestedAuthority: OutputAuthority;
  grantedAuthority: OutputAuthority;
  overrideAttempted: boolean;
  overrideClassification: OverrideClassification;
  decision: 'GRANT' | 'DOWNGRADE' | 'DENY';
  timestamp: string;
}

export interface AuthorityDetectionInput {
  requestId: string;
  workflowId?: string;
  requestedAuthority: OutputAuthority;
  policyGrantedAuthority: OutputAuthority;
  overrideAttempted: boolean;
  previousAuthority?: OutputAuthority;  // For chain tracking
}

export interface AuthorityDetectionResult {
  triggered: boolean;
  layer: ContainmentLayer;
  type: string;
  severity: Severity;
  scope: ImpactScope;
  detectionMode: string;
  effectiveAuthority: OutputAuthority;
  overrideClassification: OverrideClassification;
  auditEntry: AuthorityAuditEntry;
  mttdMs: number;
  note: string;
  detectedAt: string;
}

// ─────────────────────────────────────────────────────────
// AUTHORITY AUDIT LOG
// ─────────────────────────────────────────────────────────

/**
 * AuthorityAuditLog — immutable append-only log of authority decisions.
 * Phase 04: Persist to TimescaleDB with EVIDENCE_HANDLE indexing.
 */
export class AuthorityAuditLog {
  private readonly entries: AuthorityAuditEntry[] = [];

  append(entry: AuthorityAuditEntry): void {
    this.entries.push(Object.freeze({ ...entry }));
  }

  getEntries(requestId?: string): AuthorityAuditEntry[] {
    if (requestId) {
      return this.entries.filter(e => e.requestId === requestId);
    }
    return [...this.entries];
  }

  get length(): number {
    return this.entries.length;
  }
}

// ─────────────────────────────────────────────────────────
// AUTHORITY DETECTOR
// ─────────────────────────────────────────────────────────

export class AuthorityDetector {
  private readonly auditLog: AuthorityAuditLog;

  constructor(auditLog?: AuthorityAuditLog) {
    this.auditLog = auditLog ?? new AuthorityAuditLog();
  }

  get log(): AuthorityAuditLog {
    return this.auditLog;
  }

  /**
   * detect() — enforces the authority state machine for a request.
   *
   * Rules:
   * 1. Effective authority = min(requested, policyGranted) — never exceed what policy allows
   * 2. If previous authority exists: effective = min(effective, previous) — never upgrade in chain
   * 3. Override attempt = tried to claim higher authority than effective
   * 4. Classify override type for audit purposes
   */
  detect(input: AuthorityDetectionInput): AuthorityDetectionResult {
    const stop = startTimer();

    // Step 1: Clamp to policy grant
    const policyEffective = this._min(input.requestedAuthority, input.policyGrantedAuthority);

    // Step 2: Apply chain constraint (authority can only decrease in a chain)
    const effectiveAuthority = input.previousAuthority
      ? this._min(policyEffective, input.previousAuthority)
      : policyEffective;

    // Step 3: Detect override attempt
    const requestedRank = AUTHORITY_RANK[input.requestedAuthority];
    const effectiveRank = AUTHORITY_RANK[effectiveAuthority];
    const actualOverride = input.overrideAttempted || requestedRank > effectiveRank;

    // Step 4: Classify override
    const overrideClassification = this._classifyOverride(
      input.requestedAuthority,
      effectiveAuthority,
      input.policyGrantedAuthority,
      actualOverride,
    );

    // Step 5: Determine if triggered
    const triggered = actualOverride ||
      effectiveAuthority !== input.requestedAuthority ||
      effectiveAuthority === 'invalid';

    // Step 6: Compute severity
    const severity = this._computeSeverity(overrideClassification, effectiveAuthority);
    const scope: ImpactScope = overrideClassification === 'escalation_attempt' ? 'sys' : 'req';

    // Step 7: Determine decision label
    const decision = (() => {
      if (effectiveAuthority === 'invalid') return 'DENY' as const;
      if (effectiveAuthority !== input.requestedAuthority) return 'DOWNGRADE' as const;
      return 'GRANT' as const;
    })();

    // Step 8: Build audit entry
    const auditEntry: AuthorityAuditEntry = {
      requestId: input.requestId,
      workflowId: input.workflowId,
      requestedAuthority: input.requestedAuthority,
      grantedAuthority: effectiveAuthority,
      overrideAttempted: actualOverride,
      overrideClassification,
      decision,
      timestamp: new Date().toISOString(),
    };

    this.auditLog.append(auditEntry);

    const mttdMs = stop();

    return {
      triggered,
      layer: 'authority',
      type: triggered ? 'AUTHORITY_REVOKED' : 'AUTHORITY_GRANTED',
      severity,
      scope,
      detectionMode: LAYER_DETECTION_MODE['authority'],
      effectiveAuthority,
      overrideClassification,
      auditEntry,
      mttdMs,
      note: this._buildNote(decision, overrideClassification, effectiveAuthority),
      detectedAt: new Date().toISOString(),
    };
  }

  private _min(a: OutputAuthority, b: OutputAuthority): OutputAuthority {
    return AUTHORITY_RANK[a] <= AUTHORITY_RANK[b] ? a : b;
  }

  private _classifyOverride(
    requested: OutputAuthority,
    effective: OutputAuthority,
    policyGranted: OutputAuthority,
    overrideAttempted: boolean,
  ): OverrideClassification {
    if (!overrideAttempted && requested === effective) return 'none';
    if (effective === 'invalid' && requested !== 'invalid') return 'invalid_state_claim';
    if (AUTHORITY_RANK[requested] > AUTHORITY_RANK[policyGranted]) return 'escalation_attempt';
    if (requested === policyGranted && effective !== policyGranted) return 'boundary_test';
    return 'none';
  }

  private _computeSeverity(
    classification: OverrideClassification,
    effective: OutputAuthority,
  ): Severity {
    if (classification === 'escalation_attempt') return 'high';
    if (classification === 'invalid_state_claim') return 'high';
    if (effective === 'invalid') return 'med';
    if (classification === 'boundary_test') return 'med';
    return 'low';
  }

  private _buildNote(
    decision: 'GRANT' | 'DOWNGRADE' | 'DENY',
    classification: OverrideClassification,
    effective: OutputAuthority,
  ): string {
    if (decision === 'GRANT') return `Authority granted: ${effective}`;
    if (decision === 'DENY') return 'Authority denied — output invalid. Request blocked.';
    if (classification === 'escalation_attempt') return 'Escalation attempt detected. Authority downgraded.';
    return `Authority downgraded to ${effective}. Output is reference-only.`;
  }
}
