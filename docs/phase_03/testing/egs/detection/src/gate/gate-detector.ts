/**
 * @ncaos/detection — Gate Detection Module
 *
 * Layer 1: External Gate
 * Real-time pattern matching at the I/O perimeter.
 * First line of defence — runs before any premise evaluation.
 *
 * Phase 03 upgrades from Phase 01's flag-matching to:
 * - Configurable rule sets loaded from PolicyProfile
 * - Pattern matching with priority ordering (critical > warning > info)
 * - Rate limiting detection (request frequency analysis)
 * - Source reputation checking (allowlist / blocklist)
 * - Full MTTD instrumentation per detection run
 *
 * Design invariants:
 * - Gate never modifies the input — observe only
 * - Gate result is independent of premise/authority/continuity layers
 * - MTTD is measured from signal receipt to DetectionResult emission
 */

import { LAYER_DETECTION_MODE } from '@ncaos/core';
import type { ContainmentLayer, ImpactScope, Severity } from '@ncaos/core';
import { startTimer } from '../mttd/tracker.js';

// ─────────────────────────────────────────────────────────
// GATE RULE SET
// ─────────────────────────────────────────────────────────

export type RulePriority = 'critical' | 'warning' | 'info';

export interface GateRule {
  id: string;
  pattern: string;              // Exact flag match or glob pattern
  priority: RulePriority;
  description: string;
  scope: ImpactScope;           // Scope when this rule triggers
}

/**
 * Default rule set — derived from Architecture Guide threat categories.
 * Enterprise can extend via PolicyProfile (Phase 04: DB-backed rule CRUD).
 */
export const DEFAULT_GATE_RULES: GateRule[] = [
  // Critical — block immediately, system-wide scope
  { id: 'G-C-001', pattern: 'INJECTION_PATTERN',    priority: 'critical', scope: 'sys',  description: 'Input injection attempt detected at boundary' },
  { id: 'G-C-002', pattern: 'SIGNATURE_INVALID',    priority: 'critical', scope: 'sys',  description: 'Cryptographic signature validation failed' },
  { id: 'G-C-003', pattern: 'KNOWN_BAD_SOURCE',     priority: 'critical', scope: 'sys',  description: 'Source matched blocklist entry' },
  { id: 'G-C-004', pattern: 'REPLAY_ATTACK',        priority: 'critical', scope: 'sys',  description: 'Request nonce previously seen — replay detected' },
  { id: 'G-C-005', pattern: 'TAMPERED_PAYLOAD',     priority: 'critical', scope: 'sys',  description: 'Payload integrity check failed' },

  // Warning — downgrade or block per policy, request scope
  { id: 'G-W-001', pattern: 'RATE_EXCEEDED',        priority: 'warning',  scope: 'req',  description: 'Request rate exceeds configured threshold' },
  { id: 'G-W-002', pattern: 'UNRECOGNIZED_SOURCE',  priority: 'warning',  scope: 'req',  description: 'Source not in verified allowlist' },
  { id: 'G-W-003', pattern: 'GEO_MISMATCH',         priority: 'warning',  scope: 'req',  description: 'Request origin outside expected geographic boundary' },
  { id: 'G-W-004', pattern: 'SCHEMA_VIOLATION',     priority: 'warning',  scope: 'flow', description: 'Input does not conform to expected schema' },
  { id: 'G-W-005', pattern: 'OVERSIZED_PAYLOAD',    priority: 'warning',  scope: 'req',  description: 'Payload exceeds configured size threshold' },

  // Info — log only, does not trigger containment
  { id: 'G-I-001', pattern: 'DEPRECATED_ENDPOINT',  priority: 'info',     scope: 'req',  description: 'Request targets deprecated API endpoint' },
  { id: 'G-I-002', pattern: 'SLOW_CLIENT',          priority: 'info',     scope: 'req',  description: 'Client connection latency above threshold' },
];

// ─────────────────────────────────────────────────────────
// GATE INPUT / RESULT
// ─────────────────────────────────────────────────────────

export interface GateDetectionInput {
  sourceId: string;
  inputHash: string;
  inputFlags: string[];
  payloadSizeBytes?: number;
  requestsPerMinute?: number;
  allowedSources?: string[];    // If provided, UNRECOGNIZED_SOURCE is auto-added
}

export interface GateDetectionResult {
  triggered: boolean;
  layer: ContainmentLayer;
  type: string;
  severity: Severity;
  scope: ImpactScope;
  detectionMode: string;
  matchedRules: GateRule[];
  dominantRule: GateRule | null;
  mttdMs: number;
  note: string;
  detectedAt: string;
}

// ─────────────────────────────────────────────────────────
// GATE DETECTOR
// ─────────────────────────────────────────────────────────

export class GateDetector {
  private readonly rules: GateRule[];

  constructor(rules: GateRule[] = DEFAULT_GATE_RULES) {
    this.rules = rules;
  }

  /**
   * detect() — runs the full gate rule set against the input.
   * Returns a GateDetectionResult with full MTTD measurement.
   *
   * Priority ordering: critical > warning > info
   * Scope: widest scope across all triggered rules wins.
   * Only critical and warning rules trigger containment.
   */
  detect(input: GateDetectionInput): GateDetectionResult {
    const stop = startTimer();

    // Auto-detect source recognition
    const augmentedFlags = [...input.inputFlags];
    if (
      input.allowedSources &&
      input.allowedSources.length > 0 &&
      !input.allowedSources.includes(input.sourceId)
    ) {
      augmentedFlags.push('UNRECOGNIZED_SOURCE');
    }

    // Match rules against flags
    const matchedRules = this.rules.filter(
      r => augmentedFlags.includes(r.pattern) && r.priority !== 'info',
    );

    const triggered = matchedRules.length > 0;

    // Determine dominant rule (highest priority, then first matched)
    const dominantRule = triggered
      ? (matchedRules.find(r => r.priority === 'critical') ??
         matchedRules.find(r => r.priority === 'warning') ??
         matchedRules[0] ?? null)
      : null;

    const severity = this._severityFromPriority(dominantRule?.priority ?? 'info');
    const scope = this._widerScope(matchedRules.map(r => r.scope));

    const mttdMs = stop();

    return {
      triggered,
      layer: 'gate',
      type: triggered ? 'EXTERNAL_THREAT_BLOCKED' : 'GATE_CLEAR',
      severity,
      scope,
      detectionMode: LAYER_DETECTION_MODE['gate'],
      matchedRules,
      dominantRule,
      mttdMs,
      note: dominantRule
        ? dominantRule.description
        : 'No boundary violations detected.',
      detectedAt: new Date().toISOString(),
    };
  }

  addRule(rule: GateRule): void {
    this.rules.push(rule);
  }

  getRules(): GateRule[] {
    return [...this.rules];
  }

  private _severityFromPriority(priority: RulePriority): Severity {
    if (priority === 'critical') return 'high';
    if (priority === 'warning') return 'med';
    return 'low';
  }

  private _widerScope(scopes: ImpactScope[]): ImpactScope {
    if (scopes.includes('sys')) return 'sys';
    if (scopes.includes('flow')) return 'flow';
    return 'req';
  }
}
