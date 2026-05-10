/**
 * @ncaos/core — Detection Modules
 *
 * The four independent containment layers of the EGS.
 * Each module:
 *   1. Receives an input descriptor (what the Observer sees)
 *   2. Evaluates it against structural criteria (not internal model state)
 *   3. Returns a DetectionResult with severity, scope, type, and MTTD
 *
 * These are the "judge" stage of the observe → judge → enforce loop.
 * Each module is independently testable and independently deployable.
 *
 * PoC origin: btnInject* event handlers in NCAOS_UI_final.html
 */

import type { ContainmentLayer, DetectionMode, ImpactScope, Severity } from '../types/contracts.js';
import { LAYER_DETECTION_MODE } from '../types/contracts.js';

// ─────────────────────────────────────────────────────────
// DETECTION RESULT
// ─────────────────────────────────────────────────────────

export interface DetectionResult {
  triggered: boolean;
  type: string;                  // e.g. 'EXTERNAL_THREAT_BLOCKED'
  layer: ContainmentLayer;
  scope: ImpactScope;
  severity: Severity;
  detectionMode: DetectionMode;
  note: string;
  detectedAt: string;            // ISO 8601
  mttdMs: number;
}

// Input descriptor shapes — the Observer provides these
export interface GateInput {
  sourceId: string;
  inputHash: string;
  flags: string[];               // e.g. ['UNRECOGNIZED_SOURCE', 'RATE_EXCEEDED']
}

export interface PremiseInput {
  workflowId: string;
  contractVersion: string;
  claimedPremises: string[];     // What the request claims about its context
  validatedPremises: string[];   // What the shell can structurally verify
}

export interface AuthorityInput {
  requestedAuthority: 'decision-ready' | 'reference-only';
  policyGrantedAuthority: 'decision-ready' | 'reference-only' | 'invalid';
  overrideAttempted: boolean;
}

export interface ContinuityInput {
  updateId: string;
  equivalenceTestResults: Array<{ testId: string; passed: boolean }>;
  continuityScore: number;
  stableThreshold: number;
}

// ─────────────────────────────────────────────────────────
// LAYER 1: EXTERNAL GATE
// Real-time I/O boundary enforcement.
// Detects threats at the perimeter before any premise evaluation.
// ─────────────────────────────────────────────────────────

export function detectGate(input: GateInput): DetectionResult {
  const start = Date.now();

  const criticalFlags = ['INJECTION_PATTERN', 'KNOWN_BAD_SOURCE', 'SIGNATURE_INVALID'];
  const warnFlags = ['RATE_EXCEEDED', 'UNRECOGNIZED_SOURCE', 'GEO_MISMATCH'];

  const hasCritical = input.flags.some((f) => criticalFlags.includes(f));
  const hasWarn = input.flags.some((f) => warnFlags.includes(f));
  const triggered = hasCritical || hasWarn;

  const severity: Severity = hasCritical ? 'high' : hasWarn ? 'med' : 'low';

  return {
    triggered,
    type: 'EXTERNAL_THREAT_BLOCKED',
    layer: 'gate',
    scope: hasCritical ? 'sys' : 'req',
    severity,
    detectionMode: LAYER_DETECTION_MODE['gate'],
    note: 'Input rejected by external boundary conditions. (No signature required.)',
    detectedAt: new Date().toISOString(),
    mttdMs: Date.now() - start,
  };
}

// ─────────────────────────────────────────────────────────
// LAYER 2: PREMISE CONSISTENCY
// Validates that the request's claimed context matches structural reality.
// Legitimacy is revoked before decision authority is granted.
// ─────────────────────────────────────────────────────────

export function detectPremise(input: PremiseInput): DetectionResult {
  const start = Date.now();

  // Find premises the request claims but the shell cannot validate
  const unvalidatedClaims = input.claimedPremises.filter(
    (p) => !input.validatedPremises.includes(p),
  );

  const mismatchRatio =
    input.claimedPremises.length > 0
      ? unvalidatedClaims.length / input.claimedPremises.length
      : 0;

  const triggered = mismatchRatio > 0;
  const severity: Severity = mismatchRatio >= 0.7 ? 'high' : mismatchRatio >= 0.3 ? 'med' : 'low';

  return {
    triggered,
    type: 'PREMISE_MISMATCH',
    layer: 'premise',
    scope: severity === 'high' ? 'flow' : 'req',
    severity,
    detectionMode: LAYER_DETECTION_MODE['premise'],
    note: 'Legitimacy revoked before decision authority is granted.',
    detectedAt: new Date().toISOString(),
    mttdMs: Date.now() - start,
  };
}

// ─────────────────────────────────────────────────────────
// LAYER 3: AUTHORITY BOUNDARY
// Enforces the output authority state machine.
// Detects attempts to claim higher authority than the policy grants.
// ─────────────────────────────────────────────────────────

export function detectAuthority(input: AuthorityInput): DetectionResult {
  const start = Date.now();

  // Authority is revoked if: policy grants less than requested, or override attempted
  const authorityDowngraded =
    input.policyGrantedAuthority !== 'decision-ready' &&
    input.requestedAuthority === 'decision-ready';

  const triggered = authorityDowngraded || input.overrideAttempted;
  const severity: Severity = input.overrideAttempted
    ? 'high'
    : input.policyGrantedAuthority === 'invalid'
    ? 'high'
    : 'med';

  return {
    triggered,
    type: 'AUTHORITY_REVOKED',
    layer: 'authority',
    scope: input.overrideAttempted ? 'sys' : 'req',
    severity,
    detectionMode: LAYER_DETECTION_MODE['authority'],
    note: 'Output may be visible as reference-only or invalid depending on severity.',
    detectedAt: new Date().toISOString(),
    mttdMs: Date.now() - start,
  };
}

// ─────────────────────────────────────────────────────────
// LAYER 4: CONTINUITY WATCH
// Post-update equivalence testing.
// Detects behavioral drift across an update window.
// Scope is always sys — continuity failures are system-wide by definition.
// ─────────────────────────────────────────────────────────

export function detectContinuity(input: ContinuityInput): DetectionResult {
  const start = Date.now();

  const failedTests = input.equivalenceTestResults.filter((t) => !t.passed);
  const failRate =
    input.equivalenceTestResults.length > 0
      ? failedTests.length / input.equivalenceTestResults.length
      : 0;

  const belowStable = input.continuityScore < input.stableThreshold;
  const triggered = belowStable || failRate > 0.1;

  const severity: Severity =
    failRate >= 0.4 || input.continuityScore < 55
      ? 'high'
      : failRate >= 0.1 || input.continuityScore < 75
      ? 'med'
      : 'low';

  return {
    triggered,
    type: 'CONTINUITY_VIOLATION',
    layer: 'continuity',
    scope: 'sys',           // Always system-wide
    severity,
    detectionMode: LAYER_DETECTION_MODE['continuity'],
    note: 'Structural continuity degraded across update window; treat as provisional.',
    detectedAt: new Date().toISOString(),
    mttdMs: Date.now() - start,
  };
}
