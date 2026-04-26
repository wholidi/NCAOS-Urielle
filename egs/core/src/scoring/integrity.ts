/**
 * @ncaos/core — Scoring Module
 *
 * Derives integrity and authority states from severity + policy thresholds.
 * Ported and typed from the PoC's integrityBySeverity() and
 * authorityLevelBySeverity() functions in NCAOS_UI_final.html.
 *
 * Design principle: scoring is deterministic given severity + policy.
 * No randomness, no internal model state access — pure governance math.
 */

import type {
  AuthorityState,
  IntegrityLevel,
  IntegrityState,
  OutputAuthority,
  PolicyProfile,
  Severity,
} from '../types/contracts.js';

// ─────────────────────────────────────────────────────────
// INTEGRITY SCORING
// ─────────────────────────────────────────────────────────

/**
 * Baseline integrity scores per severity level.
 * These are starting points; policy thresholds determine level labels.
 *
 * PoC origin: integrityBySeverity() in NCAOS_UI_final.html
 */
const SEVERITY_INTEGRITY_SCORE: Record<Severity, number> = {
  low: 74,
  med: 61,
  high: 29,
};

/** Score for nominal (no active event) state. */
const NOMINAL_INTEGRITY_SCORE = 88;

/**
 * Derives an IntegrityState from a severity signal and the active policy profile.
 * The level label is determined by where the score falls within the policy thresholds.
 */
export function computeIntegrity(
  severity: Severity | null,
  policy: PolicyProfile,
): IntegrityState {
  const score = severity !== null ? SEVERITY_INTEGRITY_SCORE[severity] : NOMINAL_INTEGRITY_SCORE;
  const level = scoreToIntegrityLevel(score, policy);
  return { level, score };
}

/**
 * Maps a numeric score to an IntegrityLevel label using policy thresholds.
 * Thresholds are checked descending: Available → Limited → Degraded → Critical.
 */
export function scoreToIntegrityLevel(
  score: number,
  policy: PolicyProfile,
): IntegrityLevel {
  const { available, limited, degraded } = policy.integrityThresholds;
  if (score >= available) return 'Available';
  if (score >= limited) return 'Limited';
  if (score >= degraded) return 'Degraded';
  return 'Critical';
}

// ─────────────────────────────────────────────────────────
// AUTHORITY SCORING
// ─────────────────────────────────────────────────────────

/**
 * Baseline authority scores per severity level.
 *
 * PoC origin: authorityLevelBySeverity() in NCAOS_UI_final.html
 */
const SEVERITY_AUTHORITY_SCORE: Record<Severity, number> = {
  low: 72,
  med: 58,
  high: 22,
};

const NOMINAL_AUTHORITY_SCORE = 84;

/**
 * Derives an AuthorityState from a severity signal and the active policy profile.
 * Authority is structurally granted by the shell — not by internal self-reporting.
 */
export function computeAuthority(
  severity: Severity | null,
  policy: PolicyProfile,
): AuthorityState {
  const score =
    severity !== null ? SEVERITY_AUTHORITY_SCORE[severity] : NOMINAL_AUTHORITY_SCORE;
  const authority = scoreToOutputAuthority(score, policy);
  return { authority, score };
}

/**
 * Maps a numeric authority score to an OutputAuthority label.
 * Uses integrity thresholds as a proxy — authority degrades in line with integrity.
 */
export function scoreToOutputAuthority(
  score: number,
  policy: PolicyProfile,
): OutputAuthority {
  const { available, limited } = policy.integrityThresholds;
  if (score >= available) return 'decision-ready';
  if (score >= limited) return 'reference-only';
  return 'invalid';
}

// ─────────────────────────────────────────────────────────
// CONTAINMENT METRICS (illustrative signals)
// ─────────────────────────────────────────────────────────

/**
 * Computes the RAW_EXPOSURE vs GOVERNED_OUTPUT reduction ratio.
 *
 * RAW_EXPOSURE: instability in the protected core before governance logic.
 * GOVERNED_OUTPUT: residual exposure after the shell has filtered anomalies.
 *
 * These are illustrative signals — they demonstrate containment efficacy
 * to stakeholders without exposing internal model state.
 *
 * PoC origin: updateMetrics() in NCAOS_UI_final.html (was randomized;
 * here derived deterministically from integrity score).
 */
export function computeContainmentMetrics(integrity: IntegrityState): {
  rawExposurePct: number;
  governedOutputPct: number;
  coreIsolationPct: number;
  contextDriftPressurePct: number;
  latencyOverheadMs: number;
} {
  // Raw exposure is inversely proportional to integrity score
  const rawExposurePct = Math.round((100 - integrity.score) * 1.8 + 0.8);
  // Governed output is a fraction of raw — demonstrates containment
  const governedOutputPct = Math.round(rawExposurePct * 0.42);
  // Core isolation correlates with integrity
  const coreIsolationPct = Math.min(100, Math.round(integrity.score * 0.92 + 8));
  // Context drift pressure rises as integrity falls
  const contextDriftPressurePct = Math.round((100 - integrity.score) * 0.6);
  // Latency overhead stays bounded (governance SLA)
  const latencyOverheadMs = Math.round(120 + (100 - integrity.score) * 3.5);

  return {
    rawExposurePct: clamp(rawExposurePct, 0, 100),
    governedOutputPct: clamp(governedOutputPct, 0, 100),
    coreIsolationPct: clamp(coreIsolationPct, 0, 100),
    contextDriftPressurePct: clamp(contextDriftPressurePct, 0, 100),
    latencyOverheadMs,
  };
}

// ─────────────────────────────────────────────────────────
// CONTINUITY SCORING
// ─────────────────────────────────────────────────────────

/**
 * Maps a continuity score to an UPDATE_STATE label using policy thresholds.
 *
 * PoC origin: updateContinuity() in NCAOS_UI_final.html
 */
export function scoreToContinuityState(
  score: number,
  policy: PolicyProfile,
): 'STABLE' | 'PROVISIONAL' | 'UNSTABLE' {
  const { stable, provisional } = policy.continuityThresholds;
  if (score >= stable) return 'STABLE';
  if (score >= provisional) return 'PROVISIONAL';
  return 'UNSTABLE';
}

// ─────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
