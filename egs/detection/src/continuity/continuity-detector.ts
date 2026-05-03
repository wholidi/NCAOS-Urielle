/**
 * @ncaos/detection — Continuity Detection Module
 *
 * Layer 4: Continuity Watch
 * Post-update equivalence testing.
 * Detects behavioral drift across an update window.
 *
 * Phase 03 upgrades:
 * - Equivalence test harness with automated test case generation
 * - Behavioral drift scoring (weighted by test criticality)
 * - Change window state machine (OPEN → WATCHING → CLOSED)
 * - Continuity score trending (improving / stable / degrading)
 * - Full MTTD instrumentation
 *
 * Design invariants:
 * - Continuity always has system-wide scope (never req or flow)
 * - Equivalence means behavioral consistency, NOT output identity
 * - The harness never executes against the protected core directly
 * - Tests are structural — they verify boundary behavior, not internal state
 *
 * Change window state machine:
 *
 *   IDLE ──(update detected)──► OPEN ──(tests run)──► WATCHING ──(stable)──► CLOSED
 *                                                          │
 *                                              (threshold breach)
 *                                                          ▼
 *                                                    CONTAINMENT
 */

import { LAYER_DETECTION_MODE } from '@ncaos/core';
import type { ContainmentLayer, Severity } from '@ncaos/core';
import { startTimer } from '../mttd/tracker.js';

// ─────────────────────────────────────────────────────────
// EQUIVALENCE TEST
// ─────────────────────────────────────────────────────────

export type TestCriticality = 'critical' | 'standard' | 'informational';
export type ChangeWindowState = 'IDLE' | 'OPEN' | 'WATCHING' | 'CLOSED' | 'CONTAINMENT';

export interface EquivalenceTest {
  testId: string;
  description: string;
  criticality: TestCriticality;
  passed: boolean;
  preUpdateValue?: string;      // Expected boundary behavior before update
  postUpdateValue?: string;     // Observed boundary behavior after update
  drift?: string;               // Human-readable description of drift if failed
}

export interface ContinuityDetectionInput {
  updateId: string;
  updateDescription?: string;
  equivalenceTests: EquivalenceTest[];
  stableThreshold: number;      // From PolicyProfile.continuityThresholds.stable
  provisionalThreshold: number; // From PolicyProfile.continuityThresholds.provisional
  changeWindowState?: ChangeWindowState;
}

export interface ContinuityDetectionResult {
  triggered: boolean;
  layer: ContainmentLayer;
  type: string;
  severity: Severity;
  scope: 'sys';                 // Always sys — continuity is always system-wide
  detectionMode: string;
  continuityScore: number;      // 0–100
  updateState: 'STABLE' | 'PROVISIONAL' | 'UNSTABLE';
  changeWindowState: ChangeWindowState;
  failedTests: EquivalenceTest[];
  criticalFailures: number;
  failRate: number;             // 0.0–1.0
  scoretrend: 'improving' | 'stable' | 'degrading';
  mttdMs: number;
  note: string;
  detectedAt: string;
}

// ─────────────────────────────────────────────────────────
// CONTINUITY SCORE CALCULATOR
// ─────────────────────────────────────────────────────────

/**
 * Computes a weighted continuity score from equivalence test results.
 *
 * Weights:
 * - critical test: weight 3
 * - standard test: weight 1
 * - informational: weight 0.5 (contributes but at lower weight)
 *
 * Score = (weighted passes / total weight) * 100
 */
function computeContinuityScore(tests: EquivalenceTest[]): number {
  if (tests.length === 0) return 100;

  const weightMap: Record<TestCriticality, number> = {
    critical: 3,
    standard: 1,
    informational: 0.5,
  };

  let totalWeight = 0;
  let passWeight = 0;

  for (const test of tests) {
    const w = weightMap[test.criticality];
    totalWeight += w;
    if (test.passed) passWeight += w;
  }

  return totalWeight > 0 ? Math.round((passWeight / totalWeight) * 100) : 100;
}

// ─────────────────────────────────────────────────────────
// CONTINUITY DETECTOR
// ─────────────────────────────────────────────────────────

export class ContinuityDetector {
  private lastScore: number | null = null;
  private readonly scoreHistory: number[] = [];
  private readonly HISTORY_LIMIT = 20;

  /**
   * detect() — evaluates equivalence test results and computes continuity state.
   */
  detect(input: ContinuityDetectionInput): ContinuityDetectionResult {
    const stop = startTimer();

    const failedTests = input.equivalenceTests.filter(t => !t.passed);
    const criticalFailures = failedTests.filter(t => t.criticality === 'critical').length;
    const failRate = input.equivalenceTests.length > 0
      ? failedTests.length / input.equivalenceTests.length
      : 0;

    const continuityScore = computeContinuityScore(input.equivalenceTests);

    // Score trending
    const scoretrend = this._computeTrend(continuityScore);
    this._recordScore(continuityScore);

    // Update state
    const updateState = this._computeUpdateState(
      continuityScore,
      input.stableThreshold,
      input.provisionalThreshold,
    );

    // Triggered if below stable threshold or any critical failure
    const triggered = continuityScore < input.stableThreshold || criticalFailures > 0;

    // Severity
    const severity = this._computeSeverity(
      continuityScore,
      criticalFailures,
      input.provisionalThreshold,
    );

    // Change window state machine
    const changeWindowState = this._computeWindowState(
      input.changeWindowState ?? 'OPEN',
      updateState,
    );

    const mttdMs = stop();

    return {
      triggered,
      layer: 'continuity',
      type: triggered ? 'CONTINUITY_VIOLATION' : 'CONTINUITY_STABLE',
      severity,
      scope: 'sys',
      detectionMode: LAYER_DETECTION_MODE['continuity'],
      continuityScore,
      updateState,
      changeWindowState,
      failedTests,
      criticalFailures,
      failRate,
      scoretrend,
      mttdMs,
      note: triggered
        ? `Continuity score ${continuityScore}/100. ${criticalFailures} critical failure(s). State: ${updateState}.`
        : `Continuity score ${continuityScore}/100. System behavior stable across update window.`,
      detectedAt: new Date().toISOString(),
    };
  }

  /**
   * generateTests() — produces a standard set of equivalence test stubs.
   * In Phase 04: these are populated by real I/O boundary probes.
   * In Phase 03: they are provided by the caller (test harness or API).
   */
  static generateTestTemplate(updateId: string): EquivalenceTest[] {
    return [
      { testId: `${updateId}-T01`, description: 'Output authority boundary unchanged', criticality: 'critical', passed: true },
      { testId: `${updateId}-T02`, description: 'FAIL_SAFE path still triggers on error', criticality: 'critical', passed: true },
      { testId: `${updateId}-T03`, description: 'Tenant isolation maintained', criticality: 'critical', passed: true },
      { testId: `${updateId}-T04`, description: 'Policy profile enforcement unchanged', criticality: 'standard', passed: true },
      { testId: `${updateId}-T05`, description: 'Evidence handle format preserved', criticality: 'standard', passed: true },
      { testId: `${updateId}-T06`, description: 'MTTD within SLA bounds', criticality: 'standard', passed: true },
      { testId: `${updateId}-T07`, description: 'GovState fields present and typed', criticality: 'standard', passed: true },
      { testId: `${updateId}-T08`, description: 'Routing hints unchanged for known scenarios', criticality: 'standard', passed: true },
      { testId: `${updateId}-T09`, description: 'Deprecation notices unchanged', criticality: 'informational', passed: true },
      { testId: `${updateId}-T10`, description: 'Response latency within normal range', criticality: 'informational', passed: true },
      { testId: `${updateId}-T11`, description: 'Log format unchanged', criticality: 'informational', passed: true },
      { testId: `${updateId}-T12`, description: 'Health endpoint format unchanged', criticality: 'informational', passed: true },
    ];
  }

  private _computeUpdateState(
    score: number,
    stableThreshold: number,
    provisionalThreshold: number,
  ): 'STABLE' | 'PROVISIONAL' | 'UNSTABLE' {
    if (score >= stableThreshold) return 'STABLE';
    if (score >= provisionalThreshold) return 'PROVISIONAL';
    return 'UNSTABLE';
  }

  private _computeSeverity(
    score: number,
    criticalFailures: number,
    provisionalThreshold: number,
  ): Severity {
    if (criticalFailures > 0 || score < provisionalThreshold) return 'high';
    if (score < 75) return 'med';
    return 'low';
  }

  private _computeWindowState(
    current: ChangeWindowState,
    updateState: 'STABLE' | 'PROVISIONAL' | 'UNSTABLE',
  ): ChangeWindowState {
    if (updateState === 'UNSTABLE') return 'CONTAINMENT';
    if (current === 'OPEN') return 'WATCHING';
    if (current === 'WATCHING' && updateState === 'STABLE') return 'CLOSED';
    return current;
  }

  private _computeTrend(score: number): 'improving' | 'stable' | 'degrading' {
    if (this.lastScore === null) return 'stable';
    const delta = score - this.lastScore;
    if (delta > 5) return 'improving';
    if (delta < -5) return 'degrading';
    return 'stable';
  }

  private _recordScore(score: number): void {
    this.lastScore = score;
    this.scoreHistory.push(score);
    if (this.scoreHistory.length > this.HISTORY_LIMIT) {
      this.scoreHistory.shift();
    }
  }

  get scoreHistory(): number[] {
    return [...this.scoreHistory];
  }
}
