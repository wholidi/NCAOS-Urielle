/**
 * @ncaos/hardening — MTTD SLA Regression Tests
 *
 * Validates that all detection layers meet SLA thresholds defined in
 * PolicyProfile.mttdSlaMs under realistic load conditions.
 *
 * Phase 06 goal: establish MTTD performance baseline that Phase 07
 * regression tests can run against after any code change.
 *
 * SLA targets (ENTERPRISE_STRICT_PROFILE):
 *   gate:       50ms
 *   premise:   200ms
 *   authority: 100ms
 *   continuity:500ms
 *
 * Test methodology:
 *   - 1000 iterations per layer
 *   - Measure wall-clock mttdMs inside each detect() call
 *   - Assert p99 ≤ SLA threshold
 *   - Assert SLA breach rate < 1%
 */

import { describe, it, expect } from 'vitest';
import { GateDetector, DEFAULT_GATE_RULES } from '@ncaos/detection';
import { PremiseDetector } from '@ncaos/detection';
import { AuthorityDetector } from '@ncaos/detection';
import { ContinuityDetector } from '@ncaos/detection';
import { MttdTracker } from '@ncaos/detection';
import { ENTERPRISE_STRICT_PROFILE } from '@ncaos/core';
import type { PremiseDetectionInput } from '@ncaos/detection';

const SLA = ENTERPRISE_STRICT_PROFILE.mttdSlaMs;
const ITERATIONS = 1000;
const MAX_BREACH_RATE = 0.01; // 1%

// ─────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────

function percentile(sorted: number[], p: number): number {
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))] ?? 0;
}

function runMttdStats(mttdValues: number[], slaMs: number) {
  const sorted = [...mttdValues].sort((a, b) => a - b);
  const breaches = mttdValues.filter(v => v > slaMs).length;
  return {
    min: sorted[0] ?? 0,
    max: sorted[sorted.length - 1] ?? 0,
    mean: mttdValues.reduce((s, v) => s + v, 0) / mttdValues.length,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    breachCount: breaches,
    breachRate: breaches / mttdValues.length,
  };
}

// ─────────────────────────────────────────────────────────
// GATE DETECTOR — SLA: 50ms
// ─────────────────────────────────────────────────────────

describe('MTTD SLA Regression — Gate Detector', () => {
  const detector = new GateDetector(DEFAULT_GATE_RULES);
  const tracker = new MttdTracker('gate', SLA.gate);

  it(`gate p99 ≤ ${SLA.gate}ms over ${ITERATIONS} iterations`, () => {
    const mttdValues: number[] = [];

    for (let i = 0; i < ITERATIONS; i++) {
      // Alternate between clean and flagged inputs
      const flags = i % 3 === 0 ? ['INJECTION_PATTERN'] : i % 3 === 1 ? ['RATE_EXCEEDED'] : [];
      const result = detector.detect({
        sourceId: `src-${i}`,
        inputHash: `hash-${i}`,
        inputFlags: flags,
      });
      mttdValues.push(result.mttdMs);
      tracker.record(result.mttdMs);
    }

    const stats = runMttdStats(mttdValues, SLA.gate);
    console.log(`[GATE MTTD] p50=${stats.p50.toFixed(2)}ms p95=${stats.p95.toFixed(2)}ms p99=${stats.p99.toFixed(2)}ms mean=${stats.mean.toFixed(2)}ms breachRate=${(stats.breachRate*100).toFixed(2)}%`);

    expect(stats.p99).toBeLessThanOrEqual(SLA.gate);
    expect(stats.breachRate).toBeLessThan(MAX_BREACH_RATE);
  });

  it('gate SLA healthy flag correct after regression run', () => {
    const trackerStats = tracker.stats();
    // p50 should be well within SLA
    expect(trackerStats.p50).toBeLessThanOrEqual(SLA.gate);
    expect(trackerStats.slaBreachRate).toBeLessThan(MAX_BREACH_RATE);
  });
});

// ─────────────────────────────────────────────────────────
// PREMISE DETECTOR — SLA: 200ms
// ─────────────────────────────────────────────────────────

describe('MTTD SLA Regression — Premise Detector', () => {
  const detector = new PremiseDetector();

  it(`premise p99 ≤ ${SLA.premise}ms over ${ITERATIONS} iterations`, () => {
    const mttdValues: number[] = [];
    const defs = [
      { id: 'P-AUTH', label: 'Auth', weight: 'critical' as const },
      { id: 'P-SCOPE', label: 'Scope', weight: 'standard' as const },
      { id: 'P-ENV', label: 'Env', weight: 'informational' as const },
    ];

    for (let i = 0; i < ITERATIONS; i++) {
      const allValidated = i % 2 === 0;
      const input: PremiseDetectionInput = {
        workflowId: `wf-${i % 10}`,
        contractVersion: '1.0',
        expectedContractVersion: '1.0',
        claimedPremiseIds: ['P-AUTH', 'P-SCOPE'],
        validatedPremises: allValidated
          ? [{ id: 'P-AUTH', validatedAt: performance.now() }, { id: 'P-SCOPE', validatedAt: performance.now() }]
          : [{ id: 'P-SCOPE', validatedAt: performance.now() }],
        premiseDefinitions: defs,
      };
      const result = detector.detect(input);
      mttdValues.push(result.mttdMs);
    }

    const stats = runMttdStats(mttdValues, SLA.premise);
    console.log(`[PREMISE MTTD] p50=${stats.p50.toFixed(2)}ms p95=${stats.p95.toFixed(2)}ms p99=${stats.p99.toFixed(2)}ms breachRate=${(stats.breachRate*100).toFixed(2)}%`);

    expect(stats.p99).toBeLessThanOrEqual(SLA.premise);
    expect(stats.breachRate).toBeLessThan(MAX_BREACH_RATE);
  });
});

// ─────────────────────────────────────────────────────────
// AUTHORITY DETECTOR — SLA: 100ms
// ─────────────────────────────────────────────────────────

describe('MTTD SLA Regression — Authority Detector', () => {
  const detector = new AuthorityDetector();

  it(`authority p99 ≤ ${SLA.authority}ms over ${ITERATIONS} iterations`, () => {
    const mttdValues: number[] = [];

    for (let i = 0; i < ITERATIONS; i++) {
      const scenarios = [
        { requestedAuthority: 'decision-ready' as const, policyGrantedAuthority: 'decision-ready' as const, overrideAttempted: false },
        { requestedAuthority: 'decision-ready' as const, policyGrantedAuthority: 'reference-only' as const, overrideAttempted: false },
        { requestedAuthority: 'decision-ready' as const, policyGrantedAuthority: 'reference-only' as const, overrideAttempted: true },
      ];
      const scenario = scenarios[i % 3]!;
      const result = detector.detect({
        requestId: `REQ-${String(i).padStart(6, '0')}` as `REQ-${string}`,
        ...scenario,
      });
      mttdValues.push(result.mttdMs);
    }

    const stats = runMttdStats(mttdValues, SLA.authority);
    console.log(`[AUTHORITY MTTD] p50=${stats.p50.toFixed(2)}ms p95=${stats.p95.toFixed(2)}ms p99=${stats.p99.toFixed(2)}ms breachRate=${(stats.breachRate*100).toFixed(2)}%`);

    expect(stats.p99).toBeLessThanOrEqual(SLA.authority);
    expect(stats.breachRate).toBeLessThan(MAX_BREACH_RATE);
  });
});

// ─────────────────────────────────────────────────────────
// CONTINUITY DETECTOR — SLA: 500ms
// ─────────────────────────────────────────────────────────

describe('MTTD SLA Regression — Continuity Detector', () => {
  const detector = new ContinuityDetector();

  it(`continuity p99 ≤ ${SLA.continuity}ms over ${ITERATIONS} iterations`, () => {
    const mttdValues: number[] = [];

    for (let i = 0; i < ITERATIONS; i++) {
      const failCount = i % 4 === 0 ? 2 : 0;
      const tests = ContinuityDetector.generateTestTemplate(`UPD-${i}`).map((t, idx) => ({
        ...t,
        passed: idx < failCount ? false : true,
      }));

      const result = detector.detect({
        updateId: `UPD-${i}`,
        equivalenceTests: tests,
        stableThreshold: 75,
        provisionalThreshold: 55,
      });
      mttdValues.push(result.mttdMs);
    }

    const stats = runMttdStats(mttdValues, SLA.continuity);
    console.log(`[CONTINUITY MTTD] p50=${stats.p50.toFixed(2)}ms p95=${stats.p95.toFixed(2)}ms p99=${stats.p99.toFixed(2)}ms breachRate=${(stats.breachRate*100).toFixed(2)}%`);

    expect(stats.p99).toBeLessThanOrEqual(SLA.continuity);
    expect(stats.breachRate).toBeLessThan(MAX_BREACH_RATE);
  });
});
