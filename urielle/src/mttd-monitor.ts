/**
 * urielle/src/mttd-monitor.ts
 *
 * Aligned to NCAOS/EGS Phase 03 (MTTD instrumentation) + Phase 06 (SLA baseline)
 *
 * Urielle's MTTD monitoring layer.
 *
 * The EGS exposes /v1/mttd with p50/p95/p99 per detection layer.
 * This module gives Urielle the ability to:
 *   - Evaluate mttdMs values from individual AuditSignals
 *   - Compare against Phase 06 SLA baselines (the "Phase 07 performance contract")
 *   - Flag breaches for inclusion in audit findings
 *
 * Phase 06 baselines (from mttd-regression.test.ts):
 *   gate:        p99 ≤ 50ms
 *   premise:     p99 ≤ 200ms
 *   authority:   p99 ≤ 100ms
 *   continuity:  p99 ≤ 500ms
 */

export type DetectionLayer = 'gate' | 'premise' | 'authority' | 'continuity';

// ── Phase 06 SLA contract (p99 thresholds) ──

export const MTTD_SLA_MS: Record<DetectionLayer, number> = {
  gate:        50,
  premise:    200,
  authority:  100,
  continuity: 500,
};

// ── Phase 06 observed p99 baselines (from mttd-regression.test.ts, 1000 iterations) ──

export const MTTD_BASELINE_P99_MS: Record<DetectionLayer, number> = {
  gate:       0.03,
  premise:    0.05,
  authority:  0.03,
  continuity: 0.05,
};

// Per ADR-008: any future run exceeding baseline by >10% warrants investigation
export const REGRESSION_THRESHOLD_FACTOR = 1.10;

// ── MTTD evaluation per signal ──

export interface MttdEvaluation {
  layer:           DetectionLayer;
  mttdMs:          number;
  slaMs:           number;
  slaBreached:     boolean;
  regressionFlag:  boolean;  // >10% above Phase 06 p99 baseline
  category:        'NOMINAL' | 'ELEVATED' | 'SLA_BREACH';
}

export function evaluateMttd(layer: DetectionLayer, mttdMs: number): MttdEvaluation {
  const slaMs       = MTTD_SLA_MS[layer];
  const baselineP99 = MTTD_BASELINE_P99_MS[layer];

  const slaBreached     = mttdMs > slaMs;
  const regressionFlag  = mttdMs > baselineP99 * REGRESSION_THRESHOLD_FACTOR;

  const category: MttdEvaluation['category'] =
    slaBreached ? 'SLA_BREACH' :
    regressionFlag ? 'ELEVATED' : 'NOMINAL';

  return { layer, mttdMs, slaMs, slaBreached, regressionFlag, category };
}

// ── Aggregate MTTD report from a batch of signals ──

export interface MttdAuditReport {
  partnerId:    string;
  sampleCount:  number;
  byLayer:      Record<DetectionLayer, {
    sampleCount:   number;
    avgMs:         number;
    maxMs:         number;
    slaBreaches:   number;
    slaBreachRate: number;
    category:      'NOMINAL' | 'ELEVATED' | 'SLA_BREACH';
  }>;
  overallHealthy: boolean;
  generatedAt:    string;
}

export function buildMttdReport(
  signals: Array<{ layer: DetectionLayer; mttdMs: number }>,
  partnerId: string,
): MttdAuditReport {
  const layers: DetectionLayer[] = ['gate', 'premise', 'authority', 'continuity'];
  const byLayer = {} as MttdAuditReport['byLayer'];

  for (const layer of layers) {
    const layerSignals = signals.filter(s => s.layer === layer);
    if (layerSignals.length === 0) {
      byLayer[layer] = { sampleCount: 0, avgMs: 0, maxMs: 0, slaBreaches: 0, slaBreachRate: 0, category: 'NOMINAL' };
      continue;
    }
    const ms = layerSignals.map(s => s.mttdMs);
    const avg = ms.reduce((a, b) => a + b, 0) / ms.length;
    const max = Math.max(...ms);
    const breaches = ms.filter(m => m > MTTD_SLA_MS[layer]).length;
    const breachRate = Math.round((breaches / ms.length) * 100 * 10) / 10;
    const category: 'NOMINAL' | 'ELEVATED' | 'SLA_BREACH' =
      breaches > 0 ? 'SLA_BREACH' :
      max > MTTD_BASELINE_P99_MS[layer] * REGRESSION_THRESHOLD_FACTOR ? 'ELEVATED' : 'NOMINAL';
    byLayer[layer] = { sampleCount: ms.length, avgMs: Math.round(avg * 100) / 100, maxMs: max, slaBreaches: breaches, slaBreachRate: breachRate, category };
  }

  const overallHealthy = layers.every(l => byLayer[l].category !== 'SLA_BREACH');

  return { partnerId, sampleCount: signals.length, byLayer, overallHealthy, generatedAt: new Date().toISOString() };
}
