/**
 * @ncaos/detection — MTTD Instrumentation
 *
 * Mean Time To Detection (MTTD) is the primary performance metric for the EGS.
 * Each detection layer is instrumented to measure:
 *   - Wall-clock latency from signal ingestion to verdict
 *   - SLA compliance against the active PolicyProfile thresholds
 *   - Rolling statistics: p50, p95, p99, min, max
 *
 * Design principles:
 * - MTTD measurement is non-blocking — it never delays the detection result
 * - SLA breaches are logged and emitted as events, never suppressed
 * - Statistics are maintained in a bounded ring buffer (last 1000 samples)
 * - No external dependencies — pure Node.js performance.now()
 */

import type { ContainmentLayer, PolicyProfile } from '@ncaos/core';

// ─────────────────────────────────────────────────────────
// MTTD SAMPLE
// ─────────────────────────────────────────────────────────

export interface MttdSample {
  layer: ContainmentLayer;
  mttdMs: number;
  slaMs: number;
  slaMet: boolean;
  triggeredAt: string;        // ISO 8601
}

export interface MttdStats {
  layer: ContainmentLayer;
  sampleCount: number;
  slaMs: number;
  slaBreach: number;          // count of SLA breaches
  slaBreachRate: number;      // 0.0–1.0
  min: number;
  max: number;
  p50: number;
  p95: number;
  p99: number;
  mean: number;
}

// ─────────────────────────────────────────────────────────
// RING BUFFER
// ─────────────────────────────────────────────────────────

const BUFFER_SIZE = 1000;

class RingBuffer {
  private buf: number[] = [];
  private size: number;

  constructor(size = BUFFER_SIZE) {
    this.size = size;
  }

  push(val: number): void {
    if (this.buf.length >= this.size) {
      this.buf.shift();
    }
    this.buf.push(val);
  }

  get values(): number[] {
    return [...this.buf];
  }

  get length(): number {
    return this.buf.length;
  }
}

// ─────────────────────────────────────────────────────────
// MTTD TRACKER
// ─────────────────────────────────────────────────────────

/**
 * MttdTracker — maintains rolling MTTD statistics per detection layer.
 *
 * One tracker instance per layer, held by the DetectionRegistry.
 * Thread-safe for single-process Node.js (no shared state across workers).
 */
export class MttdTracker {
  private readonly layer: ContainmentLayer;
  private readonly slaMs: number;
  private readonly buffer: RingBuffer;
  private breachCount = 0;
  private totalSamples = 0;

  constructor(layer: ContainmentLayer, slaMs: number) {
    this.layer = layer;
    this.slaMs = slaMs;
    this.buffer = new RingBuffer();
  }

  /**
   * record() — called after each detection run to log the MTTD sample.
   * Returns the MttdSample for audit/event logging.
   */
  record(mttdMs: number): MttdSample {
    const slaMet = mttdMs <= this.slaMs;
    if (!slaMet) this.breachCount++;
    this.totalSamples++;
    this.buffer.push(mttdMs);

    const sample: MttdSample = {
      layer: this.layer,
      mttdMs,
      slaMs: this.slaMs,
      slaMet,
      triggeredAt: new Date().toISOString(),
    };

    if (!slaMet) {
      console.warn(
        `[MTTD] SLA BREACH layer=${this.layer} mttd=${mttdMs.toFixed(2)}ms sla=${this.slaMs}ms`,
      );
    }

    return sample;
  }

  /**
   * stats() — returns rolling statistics for this layer.
   * Uses the last BUFFER_SIZE samples.
   */
  stats(): MttdStats {
    const vals = this.buffer.values;
    if (vals.length === 0) {
      return {
        layer: this.layer,
        sampleCount: 0,
        slaMs: this.slaMs,
        slaBreach: 0,
        slaBreachRate: 0,
        min: 0, max: 0, p50: 0, p95: 0, p99: 0, mean: 0,
      };
    }

    const sorted = [...vals].sort((a, b) => a - b);
    const n = sorted.length;
    const percentile = (p: number) => {
      const idx = Math.ceil((p / 100) * n) - 1;
      return sorted[Math.max(0, Math.min(idx, n - 1))] ?? 0;
    };

    const mean = vals.reduce((a, b) => a + b, 0) / n;

    return {
      layer: this.layer,
      sampleCount: this.totalSamples,
      slaMs: this.slaMs,
      slaBreach: this.breachCount,
      slaBreachRate: this.totalSamples > 0 ? this.breachCount / this.totalSamples : 0,
      min: sorted[0] ?? 0,
      max: sorted[n - 1] ?? 0,
      p50: percentile(50),
      p95: percentile(95),
      p99: percentile(99),
      mean,
    };
  }

  reset(): void {
    this.breachCount = 0;
    this.totalSamples = 0;
  }
}

// ─────────────────────────────────────────────────────────
// DETECTION REGISTRY
// ─────────────────────────────────────────────────────────

/**
 * DetectionRegistry — holds one MttdTracker per layer.
 * Initialized from a PolicyProfile at startup.
 *
 * The registry is the single source of truth for MTTD statistics
 * across all four detection layers.
 */
export class DetectionRegistry {
  private readonly trackers: Map<ContainmentLayer, MttdTracker>;

  constructor(policy: PolicyProfile) {
    const { mttdSlaMs } = policy;
    this.trackers = new Map([
      ['gate',        new MttdTracker('gate',        mttdSlaMs.gate)],
      ['premise',     new MttdTracker('premise',     mttdSlaMs.premise)],
      ['authority',   new MttdTracker('authority',   mttdSlaMs.authority)],
      ['continuity',  new MttdTracker('continuity',  mttdSlaMs.continuity)],
    ]);
  }

  tracker(layer: ContainmentLayer): MttdTracker {
    const t = this.trackers.get(layer);
    if (!t) throw new Error(`No tracker for layer: ${layer}`);
    return t;
  }

  allStats(): MttdStats[] {
    return Array.from(this.trackers.values()).map(t => t.stats());
  }

  /**
   * isSlaHealthy() — returns true if ALL layers are within SLA.
   * Used by the health endpoint to signal detection layer degradation.
   */
  isSlaHealthy(): boolean {
    return this.allStats().every(s => s.slaBreachRate < 0.05); // < 5% breach rate
  }
}

// ─────────────────────────────────────────────────────────
// TIMER HELPER
// ─────────────────────────────────────────────────────────

/**
 * startTimer() — returns a function that measures elapsed time in ms.
 * Uses performance.now() for sub-millisecond precision.
 *
 * Usage:
 *   const stop = startTimer();
 *   // ... do work ...
 *   const mttdMs = stop();
 */
export function startTimer(): () => number {
  const start = performance.now();
  return () => performance.now() - start;
}
