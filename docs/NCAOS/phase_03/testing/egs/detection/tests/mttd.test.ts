/**
 * Tests — MTTD Tracker & DetectionRegistry
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MttdTracker, DetectionRegistry, startTimer } from '../src/mttd/tracker.js';
import { ENTERPRISE_STRICT_PROFILE } from '@ncaos/core';

describe('MttdTracker', () => {
  let tracker: MttdTracker;

  beforeEach(() => {
    tracker = new MttdTracker('gate', 50);
  });

  it('records a sample and returns correct SLA result', () => {
    const sample = tracker.record(30);
    expect(sample.layer).toBe('gate');
    expect(sample.mttdMs).toBe(30);
    expect(sample.slaMs).toBe(50);
    expect(sample.slaMet).toBe(true);
  });

  it('flags SLA breach when mttd exceeds sla', () => {
    const sample = tracker.record(80);
    expect(sample.slaMet).toBe(false);
  });

  it('computes stats correctly after multiple samples', () => {
    [10, 20, 30, 40, 50].forEach(ms => tracker.record(ms));
    const stats = tracker.stats();
    expect(stats.sampleCount).toBe(5);
    expect(stats.min).toBe(10);
    expect(stats.max).toBe(50);
    expect(stats.mean).toBe(30);
    expect(stats.p50).toBe(30);
  });

  it('tracks breach count correctly', () => {
    tracker.record(40);  // within SLA
    tracker.record(60);  // breach
    tracker.record(70);  // breach
    const stats = tracker.stats();
    expect(stats.slaBreach).toBe(2);
    expect(stats.slaBreachRate).toBeCloseTo(2/3);
  });

  it('returns zero stats when no samples recorded', () => {
    const stats = tracker.stats();
    expect(stats.sampleCount).toBe(0);
    expect(stats.mean).toBe(0);
    expect(stats.p99).toBe(0);
  });

  it('resets breach count on reset()', () => {
    tracker.record(100); // breach
    tracker.reset();
    const stats = tracker.stats();
    expect(stats.slaBreach).toBe(0);
  });
});

describe('DetectionRegistry', () => {
  it('initializes trackers for all four layers', () => {
    const registry = new DetectionRegistry(ENTERPRISE_STRICT_PROFILE);
    const stats = registry.allStats();
    const layers = stats.map(s => s.layer);
    expect(layers).toContain('gate');
    expect(layers).toContain('premise');
    expect(layers).toContain('authority');
    expect(layers).toContain('continuity');
  });

  it('uses SLA values from policy profile', () => {
    const registry = new DetectionRegistry(ENTERPRISE_STRICT_PROFILE);
    const gateStats = registry.allStats().find(s => s.layer === 'gate');
    expect(gateStats?.slaMs).toBe(ENTERPRISE_STRICT_PROFILE.mttdSlaMs.gate);
  });

  it('reports healthy when no breaches', () => {
    const registry = new DetectionRegistry(ENTERPRISE_STRICT_PROFILE);
    expect(registry.isSlaHealthy()).toBe(true);
  });

  it('throws on unknown layer', () => {
    const registry = new DetectionRegistry(ENTERPRISE_STRICT_PROFILE);
    expect(() => registry.tracker('unknown' as any)).toThrow();
  });
});

describe('startTimer', () => {
  it('returns a positive elapsed time', async () => {
    const stop = startTimer();
    await new Promise(r => setTimeout(r, 5));
    const elapsed = stop();
    expect(elapsed).toBeGreaterThan(0);
  });

  it('measures at least the waited duration', async () => {
    const stop = startTimer();
    await new Promise(r => setTimeout(r, 10));
    const elapsed = stop();
    expect(elapsed).toBeGreaterThanOrEqual(5); // generous lower bound
  });
});
