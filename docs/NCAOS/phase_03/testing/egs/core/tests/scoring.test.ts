/**
 * Unit tests — Scoring Module
 *
 * Validates that integrity, authority, and containment metrics are computed
 * correctly across all severity levels and policy configurations.
 *
 * These tests pin the PoC's integrityBySeverity() and
 * authorityLevelBySeverity() behaviors to typed contracts.
 */

import { describe, it, expect } from 'vitest';
import {
  computeIntegrity,
  computeAuthority,
  computeContainmentMetrics,
  scoreToContinuityState,
} from '../../src/scoring/integrity.js';
import { ENTERPRISE_STRICT_PROFILE, CRITICAL_STRICT_PROFILE, PILOT_PROFILE } from '../../src/policy/loader.js';

describe('computeIntegrity', () => {
  it('returns Available / 88 for nominal (no active event)', () => {
    const result = computeIntegrity(null, ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(88);
    expect(result.level).toBe('Available');
  });

  it('returns Limited for low severity', () => {
    const result = computeIntegrity('low', ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(74);
    expect(result.level).toBe('Limited');
  });

  it('returns Limited for med severity (score 61 >= limited threshold 60)', () => {
    const result = computeIntegrity('med', ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(61);
    expect(result.level).toBe('Limited');
  });

  it('returns Critical for high severity', () => {
    const result = computeIntegrity('high', ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(29);
    expect(result.level).toBe('Critical');
  });

  it('respects custom thresholds from CRITICAL_STRICT_PROFILE', () => {
    // CRITICAL_STRICT has available >= 90; score 88 should be Limited, not Available
    const result = computeIntegrity(null, CRITICAL_STRICT_PROFILE);
    expect(result.score).toBe(88);
    expect(result.level).toBe('Limited'); // 88 < 90 (available threshold)
  });
});

describe('computeAuthority', () => {
  it('returns decision-ready for nominal state', () => {
    const result = computeAuthority(null, ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(84);
    expect(result.authority).toBe('decision-ready');
  });

  it('returns reference-only for low severity', () => {
    const result = computeAuthority('low', ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(72);
    expect(result.authority).toBe('reference-only');
  });

  it('returns invalid for med severity (score 58 < limited threshold 60)', () => {
  const result = computeAuthority('med', ENTERPRISE_STRICT_PROFILE);
  expect(result.score).toBe(58);
  expect(result.authority).toBe('invalid');
});

  it('returns invalid for high severity', () => {
    const result = computeAuthority('high', ENTERPRISE_STRICT_PROFILE);
    expect(result.score).toBe(22);
    expect(result.authority).toBe('invalid');
  });
});

describe('computeContainmentMetrics', () => {
  it('produces lower rawExposure when integrity is Available', () => {
    const highIntegrity = { level: 'Available' as const, score: 88 };
    const lowIntegrity = { level: 'Critical' as const, score: 29 };
    const high = computeContainmentMetrics(highIntegrity);
    const low = computeContainmentMetrics(lowIntegrity);
    expect(high.rawExposurePct).toBeLessThan(low.rawExposurePct);
  });

  it('always returns governedOutputPct < rawExposurePct', () => {
    const integrity = { level: 'Degraded' as const, score: 45 };
    const m = computeContainmentMetrics(integrity);
    expect(m.governedOutputPct).toBeLessThan(m.rawExposurePct);
  });

  it('clamps all values to 0–100', () => {
    for (const score of [0, 25, 50, 75, 100]) {
      const integrity = { level: 'Available' as const, score };
      const m = computeContainmentMetrics(integrity);
      for (const key of ['rawExposurePct', 'governedOutputPct', 'coreIsolationPct', 'contextDriftPressurePct'] as const) {
        expect(m[key]).toBeGreaterThanOrEqual(0);
        expect(m[key]).toBeLessThanOrEqual(100);
      }
    }
  });
});

describe('scoreToContinuityState', () => {
  it('returns STABLE when score >= stable threshold', () => {
    expect(scoreToContinuityState(80, ENTERPRISE_STRICT_PROFILE)).toBe('STABLE');
    expect(scoreToContinuityState(75, ENTERPRISE_STRICT_PROFILE)).toBe('STABLE');
  });

  it('returns PROVISIONAL when score >= provisional but < stable', () => {
    expect(scoreToContinuityState(65, ENTERPRISE_STRICT_PROFILE)).toBe('PROVISIONAL');
    expect(scoreToContinuityState(55, ENTERPRISE_STRICT_PROFILE)).toBe('PROVISIONAL');
  });

  it('returns UNSTABLE when score < provisional threshold', () => {
    expect(scoreToContinuityState(40, ENTERPRISE_STRICT_PROFILE)).toBe('UNSTABLE');
    expect(scoreToContinuityState(0, ENTERPRISE_STRICT_PROFILE)).toBe('UNSTABLE');
  });

  it('uses PILOT_PROFILE thresholds correctly', () => {
    // PILOT has stable=65, provisional=45
    expect(scoreToContinuityState(66, PILOT_PROFILE)).toBe('STABLE');
    expect(scoreToContinuityState(55, PILOT_PROFILE)).toBe('PROVISIONAL');
    expect(scoreToContinuityState(44, PILOT_PROFILE)).toBe('UNSTABLE');
  });
});
