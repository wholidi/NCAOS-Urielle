/**
 * Unit tests — Verdict Engine & Policy Loader
 *
 * Validates the Enforcer's action resolution across all govLevel × severity combinations.
 * Also validates policy loading and consistency checks.
 */

import { describe, it, expect } from 'vitest';
import { enforce, failSafeVerdict } from '../../src/engine/verdict.js';
import {
  loadPolicy,
  validatePolicyConsistency,
  ENTERPRISE_STRICT_PROFILE,
  CRITICAL_STRICT_PROFILE,
  PILOT_PROFILE,
} from '../../src/policy/loader.js';
import type { GovEvent } from '../../src/types/contracts.js';

// ─────────────────────────────────────────────────────────
// TEST FIXTURE
// ─────────────────────────────────────────────────────────

function makeEvent(overrides: Partial<GovEvent> = {}): GovEvent {
  return {
    requestId: 'REQ-000001',
    evidenceHandle: 'EVD-1700000000000-ABCD1234',
    tenant: {
      partnerId: 'GLOBAL_ENT_2026',
      instanceId: 'EGS_INST_001',
      deployment: 'ENTERPRISE',
    },
    type: 'EXTERNAL_THREAT_BLOCKED',
    layer: 'gate',
    scope: 'req',
    severity: 'low',
    detectionMode: 'Real-time Gate Enforcement',
    integrity: { level: 'Limited', score: 74 },
    authority: { authority: 'reference-only', score: 72 },
    routing: {
      hint: 'SOC / Security Queue',
      recommendedAction: 'Isolate inputs; validate perimeter.',
    },
    detectedAt: new Date().toISOString(),
    mttdMs: 12,
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────
// VERDICT ENGINE
// ─────────────────────────────────────────────────────────

describe('enforce — ENTERPRISE_STRICT govLevel', () => {
  it('returns PASS for low severity with blockOnContainment=false', () => {
    const policy = { ...ENTERPRISE_STRICT_PROFILE, blockOnContainment: false };
    const v = enforce(makeEvent({ severity: 'low' }), policy);
    expect(v.action).toBe('PASS');
  });

  it('returns DOWNGRADE for low severity', () => {
    const v = enforce(makeEvent({ severity: 'low' }), ENTERPRISE_STRICT_PROFILE);
    expect(v.action).toBe('DOWNGRADE');
    expect(v.authority).toBe('reference-only');
  });

  it('returns BLOCK for med severity', () => {
    const v = enforce(makeEvent({ severity: 'med' }), ENTERPRISE_STRICT_PROFILE);
    expect(v.action).toBe('BLOCK');
    expect(v.authority).toBe('invalid');
  });

  it('returns BLOCK for high severity', () => {
    const v = enforce(makeEvent({ severity: 'high' }), ENTERPRISE_STRICT_PROFILE);
    expect(v.action).toBe('BLOCK');
    expect(v.authority).toBe('invalid');
  });

  it('includes routing on non-PASS verdicts', () => {
    const v = enforce(makeEvent({ severity: 'high' }), ENTERPRISE_STRICT_PROFILE);
    expect(v.routing).toBeDefined();
    expect(v.routing?.hint).toBe('SOC / Security Queue');
  });

  it('does not include routing on PASS verdicts', () => {
    const policy = { ...ENTERPRISE_STRICT_PROFILE, blockOnContainment: false };
    const v = enforce(makeEvent({ severity: 'low' }), policy);
    expect(v.routing).toBeUndefined();
  });
});

describe('enforce — CRITICAL_STRICT govLevel', () => {
  it('returns BLOCK for all severities', () => {
    for (const severity of ['low', 'med', 'high'] as const) {
      const v = enforce(makeEvent({ severity }), CRITICAL_STRICT_PROFILE);
      expect(v.action).toBe('BLOCK');
    }
  });
});

describe('enforce — PILOT govLevel', () => {
  it('returns PASS for low and med severity', () => {
    for (const severity of ['low', 'med'] as const) {
      const v = enforce(makeEvent({ severity }), PILOT_PROFILE);
      expect(v.action).toBe('PASS');
    }
  });

  it('returns DOWNGRADE for high severity', () => {
    const v = enforce(makeEvent({ severity: 'high' }), PILOT_PROFILE);
    expect(v.action).toBe('DOWNGRADE');
    expect(v.authority).toBe('reference-only');
  });
});

describe('failSafeVerdict', () => {
  it('always returns FAIL_SAFE action with invalid authority', () => {
    const v = failSafeVerdict('REQ-000001', 'STRICT-PROD');
    expect(v.action).toBe('FAIL_SAFE');
    expect(v.authority).toBe('invalid');
    expect(v.integrity.level).toBe('Critical');
    expect(v.integrity.score).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────
// POLICY LOADER
// ─────────────────────────────────────────────────────────

describe('validatePolicyConsistency', () => {
  it('passes for a valid builtin policy', () => {
    const result = validatePolicyConsistency(ENTERPRISE_STRICT_PROFILE);
    expect(result.valid).toBe(true);
  });

  it('fails when available <= limited', () => {
    const bad = {
      ...ENTERPRISE_STRICT_PROFILE,
      integrityThresholds: { available: 60, limited: 60, degraded: 40 },
    };
    const result = validatePolicyConsistency(bad);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some((e) => e.includes('available'))).toBe(true);
    }
  });

  it('fails when stable <= provisional', () => {
    const bad = {
      ...ENTERPRISE_STRICT_PROFILE,
      continuityThresholds: { stable: 55, provisional: 55 },
    };
    const result = validatePolicyConsistency(bad);
    expect(result.valid).toBe(false);
  });
});

describe('loadPolicy', () => {
  it('parses a valid raw policy object', () => {
    const raw = { ...ENTERPRISE_STRICT_PROFILE };
    const policy = loadPolicy(raw);
    expect(policy.profileId).toBe('STRICT-PROD');
  });

  it('throws on invalid raw input', () => {
    expect(() => loadPolicy({ profileId: 123 })).toThrow();
  });
});
