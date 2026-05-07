/**
 * Unit tests — PolicyStore + TenantDetectorRegistry
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyStore } from '../src/store/policy-store.js';
import { TenantDetectorRegistry } from '../src/detectors/tenant-registry.js';
import { ENTERPRISE_STRICT_PROFILE, PILOT_PROFILE, CRITICAL_STRICT_PROFILE } from '@ncaos/core';

// ─────────────────────────────────────────────────────────
// POLICY STORE TESTS
// ─────────────────────────────────────────────────────────

describe('PolicyStore', () => {
  let store: PolicyStore;
  beforeEach(() => { store = new PolicyStore(); });

  it('returns ENTERPRISE_STRICT as default for unknown tenant', () => {
    const policy = store.getActive('NEW_TENANT');
    expect(policy.profileId).toBe('STRICT-PROD');
  });

  it('accepts a valid policy update', () => {
    const result = store.setActive('TENANT_A', PILOT_PROFILE);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.policy.profileId).toBe('PILOT-OBS');
    }
    expect(store.getActive('TENANT_A').profileId).toBe('PILOT-OBS');
  });

  it('rejects invalid policy schema', () => {
    const result = store.setActive('TENANT_A', { bad: 'data' });
    expect(result.success).toBe(false);
  });

  it('rejects policy with inconsistent thresholds', () => {
    const bad = {
      ...ENTERPRISE_STRICT_PROFILE,
      integrityThresholds: { available: 60, limited: 80, degraded: 40 }, // available < limited
    };
    const result = store.setActive('TENANT_A', bad);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it('records policy history', () => {
    store.setActive('TENANT_A', ENTERPRISE_STRICT_PROFILE);
    store.setActive('TENANT_A', PILOT_PROFILE);
    store.setActive('TENANT_A', CRITICAL_STRICT_PROFILE);
    const history = store.getHistory('TENANT_A');
    expect(history.length).toBeGreaterThanOrEqual(1);
  });

  it('emits policy:changed event', () => {
    return new Promise<void>((resolve) => {
      store.on('policy:changed', ({ partnerId, policy }) => {
        expect(partnerId).toBe('TENANT_B');
        expect(policy.profileId).toBe('PILOT-OBS');
        resolve();
      });
      store.setActive('TENANT_B', PILOT_PROFILE);
    });
  });

  it('keeps policies isolated per tenant', () => {
    store.setActive('TENANT_A', PILOT_PROFILE);
    store.setActive('TENANT_B', CRITICAL_STRICT_PROFILE);
    expect(store.getActive('TENANT_A').profileId).toBe('PILOT-OBS');
    expect(store.getActive('TENANT_B').profileId).toBe('CRITICAL-STRICT');
  });

  it('resets to default policy', () => {
    store.setActive('TENANT_A', PILOT_PROFILE);
    store.reset('TENANT_A');
    expect(store.getActive('TENANT_A').profileId).toBe('STRICT-PROD');
  });
});

// ─────────────────────────────────────────────────────────
// TENANT DETECTOR REGISTRY TESTS
// ─────────────────────────────────────────────────────────

describe('TenantDetectorRegistry', () => {
  let registry: TenantDetectorRegistry;

  beforeEach(() => {
    registry = new TenantDetectorRegistry(() => ENTERPRISE_STRICT_PROFILE);
  });

  it('creates a detector set for a new tenant', () => {
    const set = registry.get('TENANT_A');
    expect(set.partnerId).toBe('TENANT_A');
    expect(set.gate).toBeDefined();
    expect(set.premise).toBeDefined();
    expect(set.authority).toBeDefined();
    expect(set.continuity).toBeDefined();
    expect(set.mttdRegistry).toBeDefined();
  });

  it('returns the same instance on subsequent calls', () => {
    const set1 = registry.get('TENANT_A');
    const set2 = registry.get('TENANT_A');
    expect(set1).toBe(set2);
  });

  it('creates independent instances per tenant', () => {
    const setA = registry.get('TENANT_A');
    const setB = registry.get('TENANT_B');
    expect(setA.gate).not.toBe(setB.gate);
    expect(setA.mttdRegistry).not.toBe(setB.mttdRegistry);
  });

  it('resets a tenant detector set', () => {
    const set1 = registry.get('TENANT_A');
    const set2 = registry.reset('TENANT_A');
    expect(set1).not.toBe(set2);
  });

  it('returns MTTD stats for all four layers', () => {
    const stats = registry.mttdStats('TENANT_A');
    expect(stats).toHaveLength(4);
    const layers = stats.map(s => s.layer);
    expect(layers).toContain('gate');
    expect(layers).toContain('premise');
    expect(layers).toContain('authority');
    expect(layers).toContain('continuity');
  });

  it('reports SLA healthy when no samples recorded', () => {
    expect(registry.isSlaHealthy('TENANT_A')).toBe(true);
  });

  it('tracks active tenant count', () => {
    expect(registry.activeTenantCount()).toBe(0);
    registry.get('TENANT_A');
    registry.get('TENANT_B');
    expect(registry.activeTenantCount()).toBe(2);
  });

  it('uses policy SLA values in MTTD registry', () => {
    const stats = registry.mttdStats('TENANT_A');
    const gateStats = stats.find(s => s.layer === 'gate');
    expect(gateStats?.slaMs).toBe(ENTERPRISE_STRICT_PROFILE.mttdSlaMs.gate);
  });
});
