/**
 * Tests — STRIDE Threat Model
 */

import { describe, it, expect } from 'vitest';
import { STRIDE_THREATS } from '../src/stride/stride-model.js';

describe('STRIDE Threat Model', () => {
  it('has at least 15 threats documented', () => {
    expect(STRIDE_THREATS.length).toBeGreaterThanOrEqual(15);
  });

  it('covers all six STRIDE categories', () => {
    const categories = new Set(STRIDE_THREATS.map(t => t.category));
    expect(categories.has('Spoofing')).toBe(true);
    expect(categories.has('Tampering')).toBe(true);
    expect(categories.has('Repudiation')).toBe(true);
    expect(categories.has('InformationDisclosure')).toBe(true);
    expect(categories.has('DenialOfService')).toBe(true);
    expect(categories.has('ElevationOfPrivilege')).toBe(true);
  });

  it('all HIGH risk threats have a Phase 06 action defined', () => {
    const highWithoutAction = STRIDE_THREATS.filter(
      t => t.residualRisk === 'HIGH' && !t.phase06Action
    );
    expect(highWithoutAction).toHaveLength(0);
  });

  it('all HIGH risk threats have a test reference', () => {
    const highWithoutTest = STRIDE_THREATS.filter(
      t => t.residualRisk === 'HIGH' && !t.testRef
    );
    expect(highWithoutTest).toHaveLength(0);
  });

  it('threat IDs are unique', () => {
    const ids = STRIDE_THREATS.map(t => t.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('identifies S-001 (tenant spoofing) as HIGH risk', () => {
    const s001 = STRIDE_THREATS.find(t => t.id === 'S-001');
    expect(s001).toBeDefined();
    expect(s001?.residualRisk).toBe('HIGH');
    expect(s001?.testRef).toBe('PT-001');
  });

  it('identifies D-001 (DoS) as HIGH risk', () => {
    const d001 = STRIDE_THREATS.find(t => t.id === 'D-001');
    expect(d001).toBeDefined();
    expect(d001?.residualRisk).toBe('HIGH');
  });

  it('identifies E-001 (policy privilege escalation) as HIGH risk', () => {
    const e001 = STRIDE_THREATS.find(t => t.id === 'E-001');
    expect(e001).toBeDefined();
    expect(e001?.residualRisk).toBe('HIGH');
  });
});
