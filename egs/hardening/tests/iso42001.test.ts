/**
 * Tests — ISO 42001 Control Mapping
 */

import { describe, it, expect } from 'vitest';
import {
  ISO42001_CONTROLS,
  iso42001Summary,
  controlsByClause,
} from '../src/iso42001/iso42001-mapping.js';
import { PEN_TEST_SCENARIOS, penTestSummary } from '../src/pentest/pentest-scenarios.js';
import { AIML_THREATS } from '../src/aiml/aiml-threat-model.js';

describe('ISO 42001 Control Mapping', () => {
  it('has at least 12 controls documented', () => {
    expect(ISO42001_CONTROLS.length).toBeGreaterThanOrEqual(12);
  });

  it('covers clauses 6, 8, 9, and 10', () => {
    const ids = ISO42001_CONTROLS.map(c => c.id);
    expect(ids.some(id => id.startsWith('6.'))).toBe(true);
    expect(ids.some(id => id.startsWith('8.'))).toBe(true);
    expect(ids.some(id => id.startsWith('9.'))).toBe(true);
    expect(ids.some(id => id.startsWith('10.'))).toBe(true);
  });

  it('all controls have evidenceSource defined', () => {
    const missing = ISO42001_CONTROLS.filter(c => !c.evidenceSource);
    expect(missing).toHaveLength(0);
  });

  it('all IMPLEMENTED controls have an API endpoint or component', () => {
    const implemented = ISO42001_CONTROLS.filter(c => c.status === 'IMPLEMENTED');
    const missingBoth = implemented.filter(c => !c.apiEndpoint && !c.egsComponent);
    expect(missingBoth).toHaveLength(0);
  });

  it('coverage is at least 70%', () => {
    const summary = iso42001Summary();
    expect(summary.coveragePercent).toBeGreaterThanOrEqual(70);
  });

  it('control IDs are unique', () => {
    const ids = ISO42001_CONTROLS.map(c => c.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('controlsByClause groups correctly', () => {
    const grouped = controlsByClause();
    expect(grouped['6']).toBeDefined();
    expect(grouped['8']).toBeDefined();
    expect(grouped['9']).toBeDefined();
    expect(grouped['10']).toBeDefined();
  });

  it('critical controls (8.4, 9.1, 9.2) are IMPLEMENTED', () => {
    const critical = ['8.4', '9.1', '9.2'];
    for (const id of critical) {
      const ctrl = ISO42001_CONTROLS.find(c => c.id === id);
      expect(ctrl).toBeDefined();
      expect(ctrl?.status).toBe('IMPLEMENTED');
    }
  });
});

describe('Pen Test Scenarios', () => {
  it('has 11 scenarios (10 + chaos test)', () => {
    expect(PEN_TEST_SCENARIOS.length).toBe(11);
  });

  it('covers HIGH severity tests', () => {
    const high = PEN_TEST_SCENARIOS.filter(s => s.severity === 'HIGH');
    expect(high.length).toBeGreaterThanOrEqual(4);
  });

  it('includes chaos test (PT-CHAOS-001)', () => {
    const chaos = PEN_TEST_SCENARIOS.find(s => s.id === 'PT-CHAOS-001');
    expect(chaos).toBeDefined();
    expect(chaos?.strideRef).toBe('ADR-002');
  });

  it('all scenarios have pass criteria defined', () => {
    const missing = PEN_TEST_SCENARIOS.filter(s => s.passCriteria.length === 0);
    expect(missing).toHaveLength(0);
  });

  it('all HIGH scenarios have PowerShell commands', () => {
    const highWithoutCmd = PEN_TEST_SCENARIOS.filter(
      s => s.severity === 'HIGH' && !s.psCommand
    );
    expect(highWithoutCmd).toHaveLength(0);
  });

  it('penTestSummary returns correct totals', () => {
    const summary = penTestSummary();
    expect(summary.total).toBe(11);
    expect(summary.highRiskCount).toBeGreaterThanOrEqual(4);
  });

  it('all scenarios have STRIDE reference', () => {
    const missing = PEN_TEST_SCENARIOS.filter(s => !s.strideRef);
    expect(missing).toHaveLength(0);
  });
});

describe('AI/ML Threat Model', () => {
  it('has threats defined', () => {
    expect(AIML_THREATS.length).toBeGreaterThan(0);
  });

  it('covers model drift threats', () => {
    const drift = AIML_THREATS.find(t => t.category === 'ModelDrift');
    expect(drift).toBeDefined();
  });

  it('covers adversarial input threats', () => {
    const adversarial = AIML_THREATS.find(t => t.category === 'AdversarialInput');
    expect(adversarial).toBeDefined();
  });

  it('all threats have EGS mitigation defined', () => {
    const missing = AIML_THREATS.filter(t => !t.egsMitigation);
    expect(missing).toHaveLength(0);
  });
});
