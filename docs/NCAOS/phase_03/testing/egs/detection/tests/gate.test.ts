/**
 * Tests — Gate Detector
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { GateDetector, DEFAULT_GATE_RULES } from '../src/gate/gate-detector.js';
import type { GateDetectionInput } from '../src/gate/gate-detector.js';

const CLEAN_INPUT: GateDetectionInput = {
  sourceId: 'src-trusted-001',
  inputHash: 'abc123',
  inputFlags: [],
};

describe('GateDetector — clean input', () => {
  let detector: GateDetector;
  beforeEach(() => { detector = new GateDetector(); });

  it('does not trigger on clean input', () => {
    const result = detector.detect(CLEAN_INPUT);
    expect(result.triggered).toBe(false);
    expect(result.type).toBe('GATE_CLEAR');
    expect(result.matchedRules).toHaveLength(0);
    expect(result.dominantRule).toBeNull();
  });

  it('returns low severity on clean input', () => {
    const result = detector.detect(CLEAN_INPUT);
    expect(result.severity).toBe('low');
  });

  it('measures MTTD > 0', () => {
    const result = detector.detect(CLEAN_INPUT);
    expect(result.mttdMs).toBeGreaterThanOrEqual(0);
  });

  it('sets layer to gate and detectionMode correctly', () => {
    const result = detector.detect(CLEAN_INPUT);
    expect(result.layer).toBe('gate');
    expect(result.detectionMode).toBe('Real-time Gate Enforcement');
  });
});

describe('GateDetector — critical flags', () => {
  let detector: GateDetector;
  beforeEach(() => { detector = new GateDetector(); });

  it('triggers HIGH severity for INJECTION_PATTERN', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['INJECTION_PATTERN'] });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');
    expect(result.type).toBe('EXTERNAL_THREAT_BLOCKED');
  });

  it('triggers HIGH for SIGNATURE_INVALID', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['SIGNATURE_INVALID'] });
    expect(result.severity).toBe('high');
    expect(result.dominantRule?.id).toBe('G-C-002');
  });

  it('triggers HIGH for KNOWN_BAD_SOURCE', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['KNOWN_BAD_SOURCE'] });
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');
  });

  it('triggers HIGH for REPLAY_ATTACK', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['REPLAY_ATTACK'] });
    expect(result.severity).toBe('high');
  });

  it('triggers HIGH for TAMPERED_PAYLOAD', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['TAMPERED_PAYLOAD'] });
    expect(result.severity).toBe('high');
  });

  it('critical flag wins over warning flag in same request', () => {
    const result = detector.detect({
      ...CLEAN_INPUT,
      inputFlags: ['RATE_EXCEEDED', 'INJECTION_PATTERN'],
    });
    expect(result.severity).toBe('high');
    expect(result.dominantRule?.priority).toBe('critical');
  });
});

describe('GateDetector — warning flags', () => {
  let detector: GateDetector;
  beforeEach(() => { detector = new GateDetector(); });

  it('triggers MED severity for RATE_EXCEEDED', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['RATE_EXCEEDED'] });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('med');
    expect(result.scope).toBe('req');
  });

  it('triggers MED for GEO_MISMATCH', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['GEO_MISMATCH'] });
    expect(result.severity).toBe('med');
  });

  it('triggers MED for SCHEMA_VIOLATION with flow scope', () => {
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['SCHEMA_VIOLATION'] });
    expect(result.severity).toBe('med');
    expect(result.scope).toBe('flow');
  });

  it('matches multiple warning rules', () => {
    const result = detector.detect({
      ...CLEAN_INPUT,
      inputFlags: ['RATE_EXCEEDED', 'GEO_MISMATCH'],
    });
    expect(result.matchedRules.length).toBeGreaterThanOrEqual(2);
  });
});

describe('GateDetector — source allowlist', () => {
  let detector: GateDetector;
  beforeEach(() => { detector = new GateDetector(); });

  it('auto-adds UNRECOGNIZED_SOURCE when source not in allowlist', () => {
    const result = detector.detect({
      ...CLEAN_INPUT,
      sourceId: 'unknown-src',
      allowedSources: ['src-trusted-001', 'src-trusted-002'],
    });
    expect(result.triggered).toBe(true);
    expect(result.matchedRules.some(r => r.pattern === 'UNRECOGNIZED_SOURCE')).toBe(true);
  });

  it('does not trigger UNRECOGNIZED_SOURCE for known source', () => {
    const result = detector.detect({
      ...CLEAN_INPUT,
      sourceId: 'src-trusted-001',
      allowedSources: ['src-trusted-001'],
    });
    expect(result.triggered).toBe(false);
  });
});

describe('GateDetector — custom rules', () => {
  it('accepts and applies custom rule', () => {
    const detector = new GateDetector([]);
    detector.addRule({
      id: 'CUSTOM-001',
      pattern: 'MY_CUSTOM_FLAG',
      priority: 'critical',
      scope: 'sys',
      description: 'Custom critical rule',
    });
    const result = detector.detect({ ...CLEAN_INPUT, inputFlags: ['MY_CUSTOM_FLAG'] });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.dominantRule?.id).toBe('CUSTOM-001');
  });

  it('returns all rules via getRules()', () => {
    const detector = new GateDetector();
    const rules = detector.getRules();
    expect(rules.length).toBe(DEFAULT_GATE_RULES.length);
  });
});
