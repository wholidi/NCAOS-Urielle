/**
 * Unit tests — Detection Layers
 *
 * Validates all four containment layer detection functions.
 * Each test ensures the correct severity, scope, and type are returned
 * for the input conditions described in the Architecture Interpretation Guide.
 */

import { describe, it, expect } from 'vitest';
import {
  detectGate,
  detectPremise,
  detectAuthority,
  detectContinuity,
} from '../../src/detection/layers.js';

// ─────────────────────────────────────────────────────────
// LAYER 1: EXTERNAL GATE
// ─────────────────────────────────────────────────────────

describe('detectGate', () => {
  it('triggers HIGH severity for critical flags', () => {
    const result = detectGate({
      sourceId: 'src-001',
      inputHash: 'abc123',
      flags: ['INJECTION_PATTERN'],
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');
    expect(result.type).toBe('EXTERNAL_THREAT_BLOCKED');
    expect(result.layer).toBe('gate');
    expect(result.detectionMode).toBe('Real-time Gate Enforcement');
  });

  it('triggers MED severity for warning flags', () => {
    const result = detectGate({
      sourceId: 'src-002',
      inputHash: 'def456',
      flags: ['RATE_EXCEEDED'],
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('med');
    expect(result.scope).toBe('req');
  });

  it('does not trigger for clean input', () => {
    const result = detectGate({
      sourceId: 'src-003',
      inputHash: 'clean-hash',
      flags: [],
    });
    expect(result.triggered).toBe(false);
    expect(result.severity).toBe('low');
  });

  it('prefers critical over warning flags', () => {
    const result = detectGate({
      sourceId: 'src-004',
      inputHash: 'mixed',
      flags: ['RATE_EXCEEDED', 'SIGNATURE_INVALID'],
    });
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');
  });

  it('includes MTTD measurement > 0', () => {
    const result = detectGate({ sourceId: 's', inputHash: 'h', flags: [] });
    expect(typeof result.mttdMs).toBe('number');
    expect(result.mttdMs).toBeGreaterThanOrEqual(0);
  });
});

// ─────────────────────────────────────────────────────────
// LAYER 2: PREMISE CONSISTENCY
// ─────────────────────────────────────────────────────────

describe('detectPremise', () => {
  it('triggers HIGH severity when most premises are unvalidated', () => {
    const result = detectPremise({
      workflowId: 'wf-001',
      contractVersion: '1.0',
      claimedPremises: ['A', 'B', 'C', 'D', 'E'],
      validatedPremises: ['A'],  // 80% unvalidated
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('flow');
    expect(result.type).toBe('PREMISE_MISMATCH');
  });

  it('triggers MED severity for partial mismatch', () => {
    const result = detectPremise({
      workflowId: 'wf-002',
      contractVersion: '1.0',
      claimedPremises: ['A', 'B', 'C'],
      validatedPremises: ['A', 'B'],  // ~33% unvalidated
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('med');
    expect(result.scope).toBe('req');
  });

  it('does not trigger when all premises validated', () => {
    const result = detectPremise({
      workflowId: 'wf-003',
      contractVersion: '1.0',
      claimedPremises: ['A', 'B'],
      validatedPremises: ['A', 'B'],
    });
    expect(result.triggered).toBe(false);
  });

  it('does not trigger when no premises claimed', () => {
    const result = detectPremise({
      workflowId: 'wf-004',
      contractVersion: '1.0',
      claimedPremises: [],
      validatedPremises: [],
    });
    expect(result.triggered).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────
// LAYER 3: AUTHORITY BOUNDARY
// ─────────────────────────────────────────────────────────

describe('detectAuthority', () => {
  it('triggers HIGH severity on override attempt', () => {
    const result = detectAuthority({
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'reference-only',
      overrideAttempted: true,
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');
    expect(result.type).toBe('AUTHORITY_REVOKED');
  });

  it('triggers MED severity on legitimate downgrade (no override)', () => {
    const result = detectAuthority({
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'reference-only',
      overrideAttempted: false,
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('med');
    expect(result.scope).toBe('req');
  });

  it('does not trigger when policy grants decision-ready', () => {
    const result = detectAuthority({
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'decision-ready',
      overrideAttempted: false,
    });
    expect(result.triggered).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────
// LAYER 4: CONTINUITY WATCH
// ─────────────────────────────────────────────────────────

describe('detectContinuity', () => {
  it('triggers HIGH when many equivalence tests fail', () => {
    const result = detectContinuity({
      updateId: 'upd-001',
      equivalenceTestResults: Array.from({ length: 10 }, (_, i) => ({
        testId: `t${i}`,
        passed: i < 4,  // 60% fail rate
      })),
      continuityScore: 40,
      stableThreshold: 75,
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');  // Always sys for continuity
    expect(result.type).toBe('CONTINUITY_VIOLATION');
  });

  it('triggers MED for moderate continuity degradation', () => {
    const result = detectContinuity({
      updateId: 'upd-002',
      equivalenceTestResults: Array.from({ length: 12 }, (_, i) => ({
        testId: `t${i}`,
        passed: i < 11,  // 1 failure (~8%)
      })),
      continuityScore: 68,
      stableThreshold: 75,
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('med');
  });

  it('does not trigger when continuity is above stable threshold and all tests pass', () => {
    const result = detectContinuity({
      updateId: 'upd-003',
      equivalenceTestResults: Array.from({ length: 12 }, (_, i) => ({
        testId: `t${i}`,
        passed: true,
      })),
      continuityScore: 91,
      stableThreshold: 75,
    });
    expect(result.triggered).toBe(false);
  });

  it('always returns scope sys regardless of severity', () => {
    const result = detectContinuity({
      updateId: 'upd-004',
      equivalenceTestResults: [{ testId: 't0', passed: false }],
      continuityScore: 60,
      stableThreshold: 75,
    });
    expect(result.scope).toBe('sys');
  });
});
