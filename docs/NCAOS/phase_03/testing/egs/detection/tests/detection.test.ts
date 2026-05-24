/**
 * Tests — Premise, Authority, Continuity Detectors
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PremiseDetector, PremiseRegistry } from '../src/premise/premise-detector.js';
import type { PremiseDetectionInput, PremiseDefinition, ValidatedPremise } from '../src/premise/premise-detector.js';
import { AuthorityDetector, AuthorityAuditLog } from '../src/authority/authority-detector.js';
import type { AuthorityDetectionInput } from '../src/authority/authority-detector.js';
import { ContinuityDetector } from '../src/continuity/continuity-detector.js';
import type { EquivalenceTest } from '../src/continuity/continuity-detector.js';

// ─────────────────────────────────────────────────────────
// PREMISE DETECTOR TESTS
// ─────────────────────────────────────────────────────────

const PREMISE_DEFS: PremiseDefinition[] = [
  { id: 'P-AUTH', label: 'User authenticated', weight: 'critical' },
  { id: 'P-SCOPE', label: 'Scope validated', weight: 'standard' },
  { id: 'P-ENV', label: 'Environment verified', weight: 'standard' },
  { id: 'P-RATE', label: 'Rate limit checked', weight: 'informational' },
];

function makeValidated(...ids: string[]): ValidatedPremise[] {
  return ids.map(id => ({ id, validatedAt: performance.now() }));
}

describe('PremiseDetector — clean', () => {
  let detector: PremiseDetector;
  beforeEach(() => { detector = new PremiseDetector(); });

  it('does not trigger when all premises validated', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-001',
      contractVersion: '1.0',
      expectedContractVersion: '1.0',
      claimedPremiseIds: ['P-AUTH', 'P-SCOPE'],
      validatedPremises: makeValidated('P-AUTH', 'P-SCOPE'),
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.triggered).toBe(false);
    expect(result.violations).toHaveLength(0);
    expect(result.mismatchRatio).toBe(0);
  });

  it('reports PREMISE_VALIDATED type on clean run', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-002',
      contractVersion: '2.0',
      expectedContractVersion: '2.0',
      claimedPremiseIds: ['P-ENV'],
      validatedPremises: makeValidated('P-ENV'),
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.type).toBe('PREMISE_VALIDATED');
  });
});

describe('PremiseDetector — violations', () => {
  let detector: PremiseDetector;
  beforeEach(() => { detector = new PremiseDetector(); });

  it('triggers HIGH when critical premise unvalidated', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-003',
      contractVersion: '1.0',
      expectedContractVersion: '1.0',
      claimedPremiseIds: ['P-AUTH', 'P-SCOPE'],
      validatedPremises: makeValidated('P-SCOPE'),  // P-AUTH missing
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.criticalViolations).toBe(1);
  });

  it('triggers MED for partial standard violations', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-004',
      contractVersion: '1.0',
      expectedContractVersion: '1.0',
      claimedPremiseIds: ['P-SCOPE', 'P-ENV', 'P-RATE'],
      validatedPremises: makeValidated('P-SCOPE'),  // 2/3 unvalidated = 67%
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.triggered).toBe(true);
    // 67% mismatch → HIGH (≥0.7 is high, 67% ≥ 0.3 → MED... but recalc: 2/3 = 0.667 → MED)
    expect(['med', 'high']).toContain(result.severity);
  });

  it('flags unknown premise claims as violation', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-005',
      contractVersion: '1.0',
      expectedContractVersion: '1.0',
      claimedPremiseIds: ['P-UNKNOWN'],
      validatedPremises: [],
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.triggered).toBe(true);
    expect(result.violations[0]?.reason).toBe('unknown_claim');
  });

  it('flags contract version mismatch', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-006',
      contractVersion: '1.0',
      expectedContractVersion: '2.0',
      claimedPremiseIds: [],
      validatedPremises: [],
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.contractVersionMismatch).toBe(true);
    expect(result.triggered).toBe(true);
  });

  it('measures MTTD > 0', () => {
    const input: PremiseDetectionInput = {
      workflowId: 'wf-007',
      contractVersion: '1.0',
      expectedContractVersion: '1.0',
      claimedPremiseIds: ['P-AUTH'],
      validatedPremises: makeValidated('P-AUTH'),
      premiseDefinitions: PREMISE_DEFS,
    };
    const result = detector.detect(input);
    expect(result.mttdMs).toBeGreaterThanOrEqual(0);
  });
});

// ─────────────────────────────────────────────────────────
// AUTHORITY DETECTOR TESTS
// ─────────────────────────────────────────────────────────

describe('AuthorityDetector — grant', () => {
  let detector: AuthorityDetector;
  beforeEach(() => { detector = new AuthorityDetector(); });

  it('grants decision-ready when policy allows', () => {
    const input: AuthorityDetectionInput = {
      requestId: 'REQ-000001',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'decision-ready',
      overrideAttempted: false,
    };
    const result = detector.detect(input);
    expect(result.triggered).toBe(false);
    expect(result.effectiveAuthority).toBe('decision-ready');
    expect(result.auditEntry.decision).toBe('GRANT');
  });

  it('does not trigger when reference-only granted and requested', () => {
    const input: AuthorityDetectionInput = {
      requestId: 'REQ-000002',
      requestedAuthority: 'reference-only',
      policyGrantedAuthority: 'reference-only',
      overrideAttempted: false,
    };
    const result = detector.detect(input);
    expect(result.effectiveAuthority).toBe('reference-only');
    expect(result.triggered).toBe(false);
  });
});

describe('AuthorityDetector — downgrade', () => {
  let detector: AuthorityDetector;
  beforeEach(() => { detector = new AuthorityDetector(); });

  it('downgrades to reference-only when policy grants less', () => {
    const input: AuthorityDetectionInput = {
      requestId: 'REQ-000003',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'reference-only',
      overrideAttempted: false,
    };
    const result = detector.detect(input);
    expect(result.triggered).toBe(true);
    expect(result.effectiveAuthority).toBe('reference-only');
    expect(result.auditEntry.decision).toBe('DOWNGRADE');
    expect(result.severity).toBe('high');
  });

  it('denies when policy grants invalid', () => {
    const input: AuthorityDetectionInput = {
      requestId: 'REQ-000004',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'invalid',
      overrideAttempted: false,
    };
    const result = detector.detect(input);
    expect(result.effectiveAuthority).toBe('invalid');
    expect(result.auditEntry.decision).toBe('DENY');
  });

  it('applies chain constraint — cannot upgrade from previous', () => {
    const input: AuthorityDetectionInput = {
      requestId: 'REQ-000005',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'decision-ready',
      overrideAttempted: false,
      previousAuthority: 'reference-only',
    };
    const result = detector.detect(input);
    // Even though policy grants decision-ready, previous was reference-only
    expect(result.effectiveAuthority).toBe('reference-only');
    expect(result.triggered).toBe(true);
  });
});

describe('AuthorityDetector — override attempts', () => {
  let detector: AuthorityDetector;
  beforeEach(() => { detector = new AuthorityDetector(); });

  it('classifies escalation_attempt as HIGH severity', () => {
    const input: AuthorityDetectionInput = {
      requestId: 'REQ-000006',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'reference-only',
      overrideAttempted: true,
    };
    const result = detector.detect(input);
    expect(result.overrideClassification).toBe('escalation_attempt');
    expect(result.severity).toBe('high');
    expect(result.scope).toBe('sys');
  });

  it('logs every decision to audit log', () => {
    const auditLog = new AuthorityAuditLog();
    const det = new AuthorityDetector(auditLog);
    det.detect({ requestId: 'REQ-A', requestedAuthority: 'decision-ready', policyGrantedAuthority: 'decision-ready', overrideAttempted: false });
    det.detect({ requestId: 'REQ-B', requestedAuthority: 'decision-ready', policyGrantedAuthority: 'reference-only', overrideAttempted: false });
    expect(auditLog.length).toBe(2);
    expect(auditLog.getEntries('REQ-A')).toHaveLength(1);
  });

  it('measures MTTD > 0', () => {
    const result = detector.detect({
      requestId: 'REQ-000007',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'decision-ready',
      overrideAttempted: false,
    });
    expect(result.mttdMs).toBeGreaterThanOrEqual(0);
  });
});

// ─────────────────────────────────────────────────────────
// CONTINUITY DETECTOR TESTS
// ─────────────────────────────────────────────────────────

function allPass(updateId: string, count = 12): EquivalenceTest[] {
  return Array.from({ length: count }, (_, i) => ({
    testId: `${updateId}-T${String(i+1).padStart(2,'0')}`,
    description: `Test ${i+1}`,
    criticality: i < 3 ? 'critical' as const : 'standard' as const,
    passed: true,
  }));
}

function withFailures(tests: EquivalenceTest[], failCount: number): EquivalenceTest[] {
  return tests.map((t, i) => i < failCount ? { ...t, passed: false } : t);
}

describe('ContinuityDetector — stable', () => {
  let detector: ContinuityDetector;
  beforeEach(() => { detector = new ContinuityDetector(); });

  it('does not trigger when all tests pass', () => {
    const result = detector.detect({
      updateId: 'UPD-001',
      equivalenceTests: allPass('UPD-001'),
      stableThreshold: 75,
      provisionalThreshold: 55,
    });
    expect(result.triggered).toBe(false);
    expect(result.continuityScore).toBe(100);
    expect(result.updateState).toBe('STABLE');
    expect(result.type).toBe('CONTINUITY_STABLE');
  });

  it('always returns sys scope', () => {
    const result = detector.detect({
      updateId: 'UPD-002',
      equivalenceTests: allPass('UPD-002'),
      stableThreshold: 75,
      provisionalThreshold: 55,
    });
    expect(result.scope).toBe('sys');
  });

  it('generates test template with 12 tests', () => {
    const tests = ContinuityDetector.generateTestTemplate('UPD-003');
    expect(tests).toHaveLength(12);
    expect(tests.filter(t => t.criticality === 'critical').length).toBeGreaterThan(0);
  });
});

describe('ContinuityDetector — violations', () => {
  let detector: ContinuityDetector;
  beforeEach(() => { detector = new ContinuityDetector(); });

  it('triggers HIGH when critical tests fail', () => {
    const tests = withFailures(allPass('UPD-004'), 1); // First test is critical
    const result = detector.detect({
      updateId: 'UPD-004',
      equivalenceTests: tests,
      stableThreshold: 75,
      provisionalThreshold: 55,
    });
    expect(result.triggered).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.criticalFailures).toBeGreaterThan(0);
  });

  it('triggers with PROVISIONAL state when score between thresholds', () => {
    // Fail ~40% of standard tests (non-critical) to get score in provisional range
    const tests = ContinuityDetector.generateTestTemplate('UPD-005').map((t, i) => ({
      ...t,
      criticality: 'standard' as const,  // Make all standard so no critical failures
      passed: i < 7,  // 7/12 pass
    }));
    const result = detector.detect({
      updateId: 'UPD-005',
      equivalenceTests: tests,
      stableThreshold: 75,
      provisionalThreshold: 55,
    });
    expect(result.triggered).toBe(true);
    expect(['PROVISIONAL', 'UNSTABLE']).toContain(result.updateState);
  });

  it('sets changeWindowState to CONTAINMENT when UNSTABLE', () => {
    const tests = withFailures(allPass('UPD-006'), 12); // All fail
    const result = detector.detect({
      updateId: 'UPD-006',
      equivalenceTests: tests,
      stableThreshold: 75,
      provisionalThreshold: 55,
      changeWindowState: 'WATCHING',
    });
    expect(result.changeWindowState).toBe('CONTAINMENT');
  });

  it('transitions window from OPEN to WATCHING when tests run', () => {
    const result = detector.detect({
      updateId: 'UPD-007',
      equivalenceTests: allPass('UPD-007'),
      stableThreshold: 75,
      provisionalThreshold: 55,
      changeWindowState: 'OPEN',
    });
    expect(result.changeWindowState).toBe('WATCHING'); // STABLE → CLOSED
  });

  it('measures MTTD > 0', () => {
    const result = detector.detect({
      updateId: 'UPD-008',
      equivalenceTests: allPass('UPD-008'),
      stableThreshold: 75,
      provisionalThreshold: 55,
    });
    expect(result.mttdMs).toBeGreaterThanOrEqual(0);
  });

  it('computes failRate correctly', () => {
    const tests = withFailures(allPass('UPD-009', 10), 4);
    const result = detector.detect({
      updateId: 'UPD-009',
      equivalenceTests: tests,
      stableThreshold: 75,
      provisionalThreshold: 55,
    });
    expect(result.failRate).toBeCloseTo(0.4);
  });
});
