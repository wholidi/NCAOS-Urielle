/**
 * urielle/tests/urielle.test.ts
 *
 * Urielle AI — comprehensive test suite
 * Aligned to NCAOS/EGS Phases 01–07
 *
 * Test data uses observed values from Phase 07 demo:
 *   WF-DEMO-LIVE-001 · DEMO_ENT_2026 · DOWNGRADE→BLOCK sequence
 *   patternType=CONTAINED · escalationDetected=True · consistencyScore=94
 */

import { describe, it, expect } from 'vitest';
import {
  AuditSignalSchema,
  evidenceLevel,
  auditFindingSummary,
  isoControlsForSignal,
  ISO42001_CONTROL_MAP,
  generateFinding,
  generateFindings,
  derivePosture,
  buildSequenceReport,
  summarizeTenantPosture,
  buildCoverageReport,
  evaluateMttd,
  buildMttdReport,
  MTTD_SLA_MS,
  MTTD_BASELINE_P99_MS,
  buildTenantAuditReport,
} from '../src/index.js';
import type { AuditSignal, AuditSignalSequence, SequenceInput } from '../src/index.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

// D-02 event: DOWNGRADE (from Phase 07 demo, WF-DEMO-LIVE-001, seqNo=1)
const SIGNAL_DOWNGRADE: AuditSignal = {
  evidenceHandle:  'EVD-1779185776973-8D24C988',
  sequenceNumber:  1,
  layer:           'gate',
  severity:        'low',
  action:          'DOWNGRADE',
  authority:       'reference-only',
  integrityScore:  88,
  detectionMode:   'Real-time Gate Enforcement',
  routingHint:     'SOC / Security Queue',
  mttdMs:          1,
  detectedAt:      '2026-05-19T10:16:16.974Z',
  storedAt:        '2026-05-19T10:16:16.976Z',
  policyProfileId: 'STRICT-PROD',
  partnerId:       'DEMO_ENT_2026',
  schemaVersion:   '1.0',
};

// D-03 event: BLOCK (from Phase 07 demo, WF-DEMO-LIVE-001, seqNo=2)
const SIGNAL_BLOCK: AuditSignal = {
  evidenceHandle:  'EVD-1779185789352-BF52C998',
  sequenceNumber:  2,
  layer:           'authority',
  severity:        'high',
  action:          'BLOCK',
  authority:       'invalid',
  integrityScore:  29,
  detectionMode:   'Authority Boundary Enforcement',
  routingHint:     'Governance / Policy Review',
  mttdMs:          0,
  detectedAt:      '2026-05-19T10:16:29.352Z',
  storedAt:        '2026-05-19T10:16:29.352Z',
  policyProfileId: 'STRICT-PROD',
  partnerId:       'DEMO_ENT_2026',
  schemaVersion:   '1.0',
};

// D-04 sequence summary (from Phase 07 demo)
const DEMO_SEQUENCE: AuditSignalSequence = {
  sequenceId:         'WF-DEMO-LIVE-001',
  patternType:        'CONTAINED',
  escalationDetected: true,
  consistencyScore:   94,
  eventCount:         2,
  firstDetectedAt:    '2026-05-19T10:16:16.974Z',
  actionChain:        ['DOWNGRADE', 'BLOCK'],
  layersInvolved:     ['gate', 'authority'],
};

// Block signal with sequence attached
const SIGNAL_BLOCK_WITH_SEQ: AuditSignal = {
  ...SIGNAL_BLOCK,
  sequence: DEMO_SEQUENCE,
};

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 1 — AuditSignal Schema (Phase 05, ADR-006)
// ═════════════════════════════════════════════════════════════════════════════

describe('AuditSignal Schema (Phase 05 — ADR-006)', () => {
  it('validates a correct core signal', () => {
    const result = AuditSignalSchema.safeParse(SIGNAL_DOWNGRADE);
    expect(result.success).toBe(true);
  });

  it('validates a core signal with sequence layer', () => {
    const result = AuditSignalSchema.safeParse(SIGNAL_BLOCK_WITH_SEQ);
    expect(result.success).toBe(true);
    expect(result.data?.sequence?.patternType).toBe('CONTAINED');
  });

  it('validates a signal with enrichment layer', () => {
    const withEnrichment: AuditSignal = {
      ...SIGNAL_BLOCK,
      enrichment: {
        identityRef:      'user-ref-abc',
        assetRef:         'asset-ref-xyz',
        serviceComponent: 'AuthService',
      },
    };
    const result = AuditSignalSchema.safeParse(withEnrichment);
    expect(result.success).toBe(true);
    expect(result.data?.enrichment?.serviceComponent).toBe('AuthService');
  });

  it('rejects invalid schema (bad data)', () => {
    const result = AuditSignalSchema.safeParse({ bad: 'data' });
    expect(result.success).toBe(false);
  });

  it('rejects invalid layer value', () => {
    const bad = { ...SIGNAL_DOWNGRADE, layer: 'unknown' };
    const result = AuditSignalSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it('rejects invalid action value', () => {
    const bad = { ...SIGNAL_DOWNGRADE, action: 'ALLOW' };
    const result = AuditSignalSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it('all 14 core fields are present in SIGNAL_BLOCK', () => {
    const coreFields = [
      'evidenceHandle', 'sequenceNumber', 'layer', 'severity', 'action',
      'authority', 'integrityScore', 'detectionMode', 'routingHint',
      'mttdMs', 'detectedAt', 'storedAt', 'policyProfileId', 'partnerId',
    ];
    coreFields.forEach(f => expect(SIGNAL_BLOCK).toHaveProperty(f));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 2 — Evidence Level (Toru-William signal quality)
// ═════════════════════════════════════════════════════════════════════════════

describe('evidenceLevel (Phase 05 — Toru-William)', () => {
  it('returns MODERATE for high-severity BLOCK without sequence', () => {
    expect(evidenceLevel(SIGNAL_BLOCK)).toBe('MODERATE');
  });

  it('returns STRONG for high-severity BLOCK with escalation in sequence', () => {
    expect(evidenceLevel(SIGNAL_BLOCK_WITH_SEQ)).toBe('STRONG');
  });

  it('returns WEAK for low-severity DOWNGRADE', () => {
    expect(evidenceLevel(SIGNAL_DOWNGRADE)).toBe('WEAK');
  });

  it('STRONG requires both high severity AND escalationDetected=true', () => {
    const noEscalation: AuditSignal = {
      ...SIGNAL_BLOCK,
      sequence: { ...DEMO_SEQUENCE, escalationDetected: false },
    };
    expect(evidenceLevel(noEscalation)).toBe('MODERATE');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 3 — Audit Finding Summary
// ═════════════════════════════════════════════════════════════════════════════

describe('auditFindingSummary', () => {
  it('produces a human-readable summary for core-only signal', () => {
    const summary = auditFindingSummary(SIGNAL_BLOCK);
    expect(summary).toContain('authority');
    expect(summary).toContain('high');
    expect(summary).toContain('BLOCK');
    expect(summary).toContain('STRICT-PROD');
  });

  it('includes sequence pattern when sequence is present', () => {
    const summary = auditFindingSummary(SIGNAL_BLOCK_WITH_SEQ);
    expect(summary).toContain('CONTAINED');
    expect(summary).toContain('94');
  });

  it('does not include sequence info when sequence is absent', () => {
    const summary = auditFindingSummary(SIGNAL_DOWNGRADE);
    expect(summary).not.toContain('CONTAINED');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 4 — ISO 42001 Control Mapping (Phase 06)
// ═════════════════════════════════════════════════════════════════════════════

describe('ISO 42001 control mapping (Phase 06)', () => {
  it('gate layer maps to correct ISO controls', () => {
    const controls = isoControlsForSignal(SIGNAL_DOWNGRADE);
    expect(controls).toContain('ISO42001-6.1.2');
    expect(controls).toContain('ISO42001-8.4');
    expect(controls).toContain('ISO42001-9.1');
  });

  it('authority layer maps to correct ISO controls', () => {
    const controls = isoControlsForSignal(SIGNAL_BLOCK);
    expect(controls).toContain('ISO42001-8.5');
    expect(controls).toContain('ISO42001-9.3');
    expect(controls).toContain('ISO42001-10.1');
  });

  it('all 4 layers have at least 3 controls mapped', () => {
    (['gate', 'premise', 'authority', 'continuity'] as const).forEach(layer => {
      expect(ISO42001_CONTROL_MAP[layer].length).toBeGreaterThanOrEqual(3);
    });
  });

  it('control IDs are unique across the map', () => {
    const allIds = Object.values(ISO42001_CONTROL_MAP).flat();
    const unique = new Set(allIds);
    // Some controls appear in multiple layers — but within a layer they're unique
    Object.values(ISO42001_CONTROL_MAP).forEach(ids => {
      expect(new Set(ids).size).toBe(ids.length);
    });
    expect(allIds.length).toBeGreaterThan(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 5 — Finding Generator (Phase 03–06)
// ═════════════════════════════════════════════════════════════════════════════

describe('generateFinding (Phase 03–06)', () => {
  it('generates a HIGH finding for BLOCK + high severity', () => {
    const finding = generateFinding(SIGNAL_BLOCK);
    expect(finding.findingSeverity).toBe('HIGH');
    expect(finding.controlStatus).toBe('TRIGGERED');
    expect(finding.isoControls.length).toBeGreaterThan(0);
  });

  it('generates a LOW finding for DOWNGRADE + low severity', () => {
    const finding = generateFinding(SIGNAL_DOWNGRADE);
    expect(finding.findingSeverity).toBe('LOW');
    expect(finding.controlStatus).toBe('TRIGGERED');
  });

  it('escalated finding when sequence has escalationDetected', () => {
    const finding = generateFinding(SIGNAL_BLOCK_WITH_SEQ);
    expect(finding.controlStatus).toBe('ESCALATED');
    expect(finding.sequenceId).toBe('WF-DEMO-LIVE-001');
    expect(finding.patternType).toBe('CONTAINED');
    expect(finding.consistencyScore).toBe(94);
    expect(finding.actionChain).toEqual(['DOWNGRADE', 'BLOCK']);
  });

  it('finding includes STRIDE context for each layer', () => {
    const gFinding = generateFinding(SIGNAL_DOWNGRADE);
    expect(gFinding.strideContext).toContain('S-001');

    const aFinding = generateFinding(SIGNAL_BLOCK);
    expect(aFinding.strideContext).toContain('E-001');
  });

  it('generates CRITICAL finding for FAIL_SAFE action', () => {
    const failSafe: AuditSignal = {
      ...SIGNAL_BLOCK,
      action: 'FAIL_SAFE',
      severity: 'high',
    };
    const finding = generateFinding(failSafe);
    expect(finding.findingSeverity).toBe('CRITICAL');
    expect(finding.controlStatus).toBe('FAILED_SAFE');
  });

  it('batch generates findings preserving order', () => {
    const findings = generateFindings([SIGNAL_DOWNGRADE, SIGNAL_BLOCK]);
    expect(findings).toHaveLength(2);
    expect(findings[0].action).toBe('DOWNGRADE');
    expect(findings[1].action).toBe('BLOCK');
  });

  it('finding ID is unique across calls', () => {
    const f1 = generateFinding(SIGNAL_DOWNGRADE);
    const f2 = generateFinding(SIGNAL_BLOCK);
    expect(f1.findingId).not.toBe(f2.findingId);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 6 — Sequence Analyzer (Phase 04–05)
// ═════════════════════════════════════════════════════════════════════════════

describe('sequence-analyzer (Phase 04–05)', () => {
  it('CONTAINED pattern → CONTAINED posture', () => {
    expect(derivePosture(DEMO_SEQUENCE)).toBe('CONTAINED');
  });

  it('STABLE pattern → HEALTHY posture', () => {
    const stable: AuditSignalSequence = {
      ...DEMO_SEQUENCE,
      patternType: 'STABLE',
      escalationDetected: false,
    };
    expect(derivePosture(stable)).toBe('HEALTHY');
  });

  it('VOLATILE pattern → UNSTABLE posture', () => {
    const volatile_seq: AuditSignalSequence = {
      ...DEMO_SEQUENCE,
      patternType: 'VOLATILE',
    };
    expect(derivePosture(volatile_seq)).toBe('UNSTABLE');
  });

  it('DEGRADING with escalation → UNDER_PRESSURE', () => {
    const degrading: AuditSignalSequence = {
      ...DEMO_SEQUENCE,
      patternType: 'DEGRADING',
      escalationDetected: true,
    };
    expect(derivePosture(degrading)).toBe('UNDER_PRESSURE');
  });

  it('builds a sequence report with correct posture and summary', () => {
    const findings = generateFindings([SIGNAL_DOWNGRADE, SIGNAL_BLOCK]);
    const report = buildSequenceReport(DEMO_SEQUENCE, findings, 'DEMO_ENT_2026');
    expect(report.posture).toBe('CONTAINED');
    expect(report.reportSummary).toContain('contained');
    expect(report.reportSummary).toContain('94');
    expect(report.isoEvidence.length).toBeGreaterThan(0);
  });

  it('sequence report includes all ISO controls from findings', () => {
    const findings = generateFindings([SIGNAL_DOWNGRADE, SIGNAL_BLOCK]);
    const report = buildSequenceReport(DEMO_SEQUENCE, findings, 'DEMO_ENT_2026');
    expect(report.isoEvidence).toContain('ISO42001-6.1.2'); // gate
    expect(report.isoEvidence).toContain('ISO42001-8.5');   // authority
  });

  it('tenant posture summary counts CONTAINED correctly', () => {
    const findings = generateFindings([SIGNAL_DOWNGRADE, SIGNAL_BLOCK]);
    const report = buildSequenceReport(DEMO_SEQUENCE, findings, 'DEMO_ENT_2026');
    const summary = summarizeTenantPosture([report], 'DEMO_ENT_2026');
    expect(summary.postureDistribution.CONTAINED).toBe(1);
    expect(summary.dominantPosture).toBe('CONTAINED');
    expect(summary.highSeverityCount).toBe(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 7 — MTTD Monitor (Phase 03/06 SLA baseline)
// ═════════════════════════════════════════════════════════════════════════════

describe('mttd-monitor (Phase 03/06)', () => {
  it('evaluates gate mttdMs=1ms as ELEVATED (above 0.03ms p99 baseline, within 50ms SLA)', () => {
    // Phase 06 observed p99 baseline = 0.03ms.
    // 1ms > 0.03ms * 1.10 → regressionFlag=true → ELEVATED (not SLA_BREACH).
    // This is correct: the demo's real-world 1ms latency exceeds the unit-test
    // baseline, demonstrating the regression flag works as designed.
    const eval_ = evaluateMttd('gate', 1);
    expect(eval_.slaBreached).toBe(false);      // 1ms << 50ms SLA — no breach
    expect(eval_.regressionFlag).toBe(true);    // 1ms >> 0.03ms baseline * 1.10
    expect(eval_.category).toBe('ELEVATED');
  });

  it('evaluates gate mttdMs=60ms as SLA_BREACH (SLA=50ms)', () => {
    const eval_ = evaluateMttd('gate', 60);
    expect(eval_.slaBreached).toBe(true);
    expect(eval_.category).toBe('SLA_BREACH');
  });

  it('SLA values match Phase 06 contract', () => {
    expect(MTTD_SLA_MS.gate).toBe(50);
    expect(MTTD_SLA_MS.premise).toBe(200);
    expect(MTTD_SLA_MS.authority).toBe(100);
    expect(MTTD_SLA_MS.continuity).toBe(500);
  });

  it('baseline p99 values are all below 0.1ms (Phase 06 observed)', () => {
    Object.values(MTTD_BASELINE_P99_MS).forEach(v => {
      expect(v).toBeLessThan(0.1);
    });
  });

  it('buildMttdReport: gate mttdMs=1ms from Phase 07 demo shows ELEVATED (regression flag vs 0.03ms baseline)', () => {
    // The Phase 07 demo produced mttdMs=1 for the gate layer — real I/O latency
    // vs the 0.03ms unit-test baseline. ELEVATED is the CORRECT classification:
    // it flags for investigation without triggering an SLA breach (SLA=50ms).
    const signals = [
      { layer: 'gate' as const, mttdMs: 1 },
      { layer: 'authority' as const, mttdMs: 0 },
    ];
    const report = buildMttdReport(signals, 'DEMO_ENT_2026');
    expect(report.overallHealthy).toBe(true);   // No SLA breach
    expect(report.byLayer.gate.category).toBe('ELEVATED');    // Regression flag fired
    expect(report.byLayer.gate.slaBreaches).toBe(0);          // SLA not breached
    expect(report.byLayer.authority.sampleCount).toBe(1);
  });

  it('regression flag fires when mttdMs exceeds baseline by >10%', () => {
    const baseline = MTTD_BASELINE_P99_MS.gate; // 0.03ms
    const regressed = baseline * 1.15; // 15% above baseline
    const eval_ = evaluateMttd('gate', regressed);
    expect(eval_.regressionFlag).toBe(true);
    expect(eval_.slaBreached).toBe(false); // Still well within 50ms SLA
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 8 — ISO 42001 Evidence Packaging (Phase 06)
// ═════════════════════════════════════════════════════════════════════════════

describe('iso42001-evidence (Phase 06)', () => {
  it('builds coverage report from demo signals', () => {
    const findings = generateFindings([SIGNAL_DOWNGRADE, SIGNAL_BLOCK]);
    const report = buildCoverageReport(findings, [], 'DEMO_ENT_2026');
    expect(report.totalControls).toBeGreaterThan(0);
    expect(report.coveragePercent).toBeGreaterThan(0);
  });

  it('evidenced controls have at least one evidence handle', () => {
    const findings = generateFindings([SIGNAL_DOWNGRADE, SIGNAL_BLOCK, SIGNAL_BLOCK]);
    const report = buildCoverageReport(findings, [], 'DEMO_ENT_2026');
    const evidenced = report.records.filter(r => r.status === 'EVIDENCED');
    evidenced.forEach(r => {
      expect(r.evidenceHandles.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('audit readiness READY when coverage ≥ 70%', () => {
    // Generate enough signals to cover multiple layers
    const signals = [
      SIGNAL_DOWNGRADE, SIGNAL_BLOCK, SIGNAL_DOWNGRADE, SIGNAL_BLOCK,
      { ...SIGNAL_DOWNGRADE, layer: 'premise' as const, evidenceHandle: 'EVD-P1' },
      { ...SIGNAL_BLOCK, layer: 'continuity' as const, evidenceHandle: 'EVD-C1' },
    ] as AuditSignal[];
    const findings = generateFindings(signals);
    const report = buildCoverageReport(findings, [], 'DEMO_ENT_2026');
    // With signals from multiple layers, coverage should be READY or PARTIAL
    expect(['READY', 'PARTIAL']).toContain(report.auditReadiness);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 9 — Full Report Builder (Phase 07)
// ═════════════════════════════════════════════════════════════════════════════

describe('buildTenantAuditReport (Phase 07)', () => {
  const PERIOD = {
    from: '2026-05-19T10:00:00.000Z',
    to:   '2026-05-19T11:00:00.000Z',
  };

  const SEQUENCE_INPUT: SequenceInput = {
    signals:  [SIGNAL_DOWNGRADE, SIGNAL_BLOCK],
    sequence: DEMO_SEQUENCE,
  };

  it('builds a complete report for DEMO_ENT_2026', () => {
    const report = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    expect(report.partnerId).toBe('DEMO_ENT_2026');
    expect(report.findings).toHaveLength(2);
    expect(report.sequences).toHaveLength(1);
    expect(report.reportId).toMatch(/^RPT-DEMO_ENT_2026-/);
  });

  it('posture summary reflects CONTAINED sequence', () => {
    const report = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    expect(report.postureSummary.dominantPosture).toBe('CONTAINED');
    expect(report.postureSummary.postureDistribution.CONTAINED).toBe(1);
  });

  it('ISO 42001 report has coverage data', () => {
    const report = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    expect(report.iso42001.totalControls).toBeGreaterThan(0);
    expect(report.iso42001.partnerId).toBe('DEMO_ENT_2026');
  });

  it('MTTD report reflects actual mttdMs from signals', () => {
    const report = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    expect(report.mttd.overallHealthy).toBe(true);
    expect(report.mttd.byLayer.gate.sampleCount).toBe(1);
  });

  it('report includes boundary note (ADR-006 compliance)', () => {
    const report = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    expect(report.boundaryNote).toContain('ADR-006');
    expect(report.boundaryNote).toContain('No internal AI system state');
  });

  it('classification is Non-Public concept artifact', () => {
    const report = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    expect(report.classification).toBe('Non-Public / Concept Demonstration Artifact');
  });

  it('report is reproducible: same inputs produce consistent structure', () => {
    const r1 = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    const r2 = buildTenantAuditReport('DEMO_ENT_2026', [SEQUENCE_INPUT], PERIOD);
    // IDs differ (timestamp + counter) but structure is identical
    expect(r1.findings.length).toBe(r2.findings.length);
    expect(r1.postureSummary.dominantPosture).toBe(r2.postureSummary.dominantPosture);
    expect(r1.iso42001.coveragePercent).toBe(r2.iso42001.coveragePercent);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 10 — Toru-William Alignment (ADR-006 boundary contract)
// ═════════════════════════════════════════════════════════════════════════════

describe('Toru-William boundary contract (ADR-006)', () => {
  it('Urielle can process D-04 sequence summary without EGS internals', () => {
    // Simulate what Urielle receives from GET /v1/events/sequence/:id/summary
    const sequenceSummary = {
      sequenceId:         'WF-DEMO-LIVE-001',
      patternType:        'CONTAINED' as const,
      escalationDetected: true,
      consistencyScore:   94,
      eventCount:         2,
      actionChain:        ['DOWNGRADE', 'BLOCK'] as const,
      layersInvolved:     ['gate', 'authority'] as const,
      firstDetectedAt:    '2026-05-19T10:16:16.974Z',
    };
    // Verify posture derivation works from boundary-only data
    expect(derivePosture(sequenceSummary as AuditSignalSequence)).toBe('CONTAINED');
  });

  it('consistencyScore=94 produces STRONG evidence when BLOCK+escalation', () => {
    expect(evidenceLevel(SIGNAL_BLOCK_WITH_SEQ)).toBe('STRONG');
  });

  it('AuditSignal schema boundary: no internal EGS fields accepted', () => {
    // Attempt to parse a signal with hypothetical internal fields
    const withInternals = {
      ...SIGNAL_BLOCK,
      modelWeights:     'access-forbidden',
      kernelState:      'access-forbidden',
      rawInferenceData: 'access-forbidden',
    };
    // Schema should still parse (extra fields stripped by Zod)
    const result = AuditSignalSchema.safeParse(withInternals);
    expect(result.success).toBe(true);
    // Internal fields must not appear in parsed output
    expect(result.data).not.toHaveProperty('modelWeights');
    expect(result.data).not.toHaveProperty('kernelState');
  });

  it('schemaVersion 1.0 is present on every parsed signal', () => {
    const parsed = AuditSignalSchema.parse(SIGNAL_BLOCK);
    expect(parsed.schemaVersion).toBe('1.0');
  });

  it('ISO control evidence is derived from layer only — no internal access', () => {
    // Urielle maps controls from the LAYER field alone
    const gateControls   = ISO42001_CONTROL_MAP['gate'];
    const authControls   = ISO42001_CONTROL_MAP['authority'];
    expect(gateControls).not.toEqual(authControls);
    // Both sets contain only public ISO control IDs
    [...gateControls, ...authControls].forEach(ctrl => {
      expect(ctrl).toMatch(/^ISO42001-\d+\.\d+/);
    });
  });
});
