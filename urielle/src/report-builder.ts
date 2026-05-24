/**
 * urielle/src/report-builder.ts
 *
 * Aligned to NCAOS/EGS Phase 07 (demo + pilot proposal context)
 *
 * Top-level Urielle audit report builder.
 * Assembles findings, sequence analysis, ISO 42001 evidence,
 * and MTTD health into a single structured report per tenant.
 *
 * This is the artefact Urielle delivers in Pilot Tier 2 and Tier 3
 * (see pilot-proposal.ts and ADR-008).
 *
 * Boundary principle (ADR-006 / Toru-William):
 *   All data in this report comes from AuditSignal boundary events.
 *   No internal EGS state is accessed. No model weights are referenced.
 *   The report is evidence of WHAT the boundary enforced — not WHY
 *   the AI system produced the flagged output.
 */

import type { AuditSignal } from './audit-signal-consumer.js';
import type { AuditFinding } from './finding-generator.js';
import type { SequenceAuditReport, TenantPostureSummary } from './sequence-analyzer.js';
import type { ISO42001CoverageReport } from './iso42001-evidence.js';
import type { MttdAuditReport } from './mttd-monitor.js';

import { generateFindings } from './finding-generator.js';
import { buildSequenceReport, summarizeTenantPosture } from './sequence-analyzer.js';
import { buildCoverageReport } from './iso42001-evidence.js';
import { buildMttdReport } from './mttd-monitor.js';

// ── Input: signals grouped by sequence ──

export interface SequenceInput {
  signals:   AuditSignal[];
  // sequence summary from GET /v1/events/sequence/:id/summary
  sequence?: {
    sequenceId:         string;
    patternType:        'STABLE' | 'DEGRADING' | 'CONTAINED' | 'VOLATILE';
    escalationDetected: boolean;
    consistencyScore:   number;
    eventCount:         number;
    actionChain:        Array<'PASS' | 'DOWNGRADE' | 'BLOCK' | 'FAIL_SAFE'>;
    layersInvolved:     Array<'gate' | 'premise' | 'authority' | 'continuity'>;
    firstDetectedAt:    string;
  };
}

// ── Full audit report ──

export interface UrielleTenantAuditReport {
  // Identity
  reportId:        string;
  partnerId:       string;
  reportPeriod:    { from: string; to: string };
  generatedAt:     string;

  // Summary
  postureSummary:  TenantPostureSummary;

  // Detail
  findings:        AuditFinding[];
  sequences:       SequenceAuditReport[];

  // Compliance
  iso42001:        ISO42001CoverageReport;

  // Performance
  mttd:            MttdAuditReport;

  // Classification
  classification:  'Non-Public / Concept Demonstration Artifact';
  boundaryNote:    string;
}

// ── Report ID generator ──
let rptCounter = 0;
function newReportId(partnerId: string): string {
  return `RPT-${partnerId}-${Date.now()}-${String(++rptCounter).padStart(3, '0')}`;
}

// ── Main builder ──

export function buildTenantAuditReport(
  partnerId: string,
  sequenceInputs: SequenceInput[],
  period: { from: string; to: string },
): UrielleTenantAuditReport {
  // 1. Generate all findings from all signals
  const allSignals = sequenceInputs.flatMap(si => si.signals);
  const allFindings = generateFindings(allSignals);

  // 2. Build per-sequence reports
  const sequenceReports: SequenceAuditReport[] = [];
  for (const si of sequenceInputs) {
    if (!si.sequence) continue;
    const seqFindings = allFindings.filter(
      f => si.signals.some(s => s.evidenceHandle === f.evidenceHandle),
    );
    sequenceReports.push(buildSequenceReport(si.sequence, seqFindings, partnerId));
  }

  // 3. Tenant posture rollup
  const postureSummary = summarizeTenantPosture(sequenceReports, partnerId);

  // 4. ISO 42001 coverage
  const iso42001 = buildCoverageReport(allFindings, sequenceReports, partnerId);

  // 5. MTTD report
  const mttdInputs = allSignals.map(s => ({
    layer: s.layer as 'gate' | 'premise' | 'authority' | 'continuity',
    mttdMs: s.mttdMs,
  }));
  const mttd = buildMttdReport(mttdInputs, partnerId);

  return {
    reportId:       newReportId(partnerId),
    partnerId,
    reportPeriod:   period,
    generatedAt:    new Date().toISOString(),
    postureSummary,
    findings:       allFindings,
    sequences:      sequenceReports,
    iso42001,
    mttd,
    classification: 'Non-Public / Concept Demonstration Artifact',
    boundaryNote:   'All evidence in this report is derived from NCAOS/EGS boundary signals (AuditSignal ADR-006). '
                  + 'No internal AI system state, model weights, or raw inference data was accessed. '
                  + 'Urielle operates exclusively on the governance boundary layer.',
  };
}
