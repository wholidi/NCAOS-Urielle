/**
 * urielle/src/sequence-analyzer.ts
 *
 * Aligned to NCAOS/EGS Phase 04 (sequenceId) + Phase 05 (AuditSignal ADR-006)
 *
 * Urielle's sequence analysis layer.
 *
 * The EGS produces a summarizeSequence() result via
 *   GET /v1/events/sequence/:id/summary
 * which gives Urielle: patternType, escalationDetected, consistencyScore,
 * actionChain, layersInvolved.
 *
 * Urielle uses this to:
 *   - Classify the governance posture over a workflow
 *   - Identify escalation patterns for audit reports
 *   - Score evidence quality for compliance use
 *
 * D-04 observed (Phase 07 demo):
 *   patternType=CONTAINED, escalationDetected=True,
 *   consistencyScore=94, actions={DOWNGRADE,BLOCK}
 */

import type { AuditSignalSequence } from './audit-signal-consumer.js';
import type { AuditFinding } from './finding-generator.js';

// ── Posture derived from sequence pattern ──

export type GovernancePosture =
  | 'HEALTHY'        // STABLE / no escalation
  | 'UNDER_PRESSURE' // DEGRADING / escalation present
  | 'CONTAINED'      // CONTAINED / escalation terminated at boundary
  | 'UNSTABLE';      // VOLATILE / repeated escalation

export function derivePosture(seq: AuditSignalSequence): GovernancePosture {
  switch (seq.patternType) {
    case 'STABLE':    return 'HEALTHY';
    case 'DEGRADING': return seq.escalationDetected ? 'UNDER_PRESSURE' : 'HEALTHY';
    case 'CONTAINED': return 'CONTAINED';
    case 'VOLATILE':  return 'UNSTABLE';
  }
}

// ── Sequence-level audit report ──

export interface SequenceAuditReport {
  sequenceId:        string;
  partnerId:         string;
  posture:           GovernancePosture;
  patternType:       string;
  escalationDetected:boolean;
  consistencyScore:  number;
  eventCount:        number;
  actionChain:       string[];
  layersInvolved:    string[];
  findings:          AuditFinding[];
  reportSummary:     string;
  isoEvidence:       string[];
  generatedAt:       string;
}

export function buildSequenceReport(
  seq: AuditSignalSequence,
  findings: AuditFinding[],
  partnerId: string,
): SequenceAuditReport {
  const posture = derivePosture(seq);

  const postureNarrative: Record<GovernancePosture, string> = {
    HEALTHY:        'Governance boundary operating normally. No escalation patterns detected.',
    UNDER_PRESSURE: `Governance boundary under pressure. Escalation pattern detected across ${seq.eventCount} events. Architecture review recommended.`,
    CONTAINED:      `Threat escalation detected and contained at the governance boundary. `
                  + `${seq.eventCount} events in sequence. Consistency score: ${seq.consistencyScore}/100. `
                  + `Action chain: ${seq.actionChain.join(' → ')}. `
                  + `No internal system access occurred during containment.`,
    UNSTABLE:       `Volatile governance pattern detected. Immediate escalation review required. `
                  + `${seq.eventCount} events with repeated boundary violations.`,
  };

  // Aggregate ISO controls from all findings in this sequence
  const allIsoControls = [...new Set(findings.flatMap(f => f.isoControls))].sort();

  return {
    sequenceId:         seq.sequenceId,
    partnerId,
    posture,
    patternType:        seq.patternType,
    escalationDetected: seq.escalationDetected,
    consistencyScore:   seq.consistencyScore,
    eventCount:         seq.eventCount,
    actionChain:        seq.actionChain,
    layersInvolved:     seq.layersInvolved,
    findings,
    reportSummary:      postureNarrative[posture],
    isoEvidence:        allIsoControls,
    generatedAt:        new Date().toISOString(),
  };
}

// ── Multi-sequence rollup ──

export interface TenantPostureSummary {
  partnerId:           string;
  totalSequences:      number;
  totalFindings:       number;
  highSeverityCount:   number;
  criticalCount:       number;
  postureDistribution: Record<GovernancePosture, number>;
  dominantPosture:     GovernancePosture;
  generatedAt:         string;
}

export function summarizeTenantPosture(
  reports: SequenceAuditReport[],
  partnerId: string,
): TenantPostureSummary {
  const dist: Record<GovernancePosture, number> = {
    HEALTHY: 0, UNDER_PRESSURE: 0, CONTAINED: 0, UNSTABLE: 0,
  };
  for (const r of reports) dist[r.posture]++;

  const allFindings = reports.flatMap(r => r.findings);
  const dominant = (Object.keys(dist) as GovernancePosture[])
    .reduce((a, b) => dist[a] >= dist[b] ? a : b);

  return {
    partnerId,
    totalSequences:      reports.length,
    totalFindings:       allFindings.length,
    highSeverityCount:   allFindings.filter(f => f.findingSeverity === 'HIGH').length,
    criticalCount:       allFindings.filter(f => f.findingSeverity === 'CRITICAL').length,
    postureDistribution: dist,
    dominantPosture:     dominant,
    generatedAt:         new Date().toISOString(),
  };
}
