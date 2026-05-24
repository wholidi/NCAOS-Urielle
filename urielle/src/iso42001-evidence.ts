/**
 * urielle/src/iso42001-evidence.ts
 *
 * Aligned to NCAOS/EGS Phase 06 (ISO 42001 mapping, hardening)
 *
 * Urielle's ISO 42001:2023 evidence packaging layer.
 *
 * The EGS hardening layer (Phase 06) maps 14 controls to API endpoints
 * and coverage status. Urielle consumes this mapping via AuditSignal
 * data to produce evidence packages suitable for external audit.
 *
 * Urielle never accesses EGS internals to produce this evidence.
 * All evidence is derived from boundary signals (AuditSignal) and
 * the ISO42001_CONTROL_MAP provided by the interface contract.
 */

import type { AuditFinding } from './finding-generator.js';
import type { SequenceAuditReport } from './sequence-analyzer.js';

// ── Control evidence record ──

export interface ControlEvidenceRecord {
  controlId:        string;
  clause:           string;
  description:      string;
  status:           'EVIDENCED' | 'PARTIAL' | 'NOT_EVIDENCED';
  evidenceHandles:  string[];
  findingIds:       string[];
  observedBehavior: string;
}

// ── Clause descriptions (from Phase 06 iso42001-mapping.ts) ──

const CLAUSE_DESCRIPTIONS: Record<string, { clause: string; description: string }> = {
  'ISO42001-6.1.2': { clause: '6.1.2', description: 'Actions to address AI risks — gate detection rules' },
  'ISO42001-6.1.3': { clause: '6.1.3', description: 'AI risk assessment — STRIDE + AI/ML threat models' },
  'ISO42001-8.3':   { clause: '8.3',   description: 'AI system design — Observer-Judge-Enforcer loop' },
  'ISO42001-8.4':   { clause: '8.4',   description: 'AI system operation — ShellLoop process isolation' },
  'ISO42001-8.5':   { clause: '8.5',   description: 'AI system deployment — tenant isolation (ADR-005)' },
  'ISO42001-8.6':   { clause: '8.6',   description: 'AI system maintenance — continuity equivalence testing' },
  'ISO42001-9.1':   { clause: '9.1',   description: 'Performance monitoring — MTTD SLA instrumentation' },
  'ISO42001-9.2':   { clause: '9.2',   description: 'Internal audit — evidence handle + AuditSignal schema' },
  'ISO42001-9.3':   { clause: '9.3',   description: 'Management review — sequence summary pattern analysis' },
  'ISO42001-10.1':  { clause: '10.1',  description: 'Nonconformity and corrective action — BLOCK + routing hints' },
  'ISO42001-10.2':  { clause: '10.2',  description: 'Continual improvement — Phase 06 hardening actions' },
};

// ── Build evidence records from findings ──

export function buildControlEvidencePackage(
  findings: AuditFinding[],
  reports: SequenceAuditReport[],
  partnerId: string,
): ControlEvidenceRecord[] {
  // Collect all control IDs mentioned across all findings
  const controlMap = new Map<string, { handles: string[]; findingIds: string[] }>();

  for (const f of findings) {
    for (const ctrl of f.isoControls) {
      if (!controlMap.has(ctrl)) controlMap.set(ctrl, { handles: [], findingIds: [] });
      const entry = controlMap.get(ctrl)!;
      entry.handles.push(f.evidenceHandle);
      entry.findingIds.push(f.findingId);
    }
  }

  const records: ControlEvidenceRecord[] = [];

  for (const [controlId, data] of controlMap.entries()) {
    const meta = CLAUSE_DESCRIPTIONS[controlId];
    if (!meta) continue;

    // Determine status: EVIDENCED if we have ≥1 handle, PARTIAL if low count
    const status: ControlEvidenceRecord['status'] =
      data.handles.length >= 2 ? 'EVIDENCED' :
      data.handles.length === 1 ? 'PARTIAL' : 'NOT_EVIDENCED';

    // Derive observed behavior from associated findings
    const relatedFindings = findings.filter(f => f.isoControls.includes(controlId));
    const layers = [...new Set(relatedFindings.map(f => f.detectionLayer))];
    const actions = [...new Set(relatedFindings.map(f => f.action))];
    const observed = `Observed ${data.handles.length} boundary event(s) on layer(s): ${layers.join(', ')}. `
                   + `Actions enforced: ${actions.join(', ')}. `
                   + `Partner: ${partnerId}.`;

    records.push({
      controlId,
      clause:           meta.clause,
      description:      meta.description,
      status,
      evidenceHandles:  [...new Set(data.handles)],
      findingIds:       [...new Set(data.findingIds)],
      observedBehavior: observed,
    });
  }

  return records.sort((a, b) => a.clause.localeCompare(b.clause));
}

// ── Coverage summary ──

export interface ISO42001CoverageReport {
  partnerId:        string;
  totalControls:    number;
  evidenced:        number;
  partial:          number;
  notEvidenced:     number;
  coveragePercent:  number;
  records:          ControlEvidenceRecord[];
  generatedAt:      string;
  auditReadiness:   'READY' | 'PARTIAL' | 'NOT_READY';
}

export function buildCoverageReport(
  findings: AuditFinding[],
  reports: SequenceAuditReport[],
  partnerId: string,
): ISO42001CoverageReport {
  const records = buildControlEvidencePackage(findings, reports, partnerId);

  const evidenced    = records.filter(r => r.status === 'EVIDENCED').length;
  const partial      = records.filter(r => r.status === 'PARTIAL').length;
  const notEvidenced = records.filter(r => r.status === 'NOT_EVIDENCED').length;
  const total        = records.length;
  const coveragePct  = total > 0 ? Math.round(((evidenced + partial * 0.5) / total) * 100) : 0;

  const readiness: ISO42001CoverageReport['auditReadiness'] =
    coveragePct >= 70 ? 'READY' :
    coveragePct >= 40 ? 'PARTIAL' : 'NOT_READY';

  return {
    partnerId,
    totalControls:   total,
    evidenced,
    partial,
    notEvidenced,
    coveragePercent: coveragePct,
    records,
    generatedAt:     new Date().toISOString(),
    auditReadiness:  readiness,
  };
}
