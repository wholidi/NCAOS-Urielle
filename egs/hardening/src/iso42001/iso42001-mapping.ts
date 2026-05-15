/**
 * @ncaos/hardening — ISO 42001 Control Mapping
 *
 * Maps NCAOS EGS architectural components and evidence outputs
 * to ISO/IEC 42001:2023 AI Management System requirements.
 *
 * Structure of ISO 42001:
 *   Clause 4: Context of the organization
 *   Clause 5: Leadership
 *   Clause 6: Planning
 *   Clause 7: Support
 *   Clause 8: Operation
 *   Clause 9: Performance evaluation
 *   Clause 10: Improvement
 *
 * For each control, this mapping identifies:
 *   - Which EGS component provides the evidence
 *   - Which API endpoint surfaces the evidence
 *   - Which AuditSignal field carries it
 *   - Evidence strength: DIRECT / INDIRECT / SUPPORTING
 */

export type EvidenceStrength = 'DIRECT' | 'INDIRECT' | 'SUPPORTING';
export type ComplianceStatus = 'IMPLEMENTED' | 'PARTIAL' | 'PLANNED' | 'NOT_APPLICABLE';

export interface Iso42001Control {
  id: string;                    // e.g. '6.1.2'
  clause: string;                // Clause description
  requirement: string;           // What ISO 42001 requires
  egsComponent: string;          // Which EGS component addresses this
  evidenceSource: string;        // Where to find the evidence
  apiEndpoint?: string;          // API endpoint that surfaces evidence
  auditSignalField?: string;     // AuditSignal field (if applicable)
  evidenceStrength: EvidenceStrength;
  status: ComplianceStatus;
  notes?: string;
}

export const ISO42001_CONTROLS: Iso42001Control[] = [

  // ── CLAUSE 6: PLANNING ──────────────────────────────────────────────────

  {
    id: '6.1.2',
    clause: 'Actions to address AI risks',
    requirement: 'Identify and address risks associated with AI system outputs and behavior',
    egsComponent: 'GateDetector — 10 configurable rules covering injection, replay, tampering, rate limits',
    evidenceSource: 'Event records with layer=gate, STRIDE threat model (stride-model.ts)',
    apiEndpoint: 'GET /v1/events?layer=gate',
    auditSignalField: 'core.layer, core.severity, core.action',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'GateDetector rules map directly to identified AI/OS risk categories. STRIDE model documents 15 threats with mitigations.',
  },
  {
    id: '6.1.3',
    clause: 'AI risk assessment',
    requirement: 'Conduct and document AI risk assessments',
    egsComponent: 'STRIDE threat model + AI/ML threat model (Phase 06)',
    evidenceSource: 'stride-model.ts (15 threats), aiml-threat-model.ts (adversarial ML threats)',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'Phase 06 provides two formal threat models covering STRIDE categories and AI/ML-specific risks (model drift, adversarial inputs, context manipulation).',
  },
  {
    id: '6.2',
    clause: 'AI objectives and planning',
    requirement: 'Establish measurable AI governance objectives',
    egsComponent: 'PolicyProfile — quantified thresholds for integrity, authority, continuity, MTTD',
    evidenceSource: 'Active policy profile with numeric thresholds',
    apiEndpoint: 'GET /v1/policy',
    auditSignalField: 'core.policyProfileId',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'PolicyProfile provides quantified objectives: integrity thresholds (0–100), MTTD SLAs (ms), continuity thresholds. All measurable and auditable.',
  },

  // ── CLAUSE 8: OPERATION ─────────────────────────────────────────────────

  {
    id: '8.3',
    clause: 'AI system design',
    requirement: 'Design AI systems with appropriate controls and oversight mechanisms',
    egsComponent: 'Observer → Judge → Enforcer architecture (ADR-003)',
    evidenceSource: 'Shell loop code, ADR-003-process-isolation.md',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'Decoupled architecture ensures governance shell cannot be disabled by AI system failure. FAIL_SAFE default-deny (ADR-002) enforces safe defaults.',
  },
  {
    id: '8.4',
    clause: 'AI system operation',
    requirement: 'Operate AI systems within defined boundaries and monitor for boundary violations',
    egsComponent: 'All four detection layers — Gate, Premise, Authority, Continuity',
    evidenceSource: 'Event records per layer, MTTD statistics',
    apiEndpoint: 'GET /v1/events, GET /v1/mttd',
    auditSignalField: 'core.layer, core.detectionMode, core.mttdMs',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'Each detection layer operates on a specific boundary dimension. MTTD provides measurable performance evidence for each layer.',
  },
  {
    id: '8.5',
    clause: 'AI system deployment',
    requirement: 'Control and document AI system deployment and configuration changes',
    egsComponent: 'PolicyStore — policy change history with timestamps and actor',
    evidenceSource: 'Policy change history log',
    apiEndpoint: 'GET /v1/policy/history',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'PolicyStore records last 10 policy versions with activatedAt, activatedBy, and reason fields. Phase 07: persist to DB for unlimited history.',
  },
  {
    id: '8.6',
    clause: 'AI system maintenance',
    requirement: 'Monitor and maintain AI system behavioral consistency across updates',
    egsComponent: 'ContinuityDetector — equivalence testing across update windows',
    evidenceSource: 'Continuity scores, equivalence test results, change window state',
    apiEndpoint: 'GET /v1/state (continuityScore, updateState, changeWindowActive)',
    auditSignalField: 'core.layer=continuity (when triggered)',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'ContinuityDetector implements OPEN→WATCHING→CLOSED state machine across update windows. Equivalence tests verify behavioral consistency, not output identity.',
  },

  // ── CLAUSE 9: PERFORMANCE EVALUATION ───────────────────────────────────

  {
    id: '9.1',
    clause: 'Monitoring, measurement, analysis and evaluation',
    requirement: 'Monitor and measure AI system performance against defined objectives',
    egsComponent: 'MttdTracker — rolling p50/p95/p99 per detection layer with SLA validation',
    evidenceSource: 'MTTD statistics, SLA breach rates',
    apiEndpoint: 'GET /v1/mttd',
    auditSignalField: 'core.mttdMs',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'MttdTracker maintains 1000-sample ring buffer per layer. slaBreachRate < 5% defines healthy operation. Directly auditable performance evidence.',
  },
  {
    id: '9.2',
    clause: 'Internal audit',
    requirement: 'Conduct internal audits of the AI management system',
    egsComponent: 'AuditSignal schema + EventStore — immutable evidence trail per tenant',
    evidenceSource: 'Evidence handles, sequence analysis, consistency scores',
    apiEndpoint: 'GET /v1/audit/:handle, GET /v1/events/sequence/:id/summary',
    auditSignalField: 'core.evidenceHandle, sequence.consistencyScore, sequence.patternType',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'AuditSignal (ADR-006) provides the formal typed interface for audit consumption. Urielle audit layer consumes this to generate governance findings.',
  },
  {
    id: '9.3',
    clause: 'Management review',
    requirement: 'Senior management reviews AI system performance and risks periodically',
    egsComponent: 'Executive view in Admin Terminal — RAW vs GOVERNED, integrity trend, system status',
    evidenceSource: 'Admin Terminal Executive view, event statistics',
    apiEndpoint: 'GET /v1/events/stats, GET /v1/state',
    evidenceStrength: 'SUPPORTING',
    status: 'IMPLEMENTED',
    notes: 'Executive view provides non-technical risk summary. RAW EXPOSURE vs GOVERNED OUTPUT comparison demonstrates containment efficacy for management review.',
  },

  // ── CLAUSE 10: IMPROVEMENT ──────────────────────────────────────────────

  {
    id: '10.1',
    clause: 'Nonconformity and corrective action',
    requirement: 'Identify, document, and correct AI governance nonconformities',
    egsComponent: 'AuthorityAuditLog — immutable record of all authority decisions and overrides',
    evidenceSource: 'Authority audit log entries, escalation patterns in sequences',
    apiEndpoint: 'GET /v1/events/sequence/:id/summary (escalationDetected)',
    auditSignalField: 'sequence.escalationDetected, sequence.patternType',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'AuthorityAuditLog provides immutable record. Sequence analysis detects DEGRADING and CONTAINED patterns which indicate governance nonconformities requiring corrective action.',
  },
  {
    id: '10.2',
    clause: 'Continual improvement',
    requirement: 'Continually improve the AI management system suitability and effectiveness',
    egsComponent: 'ContinuityDetector trend tracking + MTTD regression tests (Phase 06)',
    evidenceSource: 'Continuity score history, MTTD regression test results',
    apiEndpoint: 'GET /v1/state (continuityScore), GET /v1/mttd',
    auditSignalField: 'core.layer=continuity',
    evidenceStrength: 'SUPPORTING',
    status: 'PARTIAL',
    notes: 'Trend tracking implemented. Formal regression test suite (mttd-regression.test.ts) added in Phase 06. Historical trending and improvement metrics are Phase 07 scope.',
  },

  // ── ADDITIONAL: ANNEX A CONTROLS ────────────────────────────────────────

  {
    id: 'A.2.2',
    clause: 'Annex A — Responsible use of AI',
    requirement: 'Establish accountability for AI system decisions',
    egsComponent: 'Evidence handles + tenant isolation — every decision traceable to PARTNER_ID',
    evidenceSource: 'Evidence handles with partnerId, requestId, policyProfileId',
    apiEndpoint: 'GET /v1/audit/:handle',
    auditSignalField: 'core.evidenceHandle, core.partnerId, core.policyProfileId',
    evidenceStrength: 'DIRECT',
    status: 'IMPLEMENTED',
    notes: 'Every governance decision generates an immutable evidence handle scoped to a tenant and policy. Full decision chain is auditable without internal model access.',
  },
  {
    id: 'A.4.3',
    clause: 'Annex A — AI system impact assessment',
    requirement: 'Assess the impact of AI system outputs on stakeholders',
    egsComponent: 'IMPACT_SCOPE field — req/flow/sys scope classification per containment event',
    evidenceSource: 'Event records with scope field',
    apiEndpoint: 'GET /v1/events',
    auditSignalField: 'core.layer (maps to scope via detection layer rules)',
    evidenceStrength: 'INDIRECT',
    status: 'IMPLEMENTED',
    notes: 'Impact scope (Single Request / Workflow-Level / System-Wide) is classified per containment event. Matches IMPACT_SCOPE field in original PoC UI.',
  },
  {
    id: 'A.6.1',
    clause: 'Annex A — AI system security',
    requirement: 'Implement and maintain AI system security controls',
    egsComponent: 'STRIDE threat model + JWT middleware + rate limiter (Phase 06)',
    evidenceSource: 'stride-model.ts, auth-middleware.ts, pen test results',
    evidenceStrength: 'DIRECT',
    status: 'PARTIAL',
    notes: 'STRIDE model (15 threats) and AI/ML threat model complete. JWT middleware implemented but not deployed (JWT_SECRET not set in dev). Full deployment is Phase 07 scope.',
  },
];

// ─────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────

export function iso42001Summary(): {
  total: number;
  implemented: number;
  partial: number;
  planned: number;
  coveragePercent: number;
} {
  const implemented = ISO42001_CONTROLS.filter(c => c.status === 'IMPLEMENTED').length;
  const partial = ISO42001_CONTROLS.filter(c => c.status === 'PARTIAL').length;
  const planned = ISO42001_CONTROLS.filter(c => c.status === 'PLANNED').length;
  const total = ISO42001_CONTROLS.length;
  const coveragePercent = Math.round(((implemented + partial * 0.5) / total) * 100);

  return { total, implemented, partial, planned, coveragePercent };
}

export function controlsByClause(): Record<string, Iso42001Control[]> {
  const result: Record<string, Iso42001Control[]> = {};
  for (const ctrl of ISO42001_CONTROLS) {
    const clause = ctrl.id.split('.')[0] ?? ctrl.id;
    if (!result[clause]) result[clause] = [];
    result[clause]!.push(ctrl);
  }
  return result;
}
