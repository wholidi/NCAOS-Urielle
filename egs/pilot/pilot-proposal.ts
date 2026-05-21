/**
 * @ncaos/pilot — Commercial Pilot Proposal
 *
 * Phase 07 deliverable: structured pilot engagement proposal
 * for enterprise organizations evaluating the EGS architecture.
 *
 * Not a sales document — a technical engagement framework.
 * Designed for architecture and legal/compliance review teams.
 */

export interface PilotTier {
  name: string;
  duration: string;
  scope: string[];
  deliverables: string[];
  successCriteria: string[];
}

export const PILOT_TIERS: PilotTier[] = [
  {
    name: 'Tier 1 — Observe',
    duration: '4 weeks',
    scope: [
      'EGS deployed in PILOT-OBS mode (no blocking — observe and log only)',
      'Single AI/OS boundary endpoint instrumented',
      'Read access to /v1/events, /v1/mttd, /v1/state',
      'Admin Terminal (React UI) deployed for the architecture team',
    ],
    deliverables: [
      'MTTD baseline report — detection latency per layer over 4 weeks',
      'Event log analysis — containment event frequency and pattern',
      'GovState trend — RAW vs GOVERNED comparison',
      'Phase 01 audit signal samples for Urielle consumption review',
    ],
    successCriteria: [
      'EGS processes all boundary requests within MTTD SLA (p99 per policy)',
      'Zero false positives that would have blocked legitimate requests',
      'Evidence handles retrievable and structured for compliance review',
      'Architecture team confirms decoupling — EGS has no internal model access',
    ],
  },
  {
    name: 'Tier 2 — Contain',
    duration: '8 weeks',
    scope: [
      'EGS upgraded to ENTERPRISE_STRICT mode (DOWNGRADE + BLOCK active)',
      'Custom gate rules configured for enterprise-specific threat patterns',
      'Policy profile tuned by enterprise architecture team',
      'Per-tenant isolation validated for multi-system deployment',
    ],
    deliverables: [
      'STRIDE threat model customized for enterprise AI/OS landscape',
      'ISO 42001 control mapping with IMPLEMENTED evidence for applicable clauses',
      'Pen test results against enterprise-specific attack vectors',
      'AuditSignal samples delivered to compliance/legal for evidence review',
    ],
    successCriteria: [
      'Containment events accurately reflect genuine governance violations',
      'False positive rate < 0.5% of legitimate business requests',
      'Compliance team confirms evidence trail meets audit requirements',
      'No FAIL_SAFE activations (shell stability confirmed over 8 weeks)',
    ],
  },
  {
    name: 'Tier 3 — Audit',
    duration: '12 weeks',
    scope: [
      'Full Urielle audit layer integration — AuditSignal consumption',
      'ISO 42001 formal audit trail generation',
      'Multi-tenant deployment (up to 5 business units)',
      'JWT authentication + RBAC rolled out to all API consumers',
    ],
    deliverables: [
      'ISO 42001 compliance evidence package for Clause 8 and 9',
      'Formal audit findings report from Urielle (Toru/MLP)',
      'v1.0-rc deployment guide for enterprise infrastructure team',
      'Phase 07 hardening actions (S-003, T-003, R-001 HMAC signing)',
    ],
    successCriteria: [
      'Legal/compliance team signs off on evidence trail quality',
      'ISO 42001 Clause 8.4, 9.1, 9.2 IMPLEMENTED evidence accepted',
      'Architecture team confirms no internal visibility required',
      'Commercial terms agreed for v1.0 production deployment',
    ],
  },
];

export interface PhaseSevenRoadmap {
  item: string;
  category: string;
  priority: 'MUST' | 'SHOULD' | 'NICE';
  effort: string;
  strideRef?: string;
}

export const V1_ROADMAP: PhaseSevenRoadmap[] = [
  // MUST for v1.0-rc
  { item: 'WebSocket authentication (S-003 fix)', category: 'Security', priority: 'MUST', effort: '1 day', strideRef: 'S-003' },
  { item: 'Stack trace stripping in production error responses', category: 'Security', priority: 'MUST', effort: '0.5 day', strideRef: 'I-001' },
  { item: 'HMAC-signed evidence handles (R-001)', category: 'Security', priority: 'MUST', effort: '1 day', strideRef: 'R-001' },
  { item: 'String sanitization in ProcessRequestSchema (T-003)', category: 'Security', priority: 'MUST', effort: '0.5 day', strideRef: 'T-003' },
  { item: 'activatedBy bound to JWT sub in PolicyStore', category: 'Security', priority: 'MUST', effort: '0.5 day', strideRef: 'R-002' },
  { item: '/v1/mttd restricted to admin role', category: 'Security', priority: 'MUST', effort: '0.5 day', strideRef: 'I-003' },
  // SHOULD for v1.0-rc
  { item: 'TimescaleDB persistence for EventStore (replace in-memory)', category: 'Infrastructure', priority: 'SHOULD', effort: '3 days' },
  { item: 'Redis-backed TenantDetectorRegistry (multi-node)', category: 'Infrastructure', priority: 'SHOULD', effort: '2 days' },
  { item: 'RS256 JWT key rotation (replace HS256)', category: 'Security', priority: 'SHOULD', effort: '1 day' },
  { item: 'GitHub Pages demo deployment', category: 'Demo', priority: 'SHOULD', effort: '1 day' },
  { item: 'ADR documentation complete (ADR-001 through ADR-007)', category: 'Documentation', priority: 'SHOULD', effort: '0.5 day' },
  // NICE for v1.0-rc
  { item: 'HMAC-signed sourceId for Gate allowlist verification', category: 'Security', priority: 'NICE', effort: '2 days', strideRef: 'S-002' },
  { item: 'Per-tenant event ingestion rate limit (D-002)', category: 'Security', priority: 'NICE', effort: '1 day', strideRef: 'D-002' },
  { item: 'Automated ISO 42001 evidence package generation', category: 'Compliance', priority: 'NICE', effort: '3 days' },
];
