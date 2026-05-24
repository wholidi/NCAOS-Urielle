/**
 * @urielle/audit — Public API
 *
 * Urielle AI · AI Safety · Governance · Audit
 * v0.7.0 — aligned to NCAOS/EGS Phases 01–07
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  Phase alignment:                                               │
 * │   Phase 01  foundation                                          │
 * │   Phase 03  MTTD instrumentation → mttd-monitor                │
 * │   Phase 04  sequenceId / EventStore → sequence-analyzer        │
 * │   Phase 05  AuditSignal ADR-006 → audit-signal-consumer        │
 * │   Phase 06  ISO 42001 + STRIDE → iso42001-evidence             │
 * │   Phase 07  complete report assembly → report-builder          │
 * └─────────────────────────────────────────────────────────────────│
 */

// Phase 05 — AuditSignal boundary contract (ADR-006)
export {
  AuditSignalSchema,
  evidenceLevel,
  auditFindingSummary,
  isoControlsForSignal,
  ISO42001_CONTROL_MAP,
} from './audit-signal-consumer.js';
export type {
  AuditSignal,
  AuditSignalCore,
  AuditSignalSequence,
  EvidenceLevel,
} from './audit-signal-consumer.js';

// Phase 03–06 — Finding generation
export {
  generateFinding,
  generateFindings,
} from './finding-generator.js';
export type {
  AuditFinding,
  FindingSeverity,
  ControlStatus,
} from './finding-generator.js';

// Phase 04–05 — Sequence analysis
export {
  derivePosture,
  buildSequenceReport,
  summarizeTenantPosture,
} from './sequence-analyzer.js';
export type {
  GovernancePosture,
  SequenceAuditReport,
  TenantPostureSummary,
} from './sequence-analyzer.js';

// Phase 06 — ISO 42001 evidence packaging
export {
  buildControlEvidencePackage,
  buildCoverageReport,
} from './iso42001-evidence.js';
export type {
  ControlEvidenceRecord,
  ISO42001CoverageReport,
} from './iso42001-evidence.js';

// Phase 03/06 — MTTD monitoring
export {
  evaluateMttd,
  buildMttdReport,
  MTTD_SLA_MS,
  MTTD_BASELINE_P99_MS,
} from './mttd-monitor.js';
export type { MttdAuditReport, DetectionLayer } from './mttd-monitor.js';

// Phase 07 — Full report builder
export { buildTenantAuditReport } from './report-builder.js';
export type { UrielleTenantAuditReport, SequenceInput } from './report-builder.js';
