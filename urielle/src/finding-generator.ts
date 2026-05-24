/**
 * urielle/src/finding-generator.ts
 *
 * Aligned to NCAOS/EGS Phases 03–06
 *
 * Converts AuditSignal boundary events into structured Urielle
 * audit findings. Urielle's audit logic lives HERE — not inside EGS.
 *
 * Phase alignment:
 *   Phase 03 — Detection layers: gate/premise/authority/continuity
 *   Phase 04 — EventStore sequenceId, MTTD measurement
 *   Phase 05 — AuditSignal schema (ADR-006), sequenceId linking
 *   Phase 06 — STRIDE control mapping, ISO 42001 clauses
 *   Phase 07 — Sequence pattern analysis (CONTAINED/DEGRADING/VOLATILE)
 */

import type { AuditSignal, AuditSignalSequence } from './audit-signal-consumer.js';
import { evidenceLevel, auditFindingSummary, isoControlsForSignal } from './audit-signal-consumer.js';

// ── Finding severity (Urielle's own scale, independent of EGS severity) ──

export type FindingSeverity = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

function deriveFindingSeverity(signal: AuditSignal): FindingSeverity {
  if (signal.action === 'FAIL_SAFE')                                  return 'CRITICAL';
  if (signal.action === 'BLOCK' && signal.severity === 'high')        return 'HIGH';
  if (signal.action === 'BLOCK')                                      return 'MEDIUM';
  if (signal.action === 'DOWNGRADE' && signal.severity === 'high')    return 'MEDIUM';
  if (signal.action === 'DOWNGRADE')                                  return 'LOW';
  return 'INFORMATIONAL';
}

// ── Control status (did the EGS control operate correctly?) ──

export type ControlStatus = 'OPERATING' | 'TRIGGERED' | 'ESCALATED' | 'FAILED_SAFE';

function deriveControlStatus(signal: AuditSignal): ControlStatus {
  if (signal.action === 'FAIL_SAFE') return 'FAILED_SAFE';
  if (signal.sequence?.escalationDetected) return 'ESCALATED';
  if (signal.action === 'BLOCK' || signal.action === 'DOWNGRADE') return 'TRIGGERED';
  return 'OPERATING';
}

// ── STRIDE layer context (from Phase 06 STRIDE register) ──

const STRIDE_LAYER_MAP: Record<string, string> = {
  gate:        'Spoofing / Tampering / Denial-of-Service (S-001, T-001, D-001)',
  premise:     'Tampering / Repudiation (T-003, R-001)',
  authority:   'Elevation of Privilege / Tampering (E-001, T-002)',
  continuity:  'Denial-of-Service / Repudiation (D-002, R-002)',
};

// ── Core finding structure ──

export interface AuditFinding {
  // Identity
  findingId:         string;
  evidenceHandle:    string;
  partnerId:         string;
  generatedAt:       string;

  // Classification
  findingSeverity:   FindingSeverity;
  evidenceLevel:     'WEAK' | 'MODERATE' | 'STRONG';
  controlStatus:     ControlStatus;

  // EGS boundary data (from AuditSignal — no internal state)
  detectionLayer:    string;
  action:            string;
  authority:         string;
  integrityScore:    number;
  mttdMs:            number;
  policyProfile:     string;
  detectedAt:        string;

  // Urielle-derived analysis
  findingSummary:    string;
  strideContext:     string;
  isoControls:       string[];

  // Sequence analysis (Phase 04/05)
  sequenceId?:       string;
  patternType?:      string;
  escalationDetected?:boolean;
  consistencyScore?: number;
  actionChain?:      string[];

  // Enrichment (Phase 05 optional layer)
  identityRef?:      string;
  assetRef?:         string;
  serviceComponent?: string;
}

// ── Finding ID generator ──

let findingCounter = 0;
function newFindingId(): string {
  return `FIND-${Date.now()}-${String(++findingCounter).padStart(4, '0')}`;
}

// ── Main: generate finding from AuditSignal ──

export function generateFinding(signal: AuditSignal): AuditFinding {
  const finding: AuditFinding = {
    findingId:       newFindingId(),
    evidenceHandle:  signal.evidenceHandle,
    partnerId:       signal.partnerId,
    generatedAt:     new Date().toISOString(),

    findingSeverity: deriveFindingSeverity(signal),
    evidenceLevel:   evidenceLevel(signal),
    controlStatus:   deriveControlStatus(signal),

    detectionLayer:  signal.layer,
    action:          signal.action,
    authority:       signal.authority,
    integrityScore:  signal.integrityScore,
    mttdMs:          signal.mttdMs,
    policyProfile:   signal.policyProfileId,
    detectedAt:      signal.detectedAt,

    findingSummary:  auditFindingSummary(signal),
    strideContext:   STRIDE_LAYER_MAP[signal.layer] ?? 'Unknown',
    isoControls:     isoControlsForSignal(signal),
  };

  // Sequence layer (Phase 04/05 — sequenceId from workflowId)
  if (signal.sequence) {
    finding.sequenceId         = signal.sequence.sequenceId;
    finding.patternType        = signal.sequence.patternType;
    finding.escalationDetected = signal.sequence.escalationDetected;
    finding.consistencyScore   = signal.sequence.consistencyScore;
    finding.actionChain        = signal.sequence.actionChain;
  }

  // Enrichment layer (Phase 05 optional)
  if (signal.enrichment) {
    if (signal.enrichment.identityRef !== undefined) {
      finding.identityRef = signal.enrichment.identityRef;
    }

    if (signal.enrichment.assetRef !== undefined) {
      finding.assetRef = signal.enrichment.assetRef;
    }

    if (signal.enrichment.serviceComponent !== undefined) {
      finding.serviceComponent = signal.enrichment.serviceComponent;
    }
  }
 
  return finding;
}

// ── Batch processing ──

export function generateFindings(signals: AuditSignal[]): AuditFinding[] {
  return signals.map(generateFinding);
}
