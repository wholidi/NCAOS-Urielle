/**
 * urielle/src/audit-signal-consumer.ts
 *
 * Phase 05 alignment — AuditSignal consumption layer (ADR-006)
 *
 * Urielle's responsibility at the boundary:
 *   • Accept AuditSignal objects produced by NCAOS/EGS
 *   • Validate against the ADR-006 schema contract
 *   • Derive audit findings WITHOUT accessing EGS internals
 *   • Map to ISO 42001 control evidence
 *
 * Toru-William interface contract: Urielle may ONLY consume fields
 * defined in AuditSignalCore, AuditSignalSequence, and AuditSignalEnrichment.
 * It must not request or infer internal EGS state, model weights, or
 * raw scoring inputs.
 */

import { z } from 'zod';

// ── ADR-006: AuditSignal schema (mirrors audit-signal/src/audit-signal.ts) ──

const AuditSignalCoreSchema = z.object({
  evidenceHandle:   z.string(),
  sequenceNumber:   z.number().int().positive(),
  layer:            z.enum(['gate', 'premise', 'authority', 'continuity']),
  severity:         z.enum(['low', 'med', 'high']),
  action:           z.enum(['PASS', 'DOWNGRADE', 'BLOCK', 'FAIL_SAFE']),
  authority:        z.enum(['decision-ready', 'reference-only', 'invalid']),
  integrityScore:   z.number().min(0).max(100),
  detectionMode:    z.string(),
  routingHint:      z.string(),
  mttdMs:           z.number().min(0),
  detectedAt:       z.string().datetime(),
  storedAt:         z.string().datetime(),
  policyProfileId:  z.string(),
  partnerId:        z.string(),
  schemaVersion:    z.literal('1.0').default('1.0'),
});

const AuditSignalSequenceSchema = z.object({
  sequenceId:        z.string(),
  patternType:       z.enum(['STABLE', 'DEGRADING', 'CONTAINED', 'VOLATILE']),
  escalationDetected:z.boolean(),
  consistencyScore:  z.number().min(0).max(100),
  eventCount:        z.number().int().positive(),
  firstDetectedAt:   z.string().datetime(),
  actionChain:       z.array(z.enum(['PASS', 'DOWNGRADE', 'BLOCK', 'FAIL_SAFE'])),
  layersInvolved:    z.array(z.enum(['gate', 'premise', 'authority', 'continuity'])),
});

const AuditSignalEnrichmentSchema = z.object({
  identityRef:        z.string().optional(),
  assetRef:           z.string().optional(),
  sessionId:          z.string().optional(),
  serviceComponent:   z.string().optional(),
  tags:               z.record(z.string(), z.string()).optional(),
});

export const AuditSignalSchema = z.object({
  ...AuditSignalCoreSchema.shape,
  sequence:    AuditSignalSequenceSchema.optional(),
  enrichment:  AuditSignalEnrichmentSchema.optional(),
});

export type AuditSignal = z.infer<typeof AuditSignalSchema>;
export type AuditSignalCore = z.infer<typeof AuditSignalCoreSchema>;
export type AuditSignalSequence = z.infer<typeof AuditSignalSequenceSchema>;

// ── Evidence level derivation (Toru-William: MODERATE / STRONG logic) ──

export type EvidenceLevel = 'WEAK' | 'MODERATE' | 'STRONG';

export function evidenceLevel(signal: AuditSignal): EvidenceLevel {
  const isHighSeverityBlock = signal.severity === 'high' && signal.action === 'BLOCK';
  if (signal.sequence?.escalationDetected && isHighSeverityBlock) return 'STRONG';
  if (isHighSeverityBlock || (signal.severity === 'high') || signal.action === 'BLOCK') return 'MODERATE';
  return 'WEAK';
}

// ── Audit finding summary (human-readable for Urielle reports) ──

export function auditFindingSummary(signal: AuditSignal): string {
  const base = `Containment event detected at ${signal.layer} layer. `
    + `Severity: ${signal.severity}. `
    + `Action: ${signal.action}. `
    + `Output authority: ${signal.authority}. `
    + `Detection latency: ${signal.mttdMs}ms (SLA policy: ${signal.policyProfileId}).`;

  if (!signal.sequence) return base;

  return base + ` Sequence pattern: ${signal.sequence.patternType}. `
    + `Escalation detected: ${signal.sequence.escalationDetected}. `
    + `Consistency score: ${signal.sequence.consistencyScore}/100.`;
}

// ── ISO 42001 control mapping ──

export const ISO42001_CONTROL_MAP: Record<string, string[]> = {
  gate:        ['ISO42001-6.1.2', 'ISO42001-8.4', 'ISO42001-9.1'],
  premise:     ['ISO42001-6.1.3', 'ISO42001-8.3', 'ISO42001-9.2'],
  authority:   ['ISO42001-8.5', 'ISO42001-9.3', 'ISO42001-10.1'],
  continuity:  ['ISO42001-8.6', 'ISO42001-9.1', 'ISO42001-10.2'],
};

export function isoControlsForSignal(signal: AuditSignal): string[] {
  return ISO42001_CONTROL_MAP[signal.layer] ?? [];
}
