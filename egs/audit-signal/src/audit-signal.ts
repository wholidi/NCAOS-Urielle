/**
 * @ncaos/audit-signal — AuditSignal Schema
 *
 * The formal typed contract between the NCAOS EGS boundary layer
 * and the Urielle audit interpretation layer.
 *
 * Toru-William Interface Definition (Phase 05 deliverable)
 *
 * Design philosophy (from the Toru-William discussion):
 * "The depth of audit is largely a function of how well events are defined
 *  and structured. Strong consistency across event sequences can serve as
 *  indirect but sufficient evidence."
 *
 * Structure:
 *   AuditSignal
 *   ├── core (always present — minimum viable signal layer)
 *   │     Contains the irreducible minimum for meaningful governance evidence
 *   ├── sequence (present when workflowId provided)
 *   │     Enables behavioral pattern analysis without internal visibility
 *   └── enrichment (optional — identity, asset, session context)
 *         Enhances audit depth without breaking the boundary
 *
 * The boundary is strictly maintained:
 * - AuditSignal contains ONLY what the governance shell can observe
 * - No internal model state, no root-cause inference
 * - Urielle NEVER accesses @ncaos/shell or @ncaos/detection directly
 */

import { z } from 'zod';

// ─────────────────────────────────────────────────────────
// CORE LAYER — minimum viable signal layer
// Always present. Every AuditSignal has these fields.
// ─────────────────────────────────────────────────────────

export const AuditSignalCoreSchema = z.object({
  /**
   * Unique reference for this governance event.
   * Format: EVD-{timestamp}-{hash}
   * Used as the primary key in Urielle audit records.
   */
  evidenceHandle: z.string().regex(/^EVD-\d+-[A-Z0-9]+$/),

  /**
   * Sequential number within the tenant's event log.
   * Enables Urielle to detect gaps (missing events) in the audit trail.
   */
  sequenceNumber: z.number().int().min(1),

  /**
   * The containment layer that triggered this event.
   * gate | premise | authority | continuity
   * Tells Urielle WHICH governance mechanism was engaged.
   */
  layer: z.enum(['gate', 'premise', 'authority', 'continuity']),

  /**
   * Severity of the detected anomaly from the shell's perspective.
   * Impact signal only — not a root-cause claim.
   */
  severity: z.enum(['low', 'med', 'high']),

  /**
   * The enforcement decision made by the shell.
   * PASS | DOWNGRADE | BLOCK | FAIL_SAFE
   */
  action: z.enum(['PASS', 'DOWNGRADE', 'BLOCK', 'FAIL_SAFE']),

  /**
   * The output authority state granted by the shell.
   * Structurally determined — not internal self-reporting.
   */
  authority: z.enum(['decision-ready', 'reference-only', 'invalid']),

  /**
   * Integrity score at time of detection (0–100).
   * Reflects impact level — not internal model state.
   */
  integrityScore: z.number().int().min(0).max(100),

  /**
   * The detection mode label for this layer.
   * Structural label only — no internal logic exposed.
   */
  detectionMode: z.string(),

  /**
   * Triage routing decision.
   * Tells Urielle WHERE to route this finding for response.
   */
  routingHint: z.enum([
    'SOC / Security Queue',
    'Architecture / Requirements Review',
    'Governance / Policy Review',
    'Change Mgmt / Rollback Path',
  ]),

  /**
   * Mean time to detection in milliseconds.
   * Structural performance metric — enables Urielle to assess
   * whether detection latency itself is a governance concern.
   */
  mttdMs: z.number().min(0),

  /**
   * ISO 8601 timestamp when the anomaly was detected.
   * Temporal boundary only — no causality claims.
   */
  detectedAt: z.string().datetime(),

  /**
   * ISO 8601 timestamp when this signal was stored.
   * Enables Urielle to detect processing delays.
   */
  storedAt: z.string().datetime(),

  /**
   * The active governance policy profile at time of detection.
   * Tells Urielle WHAT rules were in force.
   */
  policyProfileId: z.string(),

  /**
   * Tenant identifier.
   */
  partnerId: z.string(),
});

export type AuditSignalCore = z.infer<typeof AuditSignalCoreSchema>;

// ─────────────────────────────────────────────────────────
// SEQUENCE LAYER — behavioral pattern signals
// Present when workflowId is provided by the caller.
// Enables sequence-level interpretation (Toru-William).
// ─────────────────────────────────────────────────────────

export const AuditSignalSequenceSchema = z.object({
  /**
   * Workflow identifier — groups related events into a behavioral sequence.
   * Derived from the caller's workflowId field.
   */
  sequenceId: z.string(),

  /**
   * Behavioral pattern classification for the sequence.
   * STABLE    — all enforcement decisions consistent, no escalation
   * DEGRADING — progressive severity increase over sequence
   * CONTAINED — escalation detected and terminated by BLOCK
   * VOLATILE  — mixed severity without clear pattern
   * UNKNOWN   — insufficient events to classify
   */
  patternType: z.enum(['STABLE', 'DEGRADING', 'CONTAINED', 'VOLATILE', 'UNKNOWN']),

  /**
   * Whether enforcement severity increased over the sequence.
   * PASS→DOWNGRADE→BLOCK = escalation detected.
   * Key audit evidence: did the system respond appropriately to escalation?
   */
  escalationDetected: z.boolean(),

  /**
   * Consistency score (0–100) for enforcement across the sequence.
   * High score = consistent enforcement decisions.
   * Low score = volatile or contradictory enforcement.
   */
  consistencyScore: z.number().int().min(0).max(100),

  /**
   * Total events in this sequence at time of this signal.
   */
  eventCount: z.number().int().min(1),

  /**
   * Timestamp of first event in the sequence.
   */
  firstDetectedAt: z.string().datetime(),

  /**
   * All enforcement actions taken in sequence order.
   * Enables Urielle to reconstruct the full decision chain.
   */
  actionChain: z.array(z.enum(['PASS', 'DOWNGRADE', 'BLOCK', 'FAIL_SAFE'])),

  /**
   * All detection layers involved in this sequence.
   * Multiple layers = multi-vector threat pattern.
   */
  layersInvolved: z.array(z.enum(['gate', 'premise', 'authority', 'continuity'])),
});

export type AuditSignalSequence = z.infer<typeof AuditSignalSequenceSchema>;

// ─────────────────────────────────────────────────────────
// ENRICHMENT LAYER — optional context fields
// Present only when provided by the caller.
// Enhances audit depth without breaking the boundary.
// ─────────────────────────────────────────────────────────

export const AuditSignalEnrichmentSchema = z.object({
  /**
   * Identity reference — WHO made the request.
   * Opaque reference only — Urielle does not resolve identity.
   * The boundary is: EGS observed a request from this identity reference.
   */
  identityRef: z.string().optional(),

  /**
   * Asset reference — WHAT asset was being accessed.
   * Opaque reference — Urielle does not access the asset.
   */
  assetRef: z.string().optional(),

  /**
   * Session identifier — groups requests within a user session.
   * Enables session-level pattern analysis.
   */
  sessionId: z.string().optional(),

  /**
   * Application or service component that generated the request.
   * For administrative triage — matches AFFECTED_SERVICE in PoC UI.
   */
  serviceComponent: z.string().optional(),

  /**
   * Free-form tags for additional context.
   * Key-value pairs — values are strings only.
   */
  tags: z.record(z.string()).optional(),
}).optional();

export type AuditSignalEnrichment = z.infer<typeof AuditSignalEnrichmentSchema>;

// ─────────────────────────────────────────────────────────
// COMPLETE AUDIT SIGNAL
// ─────────────────────────────────────────────────────────

export const AuditSignalSchema = z.object({
  /** Schema version — enables Urielle to handle schema evolution */
  schemaVersion: z.literal('1.0'),

  /** Core layer — always present */
  core: AuditSignalCoreSchema,

  /** Sequence layer — present when workflowId provided */
  sequence: AuditSignalSequenceSchema.optional(),

  /** Enrichment layer — present when caller provides identity/asset/session */
  enrichment: AuditSignalEnrichmentSchema,
});

export type AuditSignal = z.infer<typeof AuditSignalSchema>;

// ─────────────────────────────────────────────────────────
// FACTORY — construct AuditSignal from API EventRecord
// ─────────────────────────────────────────────────────────

/**
 * fromEventRecord() — converts a NCAOS API EventRecord into an AuditSignal.
 *
 * This is the primary consumption point for the Urielle audit layer.
 * Call this when fetching events from GET /v1/audit/:handle or GET /v1/events.
 *
 * The sequence layer is populated by fetching GET /v1/events/sequence/:id/summary.
 */
export function fromEventRecord(
  record: {
    evidenceHandle: string;
    sequenceNumber: number;
    storedAt: string;
    partnerId: string;
    event: {
      layer: string;
      severity: string;
      detectionMode: string;
      integrity: { score: number };
      routing: { hint: string };
      mttdMs: number;
      detectedAt: string;
      workflowId?: string;
    };
    verdict: {
      action: string;
      authority: string;
      policyProfileId?: string;
    };
    sequenceId?: string;
  },
  sequence?: {
    patternType: string;
    escalationDetected: boolean;
    consistencyScore: number;
    eventCount: number;
    firstDetectedAt: string;
    actions: string[];
    layers: string[];
  },
  enrichment?: {
    identityRef?: string;
    assetRef?: string;
    sessionId?: string;
    serviceComponent?: string;
    tags?: Record<string, string>;
  },
): AuditSignal {
  const core: AuditSignalCore = {
    evidenceHandle: record.evidenceHandle as `EVD-${string}`,
    sequenceNumber: record.sequenceNumber,
    layer: record.event.layer as AuditSignalCore['layer'],
    severity: record.event.severity as AuditSignalCore['severity'],
    action: record.verdict.action as AuditSignalCore['action'],
    authority: record.verdict.authority as AuditSignalCore['authority'],
    integrityScore: record.event.integrity.score,
    detectionMode: record.event.detectionMode,
    routingHint: record.event.routing.hint as AuditSignalCore['routingHint'],
    mttdMs: record.event.mttdMs,
    detectedAt: record.event.detectedAt,
    storedAt: record.storedAt,
    policyProfileId: record.verdict.policyProfileId ?? 'UNKNOWN',
    partnerId: record.partnerId,
  };

  const seq: AuditSignalSequence | undefined = sequence && record.sequenceId ? {
    sequenceId: record.sequenceId,
    patternType: sequence.patternType as AuditSignalSequence['patternType'],
    escalationDetected: sequence.escalationDetected,
    consistencyScore: sequence.consistencyScore,
    eventCount: sequence.eventCount,
    firstDetectedAt: sequence.firstDetectedAt,
    actionChain: sequence.actions as AuditSignalSequence['actionChain'],
    layersInvolved: sequence.layers as AuditSignalSequence['layersInvolved'],
  } : undefined;

  return AuditSignalSchema.parse({
    schemaVersion: '1.0',
    core,
    sequence: seq,
    enrichment: enrichment ?? undefined,
  });
}

// ─────────────────────────────────────────────────────────
// AUDIT CONCLUSION HELPERS
// Helper functions for Urielle to derive governance evidence
// from AuditSignal data without internal visibility.
// ─────────────────────────────────────────────────────────

/**
 * Returns a governance evidence level based on the AuditSignal.
 * STRONG  — multiple signals corroborate a clear pattern
 * MODERATE — single high-severity event or partial pattern
 * WEAK    — low-severity events, insufficient pattern data
 */
export function evidenceLevel(signal: AuditSignal): 'STRONG' | 'MODERATE' | 'WEAK' {
  const { core, sequence } = signal;
  if (core.severity === 'high' && core.action === 'BLOCK' &&
      sequence?.escalationDetected && sequence.consistencyScore >= 80) {
    return 'STRONG';
  }
  if (core.severity === 'high' || core.action === 'BLOCK' ||
      sequence?.patternType === 'CONTAINED') {
    return 'MODERATE';
  }
  return 'WEAK';
}

/**
 * Returns a human-readable audit finding summary.
 * Suitable for inclusion in a formal governance report.
 */
export function auditFindingSummary(signal: AuditSignal): string {
  const { core, sequence } = signal;
  const base = `Containment event detected at ${core.layer} layer. ` +
    `Severity: ${core.severity}. Action: ${core.action}. ` +
    `Output authority: ${core.authority}. ` +
    `Detection latency: ${core.mttdMs.toFixed(1)}ms (SLA policy: ${core.policyProfileId}).`;

  if (!sequence) return base;

  return base + ` Sequence analysis (${sequence.sequenceId}): ` +
    `${sequence.eventCount} events, pattern=${sequence.patternType}, ` +
    `escalation=${sequence.escalationDetected ? 'detected' : 'none'}, ` +
    `consistency=${sequence.consistencyScore}/100.`;
}

/**
 * ISO 42001 control reference mapping.
 * Maps AuditSignal fields to ISO 42001 AI management system controls.
 * Enables Urielle to generate structured compliance evidence.
 */
export const ISO42001_CONTROL_MAP: Record<AuditSignalCore['layer'], string[]> = {
  gate:        ['ISO42001-6.1.2', 'ISO42001-8.4',  'ISO42001-9.1'],  // Risk identification, AI system operation, Monitoring
  premise:     ['ISO42001-6.1.3', 'ISO42001-8.3',  'ISO42001-9.2'],  // Risk assessment, AI system design, Internal audit
  authority:   ['ISO42001-6.2',   'ISO42001-8.5',  'ISO42001-10.1'], // AI objectives, AI system deployment, Nonconformity
  continuity:  ['ISO42001-8.6',   'ISO42001-9.3',  'ISO42001-10.2'], // AI system maintenance, Management review, Improvement
};
