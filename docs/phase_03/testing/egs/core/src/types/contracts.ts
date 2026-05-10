/**
 * @ncaos/core — Shared Type Contracts
 *
 * These types form the canonical contract between all EGS layers.
 * Every module (Observer, Judge, Enforcer, API, UI) imports from here.
 * Changing these types is a breaking change — treat as a versioned API.
 *
 * Design principle: types represent the *governance shell's* view of the world,
 * never the internal model state. No root-cause inference, only impact signals.
 */

import { z } from 'zod';

// ─────────────────────────────────────────────────────────
// TENANT / IDENTITY
// ─────────────────────────────────────────────────────────

export const PartnerIdSchema = z.string().min(1).max(64).regex(/^[A-Z0-9_]+$/);
export const InstanceIdSchema = z.string().min(1).max(64).regex(/^[A-Z0-9_]+$/);
export type PartnerId = z.infer<typeof PartnerIdSchema>;
export type InstanceId = z.infer<typeof InstanceIdSchema>;

export const TenantContextSchema = z.object({
  partnerId: PartnerIdSchema,
  instanceId: InstanceIdSchema,
  deployment: z.enum(['ENTERPRISE', 'PILOT', 'SANDBOX']),
});
export type TenantContext = z.infer<typeof TenantContextSchema>;

// ─────────────────────────────────────────────────────────
// SEVERITY & SCOPE
// ─────────────────────────────────────────────────────────

/** Severity of a containment event from the shell's perspective. */
export const SeveritySchema = z.enum(['low', 'med', 'high']);
export type Severity = z.infer<typeof SeveritySchema>;

/**
 * Scope of a containment event.
 * req  = Single Request (isolated to one I/O transaction)
 * flow = Workflow-Level (affects a multi-step workflow)
 * sys  = System-Wide (shell is in full containment mode)
 */
export const ImpactScopeSchema = z.enum(['req', 'flow', 'sys']);
export type ImpactScope = z.infer<typeof ImpactScopeSchema>;

// ─────────────────────────────────────────────────────────
// DETECTION LAYERS
// ─────────────────────────────────────────────────────────

/**
 * The four independent containment layers of the EGS.
 * Each maps to a distinct detection module in /core/src/detection/.
 */
export const ContainmentLayerSchema = z.enum([
  'gate',       // External Gate: I/O boundary enforcement
  'premise',    // Premise Consistency: semantic contract validation
  'authority',  // Authority Boundary: output authority state machine
  'continuity', // Continuity Watch: post-update equivalence testing
]);
export type ContainmentLayer = z.infer<typeof ContainmentLayerSchema>;

export const DetectionModeSchema = z.enum([
  'Real-time Gate Enforcement',
  'Premise Constraint Check',
  'Authority Boundary Enforcement',
  'Post-Update Watch',
]);
export type DetectionMode = z.infer<typeof DetectionModeSchema>;

/** Maps each layer to its canonical detection mode label. */
export const LAYER_DETECTION_MODE: Record<ContainmentLayer, DetectionMode> = {
  gate: 'Real-time Gate Enforcement',
  premise: 'Premise Constraint Check',
  authority: 'Authority Boundary Enforcement',
  continuity: 'Post-Update Watch',
};

// ─────────────────────────────────────────────────────────
// INTEGRITY
// ─────────────────────────────────────────────────────────

/**
 * Integrity level — reflects impact only.
 * Does NOT report internal model state or root cause.
 */
export const IntegrityLevelSchema = z.enum([
  'Available',  // Score 80–100: normal operation
  'Limited',    // Score 60–79: reduced but functional
  'Degraded',   // Score 40–59: significantly impaired
  'Critical',   // Score 0–39:  containment required
]);
export type IntegrityLevel = z.infer<typeof IntegrityLevelSchema>;

export const IntegrityStateSchema = z.object({
  level: IntegrityLevelSchema,
  score: z.number().int().min(0).max(100),
});
export type IntegrityState = z.infer<typeof IntegrityStateSchema>;

// ─────────────────────────────────────────────────────────
// OUTPUT AUTHORITY
// ─────────────────────────────────────────────────────────

/**
 * Authority granted to governed output.
 * Determined structurally by the shell — not by internal self-reporting.
 *
 * decision-ready  = Output is authoritative for downstream decisions
 * reference-only  = Output may be consulted but not acted upon
 * invalid         = Output must not be used; containment in effect
 */
export const OutputAuthoritySchema = z.enum([
  'decision-ready',
  'reference-only',
  'invalid',
]);
export type OutputAuthority = z.infer<typeof OutputAuthoritySchema>;

export const AuthorityStateSchema = z.object({
  authority: OutputAuthoritySchema,
  score: z.number().int().min(0).max(100),
});
export type AuthorityState = z.infer<typeof AuthorityStateSchema>;

// ─────────────────────────────────────────────────────────
// ROUTING
// ─────────────────────────────────────────────────────────

export const RoutingHintSchema = z.enum([
  'SOC / Security Queue',
  'Architecture / Requirements Review',
  'Governance / Policy Review',
  'Change Mgmt / Rollback Path',
]);
export type RoutingHint = z.infer<typeof RoutingHintSchema>;

export const RoutingDecisionSchema = z.object({
  hint: RoutingHintSchema,
  recommendedAction: z.string().min(1).max(512),
});
export type RoutingDecision = z.infer<typeof RoutingDecisionSchema>;

// ─────────────────────────────────────────────────────────
// GOVERNANCE EVENT
// ─────────────────────────────────────────────────────────

/** A unique request identifier. Format: REQ-XXXXXX */
export const RequestIdSchema = z.string().regex(/^REQ-\d{6,}$/);
export type RequestId = z.infer<typeof RequestIdSchema>;

/** An evidence handle for audit retrieval. Format: EVD-{timestamp}-{hash} */
export const EvidenceHandleSchema = z.string().regex(/^EVD-\d+-[A-Z0-9]+$/);
export type EvidenceHandle = z.infer<typeof EvidenceHandleSchema>;

/**
 * GovEvent — the canonical event emitted by a detection module.
 * This is the primary unit of work flowing through the EGS.
 */
export const GovEventSchema = z.object({
  // Identity
  requestId: RequestIdSchema,
  workflowId: z.string().optional(),
  evidenceHandle: EvidenceHandleSchema,
  tenant: TenantContextSchema,

  // Classification
  type: z.string().min(1).max(128),         // e.g. 'EXTERNAL_THREAT_BLOCKED'
  layer: ContainmentLayerSchema,
  scope: ImpactScopeSchema,
  severity: SeveritySchema,
  detectionMode: DetectionModeSchema,

  // Impact signals (NO root-cause inference)
  integrity: IntegrityStateSchema,
  authority: AuthorityStateSchema,
  routing: RoutingDecisionSchema,

  // Affected service (for admin triage)
  affectedService: z.string().optional(),

  // Temporal
  detectedAt: z.string().datetime(),        // ISO 8601
  mttdMs: z.number().int().min(0),          // Mean time to detection in ms

  // Human-readable note (structural label only)
  note: z.string().max(512).optional(),
});
export type GovEvent = z.infer<typeof GovEventSchema>;

// ─────────────────────────────────────────────────────────
// GOVERNANCE STATE
// ─────────────────────────────────────────────────────────

/**
 * The live operational state of the EGS instance.
 * Published over WebSocket to the Admin Terminal.
 */
export const OperationalModeSchema = z.enum(['NORMAL', 'LIMITED', 'CONTAINMENT']);
export type OperationalMode = z.infer<typeof OperationalModeSchema>;

export const GovStateSchema = z.object({
  tenant: TenantContextSchema,
  systemStatus: z.enum(['ENFORCING', 'ENFORCING (LIMITED)', 'ENFORCING (STRICT)', 'FAIL_SAFE']),
  operationalMode: OperationalModeSchema,

  // Shell integrity
  shellIntegrity: z.boolean(),              // EGS layer is operational
  failSafeEnabled: z.boolean(),             // Defaults to deny on failure

  // Current readings
  integrity: IntegrityStateSchema,
  authority: AuthorityStateSchema,

  // Containment metrics (illustrative signals, not internal model state)
  rawExposurePct: z.number().min(0).max(100),
  governedOutputPct: z.number().min(0).max(100),
  coreIsolationPct: z.number().min(0).max(100),
  contextDriftPressurePct: z.number().min(0).max(100),
  latencyOverheadMs: z.number().min(0),

  // Continuity
  updateState: z.enum(['STABLE', 'PROVISIONAL', 'UNSTABLE']),
  continuityScore: z.number().int().min(0).max(100),
  lastUpdateAt: z.string().datetime().optional(),
  changeWindowActive: z.boolean(),
  equivalenceTests: z.object({
    passed: z.number().int().min(0),
    total: z.number().int().min(0),
  }),

  // Active event summary
  activeEvent: z.string().optional(),       // e.g. 'PREMISE_MISMATCH / HIGH'
  lastRouting: RoutingHintSchema.optional(),
  blockedLayer: ContainmentLayerSchema.optional(),

  updatedAt: z.string().datetime(),
});
export type GovState = z.infer<typeof GovStateSchema>;

// ─────────────────────────────────────────────────────────
// POLICY PROFILE
// ─────────────────────────────────────────────────────────

/**
 * PolicyProfile — defines the enforcement configuration for a tenant instance.
 * Loaded by the Policy Loader module; validated at startup.
 *
 * Enterprise responsibilities: defining thresholds and acceptable behavior baselines.
 * EGS responsibilities: enforcing those thresholds structurally.
 */
export const GovLevelSchema = z.enum([
  'CRITICAL_STRICT',    // Maximum enforcement — containment on any anomaly
  'ENTERPRISE_STRICT',  // Enterprise default — fail on medium+ severity
  'ENTERPRISE_RELAXED', // Reduced sensitivity — fail on high severity only
  'PILOT',              // Pilot mode — observe and report, minimal blocking
]);
export type GovLevel = z.infer<typeof GovLevelSchema>;

export const PolicyProfileSchema = z.object({
  profileId: z.string().regex(/^[A-Z0-9_-]+$/),
  label: z.string().max(64),                  // e.g. 'STRICT-PROD'
  govLevel: GovLevelSchema,

  // Integrity thresholds — below these scores, authority is downgraded
  integrityThresholds: z.object({
    available: z.number().int().min(0).max(100),   // Default: 80
    limited: z.number().int().min(0).max(100),     // Default: 60
    degraded: z.number().int().min(0).max(100),    // Default: 40
    // Below degraded → Critical
  }),

  // Continuity thresholds
  continuityThresholds: z.object({
    stable: z.number().int().min(0).max(100),      // Default: 75
    provisional: z.number().int().min(0).max(100), // Default: 55
    // Below provisional → Unstable
  }),

  // MTTD SLA in milliseconds per layer
  mttdSlaMs: z.object({
    gate: z.number().int().min(0),
    premise: z.number().int().min(0),
    authority: z.number().int().min(0),
    continuity: z.number().int().min(0),
  }),

  // Whether to block (true) or observe-and-report (false) on containment trigger
  blockOnContainment: z.boolean(),

  // Tenancy
  partnerId: PartnerIdSchema,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type PolicyProfile = z.infer<typeof PolicyProfileSchema>;

// ─────────────────────────────────────────────────────────
// VERDICT
// ─────────────────────────────────────────────────────────

/**
 * Verdict — the Enforcer's output for a given request.
 * Determines what the external environment receives.
 */
export const VerdictActionSchema = z.enum([
  'PASS',             // Output is decision-ready; no containment
  'DOWNGRADE',        // Output is reference-only; integrity limited
  'BLOCK',            // Output is invalid; request blocked
  'FAIL_SAFE',        // Shell failure — default deny triggered
]);
export type VerdictAction = z.infer<typeof VerdictActionSchema>;

export const VerdictSchema = z.object({
  requestId: RequestIdSchema,
  action: VerdictActionSchema,
  authority: OutputAuthoritySchema,
  integrity: IntegrityStateSchema,
  routing: RoutingDecisionSchema.optional(),  // Present when action != PASS
  policyProfileId: z.string(),
  enforcedAt: z.string().datetime(),
  processingMs: z.number().int().min(0),
});
export type Verdict = z.infer<typeof VerdictSchema>;
