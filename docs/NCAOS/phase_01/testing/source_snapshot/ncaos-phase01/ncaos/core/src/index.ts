/**
 * @ncaos/core — Public API
 *
 * Re-exports everything the shell, API, and UI packages need from core.
 * Import from '@ncaos/core', not from internal paths.
 */

// Type contracts (the foundation)
export * from './types/contracts.js';

// Scoring
export {
  computeIntegrity,
  computeAuthority,
  computeContainmentMetrics,
  scoreToContinuityState,
  scoreToIntegrityLevel,
  scoreToOutputAuthority,
} from './scoring/integrity.js';

// Routing
export {
  computeRouting,
  layerDisplayLabel,
  scopeDisplayLabel,
} from './engine/routing.js';

// Verdict (Enforcer)
export { enforce, failSafeVerdict } from './engine/verdict.js';

// Detection layers
export {
  detectGate,
  detectPremise,
  detectAuthority,
  detectContinuity,
} from './detection/layers.js';
export type {
  DetectionResult,
  GateInput,
  PremiseInput,
  AuthorityInput,
  ContinuityInput,
} from './detection/layers.js';

// Policy
export {
  loadPolicy,
  loadBuiltinPolicy,
  validatePolicyConsistency,
  DEFAULT_POLICY,
  BUILTIN_PROFILES,
  ENTERPRISE_STRICT_PROFILE,
  CRITICAL_STRICT_PROFILE,
  PILOT_PROFILE,
} from './policy/loader.js';

// IDs
export { generateRequestId, generateEvidenceHandle, nowIso } from './engine/ids.js';
