/**
 * @ncaos/detection — Public API
 */

// MTTD instrumentation
export { MttdTracker, DetectionRegistry, startTimer } from './mttd/tracker.js';
export type { MttdSample, MttdStats } from './mttd/tracker.js';

// Gate
export { GateDetector, DEFAULT_GATE_RULES } from './gate/gate-detector.js';
export type { GateRule, GateDetectionInput, GateDetectionResult, RulePriority } from './gate/gate-detector.js';

// Premise
export { PremiseDetector, PremiseRegistry } from './premise/premise-detector.js';
export type { PremiseDetectionInput, PremiseDetectionResult, PremiseViolation, ValidatedPremise, PremiseDefinition } from './premise/premise-detector.js';

// Authority
export { AuthorityDetector, AuthorityAuditLog } from './authority/authority-detector.js';
export type { AuthorityDetectionInput, AuthorityDetectionResult, AuthorityAuditEntry, OverrideClassification } from './authority/authority-detector.js';

// Continuity
export { ContinuityDetector } from './continuity/continuity-detector.js';
export type { ContinuityDetectionInput, ContinuityDetectionResult, EquivalenceTest, ChangeWindowState } from './continuity/continuity-detector.js';
