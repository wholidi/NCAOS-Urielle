/**
 * @ncaos/hardening — Phase 06 Public API
 */

// STRIDE threat model
export { STRIDE_THREATS } from './stride/stride-model.js';
export type { StrideThreat, StrideCategory, RiskLevel } from './stride/stride-model.js';

// AI/ML threat model
export { AIML_THREATS } from './aiml/aiml-threat-model.js';
export type { AiMlThreat } from './aiml/aiml-threat-model.js';

// JWT + Rate limiting
export { verifyJwt, rateLimitMiddleware, RateLimiter, rateLimiter } from './jwt/auth-middleware.js';
export type { JwtPayload, JwtRole, AuthContext } from './jwt/auth-middleware.js';

// Pen test scenarios
export { PEN_TEST_SCENARIOS, penTestSummary } from './pentest/pentest-scenarios.js';
export type { PenTestScenario } from './pentest/pentest-scenarios.js';

// ISO 42001 mapping
export { ISO42001_CONTROLS, iso42001Summary, controlsByClause } from './iso42001/iso42001-mapping.js';
export type { Iso42001Control, EvidenceStrength, ComplianceStatus } from './iso42001/iso42001-mapping.js';

// Chaos test harness (ADR-002 validation)
export { ChaosTestHarness, CHAOS_SCENARIOS } from './chaos/chaos-harness.js';
export type { ChaosScenario, ChaosResult, ChaosScenarioId } from './chaos/chaos-harness.js';
