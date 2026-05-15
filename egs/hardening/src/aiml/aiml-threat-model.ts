/**
 * @ncaos/hardening — AI/ML Threat Model
 *
 * Threats specific to AI governance systems that do not appear in
 * standard STRIDE analysis. The EGS governs AI/OS boundary outputs —
 * attackers who understand ML systems may attempt to exploit the
 * governance layer itself.
 *
 * Categories:
 *   ADV  — Adversarial Input attacks (crafted to evade detection)
 *   DRF  — Model/System Drift exploitation
 *   CTX  — Context Manipulation (premise poisoning, authority gaming)
 *   PRB  — Probe attacks (learning detection thresholds)
 *   PLY  — Policy Gaming (exploiting governance configuration)
 */

export type AiMlThreatCategory =
  | 'AdversarialInput'
  | 'DriftExploitation'
  | 'ModelDrift'
  | 'ContextManipulation'
  | 'ProbeAttack'
  | 'PolicyGaming';

export interface AiMlThreat {
  id: string;
  category: AiMlThreatCategory;
  threat: string;
  attackVector: string;
  whyDangerousForGovernance: string;
  currentDetection: string;
  residualRisk: 'HIGH' | 'MED' | 'LOW';
  mitigationStrategy: string;
  egsMitigation: string;
  testRef?: string;
}

export const AIML_THREATS: AiMlThreat[] = [

  // ── ADVERSARIAL INPUT ─────────────────────────────────────────────────────

  {
    id: 'ADV-001',
    category: 'AdversarialInput',
    threat: 'Threshold boundary probing — crafting inputs that score just below gate detection thresholds',
    attackVector: 'Iteratively adjust inputFlags to find the exact combination that produces DOWNGRADE instead of BLOCK',
    whyDangerousForGovernance: 'Attacker learns the exact governance boundary and operates just below it indefinitely',
    currentDetection: 'PremiseDetector weights and GateDetector rules are static — no anomaly detection on borderline scores',
    residualRisk: 'HIGH',
    mitigationStrategy: 'Add jitter to scoring thresholds per-tenant; flag repeated borderline requests as a pattern',
    egsMitigation: 'Add jitter to scoring thresholds per-tenant; flag repeated borderline requests as a pattern',
    testRef: 'PT-PRB-001',
  },
  {
    id: 'ADV-002',
    category: 'AdversarialInput',
    threat: 'Flag fragmentation — splitting a critical pattern across multiple requests below detection threshold',
    attackVector: 'Send RATE_EXCEEDED in request 1, SCHEMA_VIOLATION in request 2 — each triggers MED not HIGH',
    whyDangerousForGovernance: 'Individual signals appear benign; combined they represent INJECTION_PATTERN equivalent',
    currentDetection: 'Gate rules are per-request; no cross-request pattern aggregation in Phase 04/05',
    residualRisk: 'HIGH',
    mitigationStrategy: 'Phase 07: add sliding-window cross-request flag aggregation per tenant',
    egsMitigation: 'Phase 07: add sliding-window cross-request flag aggregation per tenant',
    testRef: 'PT-PRB-002',
  },
  {
    id: 'ADV-003',
    category: 'AdversarialInput',
    threat: 'Continuity score manipulation — claiming all equivalence tests pass to avoid continuity detection',
    attackVector: 'Set equivalenceTestResults=[{testId: "T1", passed: true}...all true] regardless of actual state',
    whyDangerousForGovernance: 'ContinuityDetector relies on caller-provided test results — it cannot verify them',
    currentDetection: 'No independent verification of equivalenceTestResults — values are trusted',
    residualRisk: 'MED',
    mitigationStrategy: 'Phase 07: EGS generates its own equivalence test probes; caller-provided results are supplemental only',
    egsMitigation: 'Phase 07: EGS generates its own equivalence test probes; caller-provided results are supplemental only',
    testRef: 'PT-PRB-003',
  },

  // ── DRIFT EXPLOITATION ────────────────────────────────────────────────────

  {
    id: 'DRF-001',
//  category: 'DriftExploitation',
    category: 'ModelDrift',
    threat: 'Gradual contextDriftPressure inflation to normalize HIGH-drift states',
    attackVector: 'Send requests with slowly increasing drift pressure over days/weeks until HIGH becomes baseline',
    whyDangerousForGovernance: 'If operators become accustomed to high drift, they may suppress or ignore alerts',
    currentDetection: 'contextDriftPressurePct is a computed metric — no historical baseline comparison',
    residualRisk: 'MED',
    mitigationStrategy: 'Add 7-day rolling baseline for contextDriftPressurePct; alert on deviation > 2σ',
    egsMitigation: 'Add 7-day rolling baseline for contextDriftPressurePct; alert on deviation > 2σ',
    testRef: 'PT-DRF-001',
  },
  {
    id: 'DRF-002',
//  category: 'DriftExploitation',
    category: 'ModelDrift',
    threat: 'Update window exploitation — submitting malicious requests during continuity WATCHING state',
    attackVector: 'Detect when changeWindowActive=true (via /v1/state), then submit high-severity requests during this window',
    whyDangerousForGovernance: 'Operators may be focused on equivalence test results and less attentive to other signals',
    currentDetection: 'Detection layers still active during change window — no blind spot technically',
    residualRisk: 'LOW',
    mitigationStrategy: 'Increase alert sensitivity during change windows; document in operations runbook',
    egsMitigation: 'Increase alert sensitivity during change windows; document in operations runbook',
  },

  // ── CONTEXT MANIPULATION ─────────────────────────────────────────────────

  {
    id: 'CTX-001',
    category: 'ContextManipulation',
    threat: 'Premise inflation — claiming more validated premises than actually exist',
    attackVector: 'Set claimedPremises=["P-AUTH","P-SCOPE","P-ENV","P-RATE"] and validatedPremises=[...same] with false validation',
    whyDangerousForGovernance: 'PremiseDetector grants legitimacy based on caller-provided validated list — no external verification',
    currentDetection: 'PremiseRegistry tracks per-workflow validation but cannot verify external truth of claims',
    residualRisk: 'HIGH',
    mitigationStrategy: 'Phase 07: external premise verification endpoint — EGS validates claims against authoritative source',
    egsMitigation: 'Phase 07: external premise verification endpoint — EGS validates claims against authoritative source',
    testRef: 'PT-CTX-001',
  },
  {
    id: 'CTX-002',
    category: 'ContextManipulation',
    threat: 'Authority anchoring — establishing high authority in early requests to anchor chain expectations',
    attackVector: 'Send legitimate decision-ready requests to build authority history, then gradually downgrade input quality',
    whyDangerousForGovernance: 'AuthorityDetector chain constraint prevents upgrades but allows maintaining high authority across a session',
    currentDetection: 'Chain constraint enforced per-request but no session-level authority decay',
    residualRisk: 'MED',
    mitigationStrategy: 'Add authority TTL — decision-ready authority expires after configurable session window',
    egsMitigation: 'Add authority TTL — decision-ready authority expires after configurable session window',
  },
  {
    id: 'CTX-003',
    category: 'ContextManipulation',
    threat: 'Workflow ID collision — using another tenant\'s workflowId to poison their sequence analysis',
    attackVector: 'Guess or enumerate workflowId of TENANT_B and send requests with that workflowId as TENANT_A',
    whyDangerousForGovernance: 'Would corrupt TENANT_B\'s sequence summary with TENANT_A\'s events',
    currentDetection: 'Sequence index is keyed by sequenceId only — not by partnerId+sequenceId',
    residualRisk: 'MED',
    mitigationStrategy: 'Key sequence index by ${partnerId}:${sequenceId} — prevents cross-tenant contamination',
    egsMitigation: 'Key sequence index by ${partnerId}:${sequenceId} — prevents cross-tenant contamination',
    testRef: 'PT-CTX-002',
  },

  // ── PROBE ATTACKS ─────────────────────────────────────────────────────────

  {
    id: 'PRB-001',
    category: 'ProbeAttack',
    threat: 'MTTD timing attack — inferring detection rule complexity from response latency',
    attackVector: 'Send requests with varying inputFlags combinations and measure mttdMs in response',
    whyDangerousForGovernance: 'Timing variations reveal which rules are computationally expensive',
    currentDetection: 'mttdMs is included in API response — no jitter or suppression',
    residualRisk: 'LOW',
    mitigationStrategy: 'Round mttdMs to nearest 5ms in API responses; suppress for non-admin callers',
    egsMitigation: 'Round mttdMs to nearest 5ms in API responses; suppress for non-admin callers',
  },
  {
    id: 'PRB-002',
    category: 'ProbeAttack',
    threat: 'Policy profile enumeration — probing governance response to learn active policy thresholds',
    attackVector: 'Send requests with varying integrityScore values to infer threshold boundaries',
    whyDangerousForGovernance: 'Attacker learns exact integrityThresholds.available/limited/degraded values',
    currentDetection: '/v1/policy returns full PolicyProfile including all thresholds to any authenticated caller',
    residualRisk: 'MED',
    mitigationStrategy: 'Restrict /v1/policy threshold details to admin role; expose only profileId/govLevel to standard callers',
    egsMitigation: 'Restrict /v1/policy threshold details to admin role; expose only profileId/govLevel to standard callers'
  },

  // ── POLICY GAMING ─────────────────────────────────────────────────────────

  {
    id: 'PLY-001',
    category: 'PolicyGaming',
    threat: 'Policy cycling — rapidly alternating between STRICT and PILOT policies to create enforcement blind spots',
    attackVector: 'POST /v1/policy with PILOT → submit malicious request → POST /v1/policy with STRICT',
    whyDangerousForGovernance: 'Malicious request processed under PILOT (blockOnContainment=false) evades blocking',
    currentDetection: 'PolicyStore records history but no rate limit on policy changes',
    residualRisk: 'HIGH',
    mitigationStrategy: 'Add cooldown period between policy changes (min 5 minutes); require admin JWT (links to T-002)',
    egsMitigation: 'Add cooldown period between policy changes (min 5 minutes); require admin JWT (links to T-002)',
    testRef: 'PT-PLY-001',
  },
  {
    id: 'PLY-002',
    category: 'PolicyGaming',
    threat: 'SLA relaxation — updating mttdSlaMs to very high values to suppress SLA breach alerts',
    attackVector: 'POST /v1/policy with mttdSlaMs.gate=999999 to make MTTD always appear within SLA',
    whyDangerousForGovernance: 'isSlaHealthy() always returns true; detection degradation goes unnoticed',
    currentDetection: 'No validation floor on mttdSlaMs values — any positive number accepted',
    residualRisk: 'MED',
    mitigationStrategy: 'Add min/max bounds on mttdSlaMs in Zod schema (e.g. gate: min=10ms, max=500ms)',
    egsMitigation: 'Add min/max bounds on mttdSlaMs in Zod schema (e.g. gate: min=10ms, max=500ms)',
  },
];

export function aimlSummary() {
  const byCategory: Record<string, number> = {};
  const byRisk: Record<string, number> = {};

  for (const t of AIML_THREATS) {
    byCategory[t.category] = (byCategory[t.category] ?? 0) + 1;
    byRisk[t.residualRisk] = (byRisk[t.residualRisk] ?? 0) + 1;
  }

  return {
    total: AIML_THREATS.length,
    byCategory,
    byRisk,
    highRiskItems: AIML_THREATS.filter(t => t.residualRisk === 'HIGH'),
  };
}
