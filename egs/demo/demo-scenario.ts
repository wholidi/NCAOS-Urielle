/**
 * @ncaos/demo — Phase 07 Stakeholder Demo Scenario
 *
 * Structured demo script for three stakeholder audiences:
 *   1. Executive (Risk & Accountability)
 *   2. System Architect (Boundary & Decoupling)
 *   3. Legal / Compliance (Auditability)
 *   4. Toru (Audit Layer Architect) — AuditSignal interface
 *
 * Demo flow: 5 scripted API calls that build a complete governance story.
 * Each call produces observable evidence that the EGS works as designed.
 *
 * Duration: ~20 minutes with commentary, ~8 minutes without.
 */

export interface DemoStep {
  id: string;
  title: string;
  audience: string[];
  narrative: string;
  command: string;
  expectedKey: string;
  governancePoint: string;
}

export const DEMO_STEPS: DemoStep[] = [
  {
    id: 'D-01',
    title: 'Baseline — Shell Operational',
    audience: ['Executive', 'Architect', 'Legal', 'Toru'],
    narrative: 'Show the governance shell is online and active before any threat.',
    command: `Invoke-RestMethod -Uri http://localhost:3000/v1/health \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"}`,
    expectedKey: 'status=OK, watchdog=RUNNING, shell=True, slaHealthy=True',
    governancePoint: 'The EGS is operational and monitoring the AI/OS boundary. The protected core is isolated.',
  },
  {
    id: 'D-02',
    title: 'Normal Request — PASS with Authority',
    audience: ['Executive', 'Architect'],
    narrative: 'A legitimate request passes through the governance shell with full decision-ready authority.',
    command: `$clean = @{
  sourceId="enterprise-svc-001"; inputHash="sha256-clean-abc"
  inputFlags=@(); claimedPremises=@("AUTH","SCOPE","ENV")
  validatedPremises=@("AUTH","SCOPE","ENV")
  contractVersion="1.0"; requestedAuthority="decision-ready"
  policyGrantedAuthority="decision-ready"; overrideAttempted=$false
  workflowId="WF-DEMO-LIVE-001"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:3000/v1/process \`
  -Method POST -ContentType "application/json" \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"} -Body $clean`,
    expectedKey: 'action=PASS or DOWNGRADE, integrity.level=Available, authority=decision-ready',
    governancePoint: 'Clean requests pass through with full authority. RAW exposure equals GOVERNED output — no containment overhead when the boundary is clean.',
  },
  {
    id: 'D-03',
    title: 'Threat Detected — BLOCK with Evidence',
    audience: ['Executive', 'Architect', 'Legal', 'Toru'],
    narrative: 'An injection attack is detected at the gate layer. The shell blocks it, generates an evidence handle, and routes to the SOC.',
    command: `$threat = @{
  sourceId="external-attacker-2026"; inputHash="sha256-injected"
  inputFlags=@("INJECTION_PATTERN","SIGNATURE_INVALID")
  claimedPremises=@("AUTH","SCOPE","ADMIN")
  validatedPremises=@("AUTH")
  contractVersion="1.0"; requestedAuthority="decision-ready"
  policyGrantedAuthority="reference-only"; overrideAttempted=$false
  workflowId="WF-DEMO-LIVE-001"
} | ConvertTo-Json

$result = Invoke-RestMethod -Uri http://localhost:3000/v1/process \`
  -Method POST -ContentType "application/json" \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"} -Body $threat
$result
$handle = $result.evidenceHandle`,
    expectedKey: 'action=BLOCK, authority=invalid, integrity.level=Critical, evidenceHandle=EVD-...',
    governancePoint: 'The EGS blocked the request at the gate layer without touching internal model weights. The evidence handle is the audit trail entry — independent of the AI system\'s own logs.',
  },
  {
    id: 'D-04',
    title: 'Sequence Analysis — Behavioral Pattern (Toru-William)',
    audience: ['Legal', 'Toru', 'Architect'],
    narrative: 'Show the behavioral sequence from workflow WF-DEMO-LIVE-001 — escalation from PASS to BLOCK is documented as governance evidence.',
    command: `# Get full sequence
Invoke-RestMethod \`
  -Uri "http://localhost:3000/v1/events/sequence/WF-DEMO-LIVE-001" \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"}

# Get behavioral pattern summary
Invoke-RestMethod \`
  -Uri "http://localhost:3000/v1/events/sequence/WF-DEMO-LIVE-001/summary" \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"}`,
    expectedKey: 'patternType=CONTAINED, escalationDetected=True, consistencyScore≥80',
    governancePoint: 'Without accessing internal model state, the EGS produces behavioral evidence: a PASS followed by BLOCK is classified as CONTAINED — the governance shell detected and terminated an escalating threat.',
  },
  {
    id: 'D-05',
    title: 'Audit Trail — Evidence Handle Retrieval',
    audience: ['Legal', 'Toru'],
    narrative: 'Retrieve the full evidence record for the BLOCK event. This is what a compliance audit would access.',
    command: `Invoke-RestMethod \`
  -Uri "http://localhost:3000/v1/audit/$handle" \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"}`,
    expectedKey: 'layer=gate, severity=high, action=BLOCK, routingHint=SOC/Security Queue, mttdMs, detectedAt',
    governancePoint: 'The evidence record is structurally independent of the AI system\'s internal logs. A compliance auditor can verify containment without needing access to the protected core.',
  },
  {
    id: 'D-06',
    title: 'GovState — Executive Dashboard',
    audience: ['Executive'],
    narrative: 'Show the current system state — what an executive would see in real time.',
    command: `Invoke-RestMethod -Uri http://localhost:3000/v1/state \`
  -Headers @{"X-Partner-ID"="DEMO_ENT_2026"}`,
    expectedKey: 'systemStatus=ENFORCING (STRICT), operationalMode=CONTAINMENT, rawExposurePct=100, governedOutputPct<100',
    governancePoint: 'RAW_EXPOSURE is high (unmanaged system risk) but GOVERNED_OUTPUT is contained. The EGS absorbed the boundary shock — external consumers received only safe signals.',
  },
];

export function demoScript(): string {
  return DEMO_STEPS.map(s =>
    `\n${'='.repeat(60)}\n${s.id}: ${s.title}\nAudience: ${s.audience.join(', ')}\n${'-'.repeat(40)}\nNarrative: ${s.narrative}\n\nCommand:\n${s.command}\n\nExpected: ${s.expectedKey}\n\nGovernance point: ${s.governancePoint}\n`
  ).join('\n');
}
