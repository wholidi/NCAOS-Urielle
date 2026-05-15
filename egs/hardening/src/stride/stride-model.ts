/**
 * @ncaos/hardening — STRIDE Threat Model
 *
 * Systematic threat analysis for the External Governance Shell (EGS).
 * STRIDE categories: Spoofing, Tampering, Repudiation, Information Disclosure,
 *                    Denial of Service, Elevation of Privilege
 *
 * Scope: All four EGS layers + API surface + WebSocket stream + Tenant isolation
 *
 * Each threat entry includes:
 *   - Threat ID and category
 *   - Affected component
 *   - Attack vector
 *   - Current mitigation
 *   - Residual risk (HIGH/MED/LOW)
 *   - Test reference (links to pentest scenario)
 */

export type StrideCategory =
  | 'Spoofing'
  | 'Tampering'
  | 'Repudiation'
  | 'InformationDisclosure'
  | 'DenialOfService'
  | 'ElevationOfPrivilege';

export type RiskLevel = 'HIGH' | 'MED' | 'LOW' | 'ACCEPTED';

export interface StrideThreat {
  id: string;
  category: StrideCategory;
  component: string;
  threat: string;
  attackVector: string;
  currentMitigation: string;
  residualRisk: RiskLevel;
  testRef?: string;         // Links to pentest scenario
  adrRef?: string;          // Links to relevant ADR
  phase06Action?: string;   // What Phase 06 adds
}

// ─────────────────────────────────────────────────────────
// STRIDE THREAT REGISTER
// ─────────────────────────────────────────────────────────

export const STRIDE_THREATS: StrideThreat[] = [

  // ── SPOOFING ──────────────────────────────────────────────────────────────

  {
    id: 'S-001',
    category: 'Spoofing',
    component: 'API — X-Partner-ID header',
    threat: 'Attacker forges X-Partner-ID to impersonate another tenant',
    attackVector: 'Send requests with arbitrary X-Partner-ID header value',
    currentMitigation: 'Header is present but unauthenticated — any string is accepted',
    residualRisk: 'HIGH',
    testRef: 'PT-001',
    phase06Action: 'Add JWT validation middleware — X-Partner-ID must match JWT sub claim',
  },
  {
    id: 'S-002',
    category: 'Spoofing',
    component: 'Gate Detector — sourceId',
    threat: 'Attacker spoofs trusted sourceId to bypass UNRECOGNIZED_SOURCE rule',
    attackVector: 'Copy a known allowlisted sourceId and use it in malicious request',
    currentMitigation: 'allowedSources list checked but sourceId is not cryptographically verified',
    residualRisk: 'MED',
    testRef: 'PT-002',
    phase06Action: 'Document HMAC-signed sourceId as Phase 07 enhancement',
  },
  {
    id: 'S-003',
    category: 'Spoofing',
    component: 'WebSocket — state stream',
    threat: 'Attacker connects to WebSocket without authentication and receives GovState',
    attackVector: 'Direct WebSocket connection to /v1/state/stream without X-Partner-ID',
    currentMitigation: 'preHandler hook runs but WebSocket upgrade bypasses it in some Fastify configs',
    residualRisk: 'MED',
    testRef: 'PT-003',
    phase06Action: 'Add WebSocket authentication check in upgrade handler',
  },

  // ── TAMPERING ─────────────────────────────────────────────────────────────

  {
    id: 'T-001',
    category: 'Tampering',
    component: 'EventStore — evidence handles',
    threat: 'Attacker submits crafted evidence handle to retrieve another tenant\'s event',
    attackVector: 'Enumerate or guess EVD-{timestamp}-{hash} format to access other tenant events',
    currentMitigation: 'getByHandle() enforces tenant isolation — wrong partnerId returns null',
    residualRisk: 'LOW',
    testRef: 'PT-004',
    adrRef: 'ADR-005',
  },
  {
    id: 'T-002',
    category: 'Tampering',
    component: 'PolicyStore — POST /v1/policy',
    threat: 'Attacker updates policy to PILOT (blockOnContainment=false) to disable enforcement',
    attackVector: 'POST /v1/policy with PILOT profile to reduce governance strictness',
    currentMitigation: 'No admin authentication on policy update endpoint — any tenant can update',
    residualRisk: 'HIGH',
    testRef: 'PT-005',
    phase06Action: 'Require admin role JWT claim for POST /v1/policy — add role-based access control',
  },
  {
    id: 'T-003',
    category: 'Tampering',
    component: 'GovEvent — log injection',
    threat: 'Attacker injects structured data via sourceId or other string fields to corrupt event log',
    attackVector: 'Send sourceId with JSON/newline characters: sourceId=\'{"layer":"gate","severity":"low"}\n\'',
    currentMitigation: 'Zod schema validates types but does not sanitize string content',
    residualRisk: 'MED',
    testRef: 'PT-006',
    phase06Action: 'Add string sanitization in ProcessRequestSchema — strip control characters and newlines',
  },
  {
    id: 'T-004',
    category: 'Tampering',
    component: 'Shell — FAIL_SAFE invariant',
    threat: 'Attacker finds path to bypass FAIL_SAFE by causing controlled Enforcer exception',
    attackVector: 'Craft input that causes failSafeVerdict() to throw (double fault)',
    currentMitigation: 'failSafeVerdict() is deliberately minimal — no external calls, pure construction',
    residualRisk: 'LOW',
    adrRef: 'ADR-002',
    phase06Action: 'Chaos test: verify FAIL_SAFE triggers on shell process kill (PT-CHAOS-001)',
  },

  // ── REPUDIATION ───────────────────────────────────────────────────────────

  {
    id: 'R-001',
    category: 'Repudiation',
    component: 'EventStore — audit trail',
    threat: 'Attacker or operator denies that a containment event occurred',
    attackVector: 'No cryptographic signing of evidence handles — handles are deterministic hashes',
    currentMitigation: 'EventStore is append-only in memory; evidence handles are immutable once created',
    residualRisk: 'MED',
    phase06Action: 'Phase 07: sign evidence handles with HMAC-SHA256 using tenant key',
  },
  {
    id: 'R-002',
    category: 'Repudiation',
    component: 'PolicyStore — policy changes',
    threat: 'Admin denies having changed the policy profile',
    attackVector: 'POST /v1/policy with no audit trail of who made the change',
    currentMitigation: 'PolicyHistoryEntry records activatedBy field but it defaults to "ADMIN_API"',
    residualRisk: 'MED',
    phase06Action: 'Bind activatedBy to authenticated JWT sub claim (requires S-001 fix first)',
  },

  // ── INFORMATION DISCLOSURE ────────────────────────────────────────────────

  {
    id: 'I-001',
    category: 'InformationDisclosure',
    component: 'API — error responses',
    threat: 'Verbose error messages expose internal stack traces or module paths',
    attackVector: 'Send malformed requests and observe detailed error responses',
    currentMitigation: 'Fastify default error handler includes some internal details',
    residualRisk: 'MED',
    testRef: 'PT-007',
    phase06Action: 'Add custom error handler that strips stack traces in production mode',
  },
  {
    id: 'I-002',
    category: 'InformationDisclosure',
    component: 'GovState — WebSocket stream',
    threat: 'GovState broadcast reveals operational details to unauthenticated WebSocket clients',
    attackVector: 'Connect to /v1/state/stream without authentication',
    currentMitigation: 'GovState is intentionally high-level (no internal model state) but reveals operational mode',
    residualRisk: 'MED',
    testRef: 'PT-003',
    phase06Action: 'Add WebSocket auth (linked to S-003 fix)',
  },
  {
    id: 'I-003',
    category: 'InformationDisclosure',
    component: 'MTTD stats — /v1/mttd',
    threat: 'MTTD statistics reveal timing characteristics that help attacker evade detection',
    attackVector: 'Query /v1/mttd to learn gate detection latency, then craft sub-threshold attacks',
    currentMitigation: 'No authentication on /v1/mttd endpoint',
    residualRisk: 'LOW',
    phase06Action: 'Restrict /v1/mttd to admin role (same JWT fix as T-002)',
  },

  // ── DENIAL OF SERVICE ─────────────────────────────────────────────────────

  {
    id: 'D-001',
    category: 'DenialOfService',
    component: 'API — POST /v1/process',
    threat: 'Attacker floods /v1/process with requests to exhaust shell processing capacity',
    attackVector: 'Send thousands of requests per second to overwhelm the ShellLoop',
    currentMitigation: 'No rate limiting on /v1/process — Watchdog restarts on crash but adds latency',
    residualRisk: 'HIGH',
    testRef: 'PT-008',
    phase06Action: 'Add rate limiting middleware: max 100 req/s per PARTNER_ID',
  },
  {
    id: 'D-002',
    category: 'DenialOfService',
    component: 'EventStore — memory exhaustion',
    threat: 'Attacker generates MAX_EVENTS_PER_TENANT events to force LRU eviction of legitimate events',
    attackVector: 'Send 10,001 containment-triggering requests to overflow the tenant event store',
    currentMitigation: 'MAX_EVENTS_PER_TENANT=10,000 cap with LRU eviction — oldest events lost',
    residualRisk: 'MED',
    testRef: 'PT-009',
    phase06Action: 'Add per-tenant rate limit on event ingestion; alert on eviction',
  },
  {
    id: 'D-003',
    category: 'DenialOfService',
    component: 'Watchdog — restart loop',
    threat: 'Attacker crafts input that reliably crashes the ShellLoop, triggering max-restart exhaustion',
    attackVector: 'Send input that causes uncaught exception in Enforcer, repeat 3+ times within 60s',
    currentMitigation: 'Watchdog enters permanent FAIL_SAFE after 3 restarts (ADR-003)',
    residualRisk: 'MED',
    testRef: 'PT-CHAOS-001',
    adrRef: 'ADR-003',
    phase06Action: 'Chaos test verifies FAIL_SAFE permanent state and 503 response',
  },

  // ── ELEVATION OF PRIVILEGE ────────────────────────────────────────────────

  {
    id: 'E-001',
    category: 'ElevationOfPrivilege',
    component: 'PolicyStore — govLevel',
    threat: 'Attacker changes govLevel to PILOT to disable blocking and observe uncontained outputs',
    attackVector: 'POST /v1/policy with govLevel=PILOT and blockOnContainment=false',
    currentMitigation: 'No authentication on POST /v1/policy — any caller can change policy',
    residualRisk: 'HIGH',
    testRef: 'PT-005',
    phase06Action: 'RBAC: policy updates require admin JWT claim',
  },
  {
    id: 'E-002',
    category: 'ElevationOfPrivilege',
    component: 'Authority Detector — chain constraint',
    threat: 'Attacker attempts to upgrade authority by replaying a previously decision-ready request',
    attackVector: 'Resend request that previously received decision-ready authority to a downgraded context',
    currentMitigation: 'AuthorityDetector chain constraint prevents upgrading from previous authority',
    residualRisk: 'LOW',
    testRef: 'PT-010',
    adrRef: 'ADR-004',
  },
  {
    id: 'E-003',
    category: 'ElevationOfPrivilege',
    component: 'Tenant isolation — cross-tenant access',
    threat: 'Tenant A accesses Tenant B\'s evidence handles or sequences',
    attackVector: 'Send requests with X-Partner-ID=TENANT_A but valid evidence handle from TENANT_B',
    currentMitigation: 'getByHandle() enforces partnerId match; sequence queries filtered by partnerId',
    residualRisk: 'LOW',
    testRef: 'PT-004',
    adrRef: 'ADR-005',
  },
];

// ─────────────────────────────────────────────────────────
// STRIDE SUMMARY
// ─────────────────────────────────────────────────────────

export function strideSummary(): {
  total: number;
  byCategory: Record<StrideCategory, number>;
  byRisk: Record<RiskLevel, number>;
  highRiskItems: StrideThreat[];
} {
  const byCategory = {} as Record<StrideCategory, number>;
  const byRisk = {} as Record<RiskLevel, number>;

  for (const t of STRIDE_THREATS) {
    byCategory[t.category] = (byCategory[t.category] ?? 0) + 1;
    byRisk[t.residualRisk] = (byRisk[t.residualRisk] ?? 0) + 1;
  }

  return {
    total: STRIDE_THREATS.length,
    byCategory,
    byRisk,
    highRiskItems: STRIDE_THREATS.filter(t => t.residualRisk === 'HIGH'),
  };
}
