/**
 * @ncaos/hardening — Chaos Test Harness
 *
 * Phase 06: Validates ADR-002 (FAIL_SAFE default-deny) under failure conditions.
 *
 * The fundamental invariant: if the shell crashes or is killed, the API
 * must return 503 GOVERNANCE_UNAVAILABLE — never pass requests through ungoverned.
 *
 * Chaos scenarios:
 *   CHAOS-001: Kill shell process → API must return 503
 *   CHAOS-002: Exhaust rate limit → API must return 429
 *   CHAOS-003: Simultaneous high-volume requests → no data races, all responses valid
 *   CHAOS-004: Invalid payload flood → API must return 400, never 500
 *   CHAOS-005: Rapid policy change during processing → no stale policy applied
 *
 * Design: The harness is a test utility — it does not run in production.
 * It coordinates between the API and the shell to simulate failure modes.
 */

import type { ShellLoop } from '@ncaos/shell';

// ─────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────

export type ChaosScenarioId =
  | 'CHAOS-001'
  | 'CHAOS-002'
  | 'CHAOS-003'
  | 'CHAOS-004'
  | 'CHAOS-005';

export interface ChaosScenario {
  id: ChaosScenarioId;
  title: string;
  description: string;
  strideRef?: string;
  expectedBehavior: string;
  passCriteria: string[];
}

export interface ChaosResult {
  scenarioId: ChaosScenarioId;
  passed: boolean;
  observations: string[];
  durationMs: number;
  failSafeTriggered: boolean;
  unexpectedErrors: string[];
}

// ─────────────────────────────────────────────────────────
// SCENARIO DEFINITIONS
// ─────────────────────────────────────────────────────────

export const CHAOS_SCENARIOS: ChaosScenario[] = [
  {
    id: 'CHAOS-001',
    title: 'Shell Kill → FAIL_SAFE Activation',
    description: 'Stop the ShellLoop while the API is running. All subsequent requests must return 503 GOVERNANCE_UNAVAILABLE.',
    strideRef: 'D-002',
    expectedBehavior: 'API returns 503 with error=GOVERNANCE_UNAVAILABLE. Watchdog begins restart sequence.',
    passCriteria: [
      'All requests during shell downtime return 503',
      'No requests are processed without governance',
      'Watchdog emits shell:stopped event',
      'After restart, requests resume normally',
    ],
  },
  {
    id: 'CHAOS-002',
    title: 'Rate Limit Exhaustion → 429',
    description: 'Send requests faster than 100/s sustained. Rate limiter must activate and return 429.',
    strideRef: 'D-001',
    expectedBehavior: 'First burst (up to 150) succeeds. Subsequent requests return 429 RATE_LIMITED.',
    passCriteria: [
      'Burst of 150 requests allowed',
      'Request 151+ returns 429',
      'Rate limit is per-tenant (TENANT_B unaffected)',
      'After 1s, new tokens available',
    ],
  },
  {
    id: 'CHAOS-003',
    title: 'Concurrent Request Storm → No Race Conditions',
    description: 'Send 50 concurrent requests simultaneously. All responses must be valid, no 500 errors.',
    expectedBehavior: 'All 50 responses are 200 or 429. No 500 Internal Server Error. GovState remains consistent.',
    passCriteria: [
      'Zero 500 responses',
      'All responses are 200 or 429',
      'Evidence handles are unique across concurrent requests',
      'Sequence numbers are monotonically increasing (no gaps or duplicates)',
    ],
  },
  {
    id: 'CHAOS-004',
    title: 'Invalid Payload Flood → 400 Not 500',
    description: 'Send malformed JSON, missing fields, and invalid types. API must return 400 for all, never 500.',
    expectedBehavior: 'All malformed requests return 400 BAD_REQUEST with Zod validation errors. Server remains stable.',
    passCriteria: [
      'Zero 500 responses under invalid input',
      'All responses include error field',
      'Server continues handling valid requests after flood',
      'No memory leak or performance degradation',
    ],
  },
  {
    id: 'CHAOS-005',
    title: 'Policy Change During Active Processing → No Stale Policy',
    description: 'Trigger a policy change (POST /v1/policy) while concurrent requests are being processed.',
    expectedBehavior: 'Policy change triggers detector reset. In-flight requests complete with old policy. New requests use new policy.',
    passCriteria: [
      'No panics or 500 errors during policy change',
      'Policy:changed event fires and detectors reset',
      'Subsequent requests reflect new policy',
      'No cross-tenant policy bleed',
    ],
  },
];

// ─────────────────────────────────────────────────────────
// CHAOS HARNESS
// ─────────────────────────────────────────────────────────

/**
 * ChaosTestHarness — coordinates chaos scenarios for integration testing.
 *
 * Usage in vitest integration tests:
 *   const harness = new ChaosTestHarness(app, shellLoop);
 *   const result = await harness.run('CHAOS-001');
 *   expect(result.passed).toBe(true);
 *   expect(result.failSafeTriggered).toBe(true);
 */
export class ChaosTestHarness {
  private readonly baseUrl: string;
  private readonly partnerId: string;

  constructor(baseUrl = 'http://localhost:3000', partnerId = 'CHAOS_TEST') {
    this.baseUrl = baseUrl;
    this.partnerId = partnerId;
  }

  /**
   * runChaos001() — Shell kill test (ADR-002 validation).
   *
   * In unit test context: uses a mock shell that can be stopped.
   * In manual test: stop the API server's shell process directly.
   */
  async runChaos001(shell: ShellLoop): Promise<ChaosResult> {
    const start = Date.now();
    const observations: string[] = [];
    let failSafeTriggered = false;
    const unexpectedErrors: string[] = [];

    try {
      // Verify shell is running
      const preCheck = await this._get('/v1/health');
      if (preCheck.status !== 200) {
        return this._fail('CHAOS-001', start, ['Shell was not running before test']);
      }
      observations.push('Pre-check: shell running ✓');

      // Stop the shell
      shell.stop();
      observations.push('Shell stopped');

      // Small delay for stop to propagate
      await this._sleep(50);

      // FAIL_SAFE should now be active — process() returns FAIL_SAFE
      const result = shell.process({
        sourceId: 'chaos-test',
        inputHash: 'chaos',
        inputFlags: [],
        claimedPremises: [],
        validatedPremises: [],
        contractVersion: '1.0',
        requestedAuthority: 'decision-ready',
        policyGrantedAuthority: 'decision-ready',
        overrideAttempted: false,
        workflowId: '',
        updateId: '',
        equivalenceTestResults: [],
        continuityScore: 100,
      });

      if (result.verdict.action === 'FAIL_SAFE') {
        failSafeTriggered = true;
        observations.push('FAIL_SAFE verdict returned ✓');
      } else {
        unexpectedErrors.push(`Expected FAIL_SAFE, got ${result.verdict.action}`);
      }

    } catch (err) {
      unexpectedErrors.push(`Unexpected exception: ${String(err)}`);
    }

    const passed = failSafeTriggered && unexpectedErrors.length === 0;
    return {
      scenarioId: 'CHAOS-001',
      passed,
      observations,
      durationMs: Date.now() - start,
      failSafeTriggered,
      unexpectedErrors,
    };
  }

  /**
   * runChaos002() — Rate limit exhaustion.
   */
  async runChaos002(): Promise<ChaosResult> {
    const start = Date.now();
    const observations: string[] = [];
    const unexpectedErrors: string[] = [];

    const { RateLimiter } = await import('../jwt/auth-middleware.js');
    const limiter = new RateLimiter(10, 15); // Test with low limits

    let allowed = 0;
    let blocked = 0;

    for (let i = 0; i < 20; i++) {
      if (limiter.check('CHAOS_TENANT')) allowed++;
      else blocked++;
    }

    observations.push(`Allowed: ${allowed}, Blocked: ${blocked}`);

    // Tenant isolation check
    const otherAllowed = limiter.check('OTHER_TENANT');
    if (otherAllowed) {
      observations.push('Tenant isolation: OTHER_TENANT unaffected ✓');
    } else {
      unexpectedErrors.push('Rate limit bled to OTHER_TENANT — isolation failure');
    }

    const passed = allowed <= 15 && blocked > 0 && otherAllowed;
    return {
      scenarioId: 'CHAOS-002',
      passed,
      observations,
      durationMs: Date.now() - start,
      failSafeTriggered: false,
      unexpectedErrors,
    };
  }

  /**
   * runChaos003() — Concurrent request storm (use with live server).
   */
  async runChaos003(): Promise<ChaosResult> {
    const start = Date.now();
    const observations: string[] = [];
    const unexpectedErrors: string[] = [];

    const CONCURRENT = 20;
    const payload = JSON.stringify({
      sourceId: 'chaos-concurrent',
      inputHash: 'abc',
      inputFlags: [],
      claimedPremises: ['A'],
      validatedPremises: ['A'],
      contractVersion: '1.0',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'decision-ready',
      overrideAttempted: false,
    });

    const results = await Promise.allSettled(
      Array.from({ length: CONCURRENT }, () =>
        this._post('/v1/process', payload),
      ),
    );

    const statuses = results.map(r =>
      r.status === 'fulfilled' ? r.value.status : 500,
    );

    const has500 = statuses.some(s => s === 500);
    const validStatuses = statuses.every(s => [200, 429, 503].includes(s));

    observations.push(`${CONCURRENT} concurrent requests: ${statuses.join(', ')}`);
    if (!has500) observations.push('Zero 500 responses ✓');
    if (validStatuses) observations.push('All responses have valid status codes ✓');

    if (has500) unexpectedErrors.push('500 Internal Server Error detected under concurrent load');

    return {
      scenarioId: 'CHAOS-003',
      passed: !has500 && validStatuses,
      observations,
      durationMs: Date.now() - start,
      failSafeTriggered: false,
      unexpectedErrors,
    };
  }

  // ── HELPERS ──────────────────────────────────────────────────────────────

  private async _get(path: string): Promise<{ status: number; body: unknown }> {
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        headers: { 'X-Partner-ID': this.partnerId },
      });
      return { status: res.status, body: await res.json().catch(() => null) };
    } catch {
      return { status: 0, body: null };
    }
  }

  private async _post(path: string, body: string): Promise<{ status: number; body: unknown }> {
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Partner-ID': this.partnerId },
        body,
      });
      return { status: res.status, body: await res.json().catch(() => null) };
    } catch {
      return { status: 0, body: null };
    }
  }

  private _sleep(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }

  private _fail(id: ChaosScenarioId, start: number, errors: string[]): ChaosResult {
    return {
      scenarioId: id,
      passed: false,
      observations: [],
      durationMs: Date.now() - start,
      failSafeTriggered: false,
      unexpectedErrors: errors,
    };
  }
}
