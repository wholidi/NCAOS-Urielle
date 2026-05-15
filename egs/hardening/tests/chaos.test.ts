/**
 * Tests — Chaos Harness (unit-testable scenarios)
 *
 * CHAOS-001 (shell kill) requires a live ShellLoop — tested manually.
 * CHAOS-002 (rate limit) is fully unit-testable.
 * CHAOS-003 (concurrent storm) tested against live server — manual.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter } from '../src/jwt/auth-middleware.js';
import { CHAOS_SCENARIOS, ChaosTestHarness } from '../src/chaos/chaos-harness.js';

describe('Chaos Scenarios — documented', () => {
  it('has all 5 chaos scenarios defined', () => {
    expect(CHAOS_SCENARIOS).toHaveLength(5);
  });

  it('all scenarios have pass criteria', () => {
    for (const s of CHAOS_SCENARIOS) {
      expect(s.passCriteria.length).toBeGreaterThan(0);
    }
  });

  it('CHAOS-001 references ADR-002 invariant', () => {
    const s = CHAOS_SCENARIOS.find(c => c.id === 'CHAOS-001');
    expect(s?.expectedBehavior).toContain('503');
    expect(s?.expectedBehavior).toContain('GOVERNANCE_UNAVAILABLE');
  });

  it('CHAOS-002 references rate limiting', () => {
    const s = CHAOS_SCENARIOS.find(c => c.id === 'CHAOS-002');
    expect(s?.expectedBehavior).toContain('429');
  });
});

describe('CHAOS-002 — Rate Limit Exhaustion (unit)', () => {
  let harness: ChaosTestHarness;

  beforeEach(() => {
    harness = new ChaosTestHarness();
  });

  it('passes CHAOS-002 scenario', async () => {
    const result = await harness.runChaos002();
    expect(result.passed).toBe(true);
    expect(result.scenarioId).toBe('CHAOS-002');
    expect(result.unexpectedErrors).toHaveLength(0);
  });

  it('allows burst then blocks', () => {
    const limiter = new RateLimiter(10, 15);
    let allowed = 0;
    let blocked = 0;
    for (let i = 0; i < 20; i++) {
      if (limiter.check('T1')) allowed++;
      else blocked++;
    }
    expect(allowed).toBe(15);
    expect(blocked).toBe(5);
  });

  it('FAIL_SAFE: tenant isolation maintained under rate limit', () => {
    const limiter = new RateLimiter(10, 5);
    // Exhaust TENANT_A
    for (let i = 0; i < 10; i++) limiter.check('TENANT_A');
    // TENANT_B must still have full bucket (ADR-005)
    expect(limiter.check('TENANT_B')).toBe(true);
  });

  it('tokens refill over time', async () => {
    const limiter = new RateLimiter(1000, 1); // 1 token burst
    limiter.check('T'); // consume the one token
    expect(limiter.check('T')).toBe(false); // blocked

    await new Promise(r => setTimeout(r, 5)); // wait 5ms = 5 tokens at 1000/s
    expect(limiter.check('T')).toBe(true); // refilled
  });
});
