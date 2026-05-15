/**
 * Tests — JWT Middleware + Rate Limiter
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter } from '../src/jwt/auth-middleware.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter(10, 15); // 10 req/s, burst 15
  });

  it('allows requests within burst limit', () => {
    let allowed = 0;
    for (let i = 0; i < 15; i++) {
      if (limiter.check('TENANT_A')) allowed++;
    }
    expect(allowed).toBe(15);
  });

  it('blocks requests beyond burst limit', () => {
    for (let i = 0; i < 15; i++) limiter.check('TENANT_A');
    const blocked = !limiter.check('TENANT_A');
    expect(blocked).toBe(true);
  });

  it('isolates rate limits per tenant', () => {
    for (let i = 0; i < 15; i++) limiter.check('TENANT_A');
    // TENANT_B should still have full bucket
    expect(limiter.check('TENANT_B')).toBe(true);
  });

  it('returns correct stats', () => {
    limiter.check('TENANT_A');
    limiter.check('TENANT_A');
    const stats = limiter.stats('TENANT_A');
    expect(stats.ratePerSec).toBe(10);
    expect(stats.burst).toBe(15);
    expect(stats.tokens).toBeLessThan(15);
  });

  it('returns burst tokens for unknown tenant', () => {
    const stats = limiter.stats('NEW_TENANT');
    expect(stats.tokens).toBe(15);
  });

  it('refills tokens over time', async () => {
    // Exhaust the bucket
    for (let i = 0; i < 15; i++) limiter.check('TENANT_A');
    expect(limiter.check('TENANT_A')).toBe(false);
    // Wait for refill (1 token per 100ms at 10/s)
    await new Promise(r => setTimeout(r, 150));
    expect(limiter.check('TENANT_A')).toBe(true);
  });

  it('does not exceed burst on refill', async () => {
    // Wait a long time
    await new Promise(r => setTimeout(r, 200));
    const stats = limiter.stats('TENANT_A');
    expect(stats.tokens).toBeLessThanOrEqual(15);
  });
});

describe('RateLimiter — high volume', () => {
  it('handles 1000 rapid checks without error', () => {
    const limiter = new RateLimiter(100, 150);
    let allowed = 0;
    for (let i = 0; i < 1000; i++) {
      if (limiter.check('LOAD_TEST')) allowed++;
    }
    expect(allowed).toBeLessThanOrEqual(150);
    expect(allowed).toBeGreaterThan(0);
  });
});
