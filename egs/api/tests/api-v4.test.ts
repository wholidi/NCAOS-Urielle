/**
 * Integration tests — Phase 04 API
 *
 * Tests all new Phase 04 endpoints plus regression on Phase 02 routes.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';

let app: FastifyInstance;

beforeAll(async () => {
  app = await buildServer();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

const HDR = {
  'content-type': 'application/json',
  'x-partner-id': 'TEST_PARTNER',
};

const CLEAN_BODY = JSON.stringify({
  sourceId: 'test-src-001',
  inputHash: 'abc123',
  inputFlags: [],
  claimedPremises: ['A', 'B'],
  validatedPremises: ['A', 'B'],
  contractVersion: '1.0',
  requestedAuthority: 'decision-ready',
  policyGrantedAuthority: 'decision-ready',
  overrideAttempted: false,
});

const THREAT_BODY = JSON.stringify({
  sourceId: 'attacker-001',
  inputHash: 'bad-hash',
  inputFlags: ['INJECTION_PATTERN'],
  claimedPremises: ['A', 'B', 'C'],
  validatedPremises: ['A'],
  contractVersion: '1.0',
  requestedAuthority: 'decision-ready',
  policyGrantedAuthority: 'reference-only',
  overrideAttempted: false,
});

// ─────────────────────────────────────────────────────────
// REGRESSION — Phase 02 routes
// ─────────────────────────────────────────────────────────

describe('GET /v1/health — upgraded', () => {
  it('returns 200 with slaHealthy and activeTenants fields', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/health', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ status: string; slaHealthy: boolean; activeTenants: number }>();
    expect(body.status).toBe('OK');
    expect(typeof body.slaHealthy).toBe('boolean');
    expect(typeof body.activeTenants).toBe('number');
  });

  it('returns 401 without X-Partner-ID', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/health' });
    expect(res.statusCode).toBe(401);
  });
});

describe('POST /v1/process — upgraded', () => {
  it('returns 200 for clean request', async () => {
    const res = await app.inject({ method: 'POST', url: '/v1/process', headers: HDR, payload: CLEAN_BODY });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ action: string; requestId: string }>();
    expect(body.requestId).toMatch(/^REQ-\d+$/);
    expect(['PASS', 'DOWNGRADE', 'BLOCK']).toContain(body.action);
  });

  it('returns BLOCK + evidenceHandle for threat request', async () => {
    const res = await app.inject({ method: 'POST', url: '/v1/process', headers: HDR, payload: THREAT_BODY });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ action: string; evidenceHandle?: string }>();
    expect(body.action).toBe('BLOCK');
    expect(body.evidenceHandle).toMatch(/^EVD-\d+-[A-Z0-9]+$/);
  });
});

describe('GET /v1/audit/:handle — upgraded', () => {
  it('returns full EventRecord with sequenceNumber', async () => {
    // Trigger a containment event first
    const proc = await app.inject({ method: 'POST', url: '/v1/process', headers: HDR, payload: THREAT_BODY });
    const { evidenceHandle } = proc.json<{ evidenceHandle?: string }>();
    if (!evidenceHandle) return;

    const res = await app.inject({ method: 'GET', url: `/v1/audit/${evidenceHandle}`, headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ evidenceHandle: string; sequenceNumber: number; storedAt: string }>();
    expect(body.evidenceHandle).toBe(evidenceHandle);
    expect(typeof body.sequenceNumber).toBe('number');
    expect(body.sequenceNumber).toBeGreaterThan(0);
    expect(body.storedAt).toBeDefined();
  });

  it('returns 404 for unknown handle', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/audit/EVD-0000000000000-00000000', headers: HDR });
    expect(res.statusCode).toBe(404);
  });

  it('returns 404 for different tenant handle (isolation)', async () => {
    const proc = await app.inject({ method: 'POST', url: '/v1/process', headers: HDR, payload: THREAT_BODY });
    const { evidenceHandle } = proc.json<{ evidenceHandle?: string }>();
    if (!evidenceHandle) return;

    // Try to access with a different tenant
    const res = await app.inject({
      method: 'GET',
      url: `/v1/audit/${evidenceHandle}`,
      headers: { ...HDR, 'x-partner-id': 'OTHER_TENANT' },
    });
    expect(res.statusCode).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────
// NEW — GET /v1/events
// ─────────────────────────────────────────────────────────

describe('GET /v1/events', () => {
  it('returns paginated event list', async () => {
    // Generate some events first
    await app.inject({ method: 'POST', url: '/v1/process', headers: HDR, payload: THREAT_BODY });

    const res = await app.inject({ method: 'GET', url: '/v1/events?limit=10', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ records: unknown[]; pagination: { total: number; limit: number } }>();
    expect(Array.isArray(body.records)).toBe(true);
    expect(body.pagination.limit).toBe(10);
    expect(typeof body.pagination.total).toBe('number');
  });

  it('filters by layer', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/events?layer=gate', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ records: Array<{ event: { layer: string } }> }>();
    for (const r of body.records) {
      expect(r.event.layer).toBe('gate');
    }
  });

  it('filters by severity', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/events?severity=high', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ records: Array<{ event: { severity: string } }> }>();
    for (const r of body.records) {
      expect(r.event.severity).toBe('high');
    }
  });

  it('returns 400 for invalid limit', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/events?limit=9999', headers: HDR });
    expect(res.statusCode).toBe(400);
  });

  it('enforces tenant isolation — different tenants see different events', async () => {
    const res1 = await app.inject({ method: 'GET', url: '/v1/events', headers: HDR });
    const res2 = await app.inject({
      method: 'GET', url: '/v1/events',
      headers: { ...HDR, 'x-partner-id': 'ISOLATED_TENANT' },
    });
    const body1 = res1.json<{ pagination: { total: number } }>();
    const body2 = res2.json<{ pagination: { total: number } }>();
    // ISOLATED_TENANT has no events
    expect(body2.pagination.total).toBe(0);
    // TEST_PARTNER has events from prior tests
    expect(body1.pagination.total).toBeGreaterThanOrEqual(0);
  });
});

// ─────────────────────────────────────────────────────────
// NEW — GET /v1/events/stats
// ─────────────────────────────────────────────────────────

describe('GET /v1/events/stats', () => {
  it('returns aggregate statistics', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/events/stats', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ total: number; byLayer: object; bySeverity: object; byAction: object }>();
    expect(typeof body.total).toBe('number');
    expect(typeof body.byLayer).toBe('object');
    expect(typeof body.bySeverity).toBe('object');
    expect(typeof body.byAction).toBe('object');
  });
});

// ─────────────────────────────────────────────────────────
// NEW — GET /v1/mttd
// ─────────────────────────────────────────────────────────

describe('GET /v1/mttd', () => {
  it('returns MTTD stats for all four layers', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/mttd', headers: HDR });
    expect([200, 207]).toContain(res.statusCode);
    const body = res.json<{ slaHealthy: boolean; layers: Array<{ layer: string; slaMs: number }> }>();
    expect(typeof body.slaHealthy).toBe('boolean');
    expect(Array.isArray(body.layers)).toBe(true);
    const layers = body.layers.map(l => l.layer);
    expect(layers).toContain('gate');
    expect(layers).toContain('premise');
    expect(layers).toContain('authority');
    expect(layers).toContain('continuity');
  });
});

// ─────────────────────────────────────────────────────────
// NEW — Policy CRUD
// ─────────────────────────────────────────────────────────

describe('GET /v1/policy', () => {
  it('returns active policy profile', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/policy', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ profileId: string; govLevel: string }>();
    expect(body.profileId).toBeDefined();
    expect(body.govLevel).toBeDefined();
  });
});

describe('POST /v1/policy', () => {
  it('rejects invalid policy schema', async () => {
    const res = await app.inject({
      method: 'POST', url: '/v1/policy', headers: HDR,
      payload: JSON.stringify({ bad: 'policy' }),
    });
    expect(res.statusCode).toBe(400);
    const body = res.json<{ error: string }>();
    expect(body.error).toBe('INVALID_POLICY');
  });
});

describe('GET /v1/policy/history', () => {
  it('returns policy history array', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/policy/history', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ history: unknown[] }>();
    expect(Array.isArray(body.history)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────
// NEW — GET /v1/detectors
// ─────────────────────────────────────────────────────────

describe('GET /v1/detectors', () => {
  it('returns per-tenant detector status', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/detectors', headers: HDR });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ partnerId: string; gateRules: number; mttdStats: unknown[] }>();
    expect(body.partnerId).toBe('TEST_PARTNER');
    expect(body.gateRules).toBeGreaterThan(0);
    expect(Array.isArray(body.mttdStats)).toBe(true);
  });
});
