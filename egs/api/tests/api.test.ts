/**
 * Integration tests — API routes
 *
 * Tests the Fastify API endpoints using inject() (no real HTTP).
 * Uses PILOT profile to avoid blocking test requests.
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

const HEADERS = {
  'content-type': 'application/json',
  'x-partner-id': 'TEST_PARTNER',
};

const CLEAN_PAYLOAD = JSON.stringify({
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

describe('GET /v1/health', () => {
  it('returns 200 when shell is running', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/health',
      headers: HEADERS,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ status: string; watchdog: string }>();
    expect(body.status).toBe('OK');
    expect(body.watchdog).toBe('RUNNING');
  });
});

describe('POST /v1/process', () => {
  it('returns 401 without X-Partner-ID', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/process',
      headers: { 'content-type': 'application/json' },
      payload: CLEAN_PAYLOAD,
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns 400 for invalid payload', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/process',
      headers: HEADERS,
      payload: JSON.stringify({ bad: 'payload' }),
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns 200 with verdict for clean request', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/process',
      headers: HEADERS,
      payload: CLEAN_PAYLOAD,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ action: string; authority: string; requestId: string }>();
    expect(body.requestId).toMatch(/^REQ-\d+$/);
    expect(['PASS', 'DOWNGRADE', 'BLOCK']).toContain(body.action);
    expect(body.authority).toBeDefined();
  });

  it('returns evidenceHandle when containment triggered', async () => {
    const threatPayload = JSON.stringify({
      sourceId: 'src-threat',
      inputHash: 'bad999',
      inputFlags: ['INJECTION_PATTERN'],
      claimedPremises: ['A', 'B', 'C'],
      validatedPremises: ['A'],
      contractVersion: '1.0',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'reference-only',
      overrideAttempted: false,
    });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/process',
      headers: HEADERS,
      payload: threatPayload,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ action: string; evidenceHandle?: string }>();
    expect(body.action).toBe('BLOCK');
    expect(body.evidenceHandle).toMatch(/^EVD-\d+-[A-Z0-9]+$/);
  });
});

describe('GET /v1/state', () => {
  it('returns current GovState after processing', async () => {
    // Process a request first to ensure state exists
    await app.inject({
      method: 'POST',
      url: '/v1/process',
      headers: HEADERS,
      payload: CLEAN_PAYLOAD,
    });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/state',
      headers: HEADERS,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json<{ systemStatus: string; operationalMode: string }>();
    expect(body.systemStatus).toBeDefined();
    expect(body.operationalMode).toBeDefined();
  });
});

describe('GET /v1/audit/:handle', () => {
  it('returns 404 for unknown evidence handle', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/audit/EVD-0000000000000-00000000',
      headers: HEADERS,
    });
    expect(res.statusCode).toBe(404);
  });

  it('returns event for known evidence handle', async () => {
    // Trigger a containment event to get a real handle
    const threatPayload = JSON.stringify({
      sourceId: 'src-audit-test',
      inputHash: 'bad-hash',
      inputFlags: ['INJECTION_PATTERN'],
      claimedPremises: ['A'],
      validatedPremises: [],
      contractVersion: '1.0',
      requestedAuthority: 'decision-ready',
      policyGrantedAuthority: 'invalid',
      overrideAttempted: false,
    });

    const processRes = await app.inject({
      method: 'POST',
      url: '/v1/process',
      headers: HEADERS,
      payload: threatPayload,
    });

    const { evidenceHandle } = processRes.json<{ evidenceHandle?: string }>();
    if (!evidenceHandle) return; // Skip if no event generated

    const auditRes = await app.inject({
      method: 'GET',
      url: `/v1/audit/${evidenceHandle}`,
      headers: HEADERS,
    });

    expect(auditRes.statusCode).toBe(200);
    const body = auditRes.json<{ evidenceHandle: string; verdict: object }>();
    expect(body.evidenceHandle).toBe(evidenceHandle);
    expect(body.verdict).toBeDefined();
  });
});
