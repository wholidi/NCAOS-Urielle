/**
 * @ncaos/api — Production Server (Phase 04)
 *
 * Upgrades from Phase 02 skeleton:
 *
 * NEW ROUTES:
 *   GET  /v1/events            — Paginated event log with filters
 *   GET  /v1/events/stats      — Event log aggregate statistics
 *   GET  /v1/mttd              — MTTD statistics per detection layer
 *   POST /v1/policy            — Update active policy profile (admin)
 *   GET  /v1/policy            — Get active policy profile
 *   GET  /v1/policy/history    — Policy change history
 *   GET  /v1/detectors         — Per-tenant detector status
 *
 * UPGRADED:
 *   POST /v1/process  — Now uses per-tenant detector instances
 *   GET  /v1/health   — Now includes MTTD SLA health + detector status
 *   GET  /v1/audit/:handle — Now returns full EventRecord
 *
 * UNCHANGED:
 *   GET  /v1/state
 *   WS   /v1/state/stream
 */

import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyCors from '@fastify/cors';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { Watchdog } from '@ncaos/shell';
import { ENTERPRISE_STRICT_PROFILE } from '@ncaos/core';
import type { GovState } from '@ncaos/core';
import type { EnforcerOutput } from '@ncaos/shell';
import { TenantDetectorRegistry } from './detectors/tenant-registry.js';
import { EventStore } from './store/event-store.js';
import { PolicyStore } from './store/policy-store.js';
import type { EventQuery } from './store/event-store.js';

// ─────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────

const PORT = parseInt(process.env['PORT'] ?? '3000', 10);
const HOST = process.env['HOST'] ?? '0.0.0.0';
const PARTNER_ID = (process.env['PARTNER_ID'] ?? 'GLOBAL_ENT_2026') as string;
const INSTANCE_ID = (process.env['INSTANCE_ID'] ?? 'EGS_INST_001') as string;

// ─────────────────────────────────────────────────────────
// REQUEST SCHEMAS
// ─────────────────────────────────────────────────────────

const ProcessRequestSchema = z.object({
  sourceId: z.string().min(1),
  inputHash: z.string().min(1),
  inputFlags: z.array(z.string()).default([]),
  claimedPremises: z.array(z.string()).default([]),
  validatedPremises: z.array(z.string()).default([]),
  contractVersion: z.string().default('1.0'),
  requestedAuthority: z.enum(['decision-ready', 'reference-only']).default('decision-ready'),
  policyGrantedAuthority: z.enum(['decision-ready', 'reference-only', 'invalid']).default('decision-ready'),
  overrideAttempted: z.boolean().default(false),
  workflowId: z.string().default(''),
  updateId: z.string().default(''),
  equivalenceTestResults: z.array(z.object({
    testId: z.string(),
    passed: z.boolean(),
  })).default([]),
  continuityScore: z.number().default(100),
});

const EventQuerySchema = z.object({
  layer: z.enum(['gate', 'premise', 'authority', 'continuity']).optional(),
  severity: z.enum(['low', 'med', 'high']).optional(),
  action: z.enum(['PASS', 'DOWNGRADE', 'BLOCK', 'FAIL_SAFE']).optional(),
  fromDate: z.string().optional(),
  toDate: z.string().optional(),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

// ─────────────────────────────────────────────────────────
// BUILD SERVER
// ─────────────────────────────────────────────────────────

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({ logger: true });

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);

  // ── Shared stores ─────────────────────────────────────────────────────────
  const policyStore = new PolicyStore();
  const eventStore = new EventStore();
  const detectorRegistry = new TenantDetectorRegistry(
    (partnerId) => policyStore.getActive(partnerId),
  );

  // ── WebSocket clients ─────────────────────────────────────────────────────
  const wsClients = new Set<import('ws').WebSocket>();
  function broadcastState(state: GovState): void {
    const payload = JSON.stringify({ type: 'state:update', data: state });
    for (const client of wsClients) {
      if ((client as any).readyState === 1) (client as any).send(payload);
    }
  }

  // ── Watchdog ──────────────────────────────────────────────────────────────
  const watchdog = new Watchdog({
    shellConfig: {
      tenant: {
        partnerId: PARTNER_ID as any,
        instanceId: INSTANCE_ID as any,
        deployment: 'ENTERPRISE',
      },
      policy: ENTERPRISE_STRICT_PROFILE,
    },
    maxRestarts: 3,
    windowMs: 60_000,
    baseBackoffMs: 500,
  });

  // Forward shell output → event store + WebSocket
  watchdog.on('shell:output', (output: EnforcerOutput) => {
    eventStore.append(PARTNER_ID, output);
    broadcastState(output.state);
  });

  // Reset detectors when policy changes
  policyStore.on('policy:changed', ({ partnerId }: { partnerId: string }) => {
    detectorRegistry.reset(partnerId);
  });

  watchdog.start();

  /*
  // ── Tenant middleware ──────────────────────────────────────────────────────
  app.addHook('preHandler', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'];
    if (!partnerId) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'X-Partner-ID header required',
      });
    }
  });
*/

// ── Tenant middleware ──────────────────────────────────────────────────────
app.addHook('preHandler', async (req: FastifyRequest, reply: FastifyReply) => {
  const query = req.query as any;

  const partnerId =
    req.headers['x-partner-id'] ??
    query?.partnerId ??
    query?.['x-partner-id'] ??
    PARTNER_ID;

    if (!partnerId) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'X-Partner-ID header required',
    });
  }
});

  // ─────────────────────────────────────────────────────
  // POST /v1/process — upgraded with per-tenant detectors
  // ─────────────────────────────────────────────────────
  app.post('/v1/process', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    const wd = watchdog;

    if (wd.currentStatus === 'FAIL_SAFE' || wd.currentStatus === 'STOPPED') {
      return reply.status(503).send({
        error: 'GOVERNANCE_UNAVAILABLE',
        message: 'EGS shell is unavailable — all requests blocked per FAIL_SAFE policy',
        status: wd.currentStatus,
      });
    }

    if (wd.currentStatus === 'RESTARTING') {
      return reply.status(503).send({
        error: 'GOVERNANCE_RESTARTING',
        message: 'EGS shell is restarting — request cannot be processed',
        status: wd.currentStatus,
      });
    }

    const parsed = ProcessRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'INVALID_REQUEST', issues: parsed.error.issues });
    }

    const shell = wd.shellLoop;
    if (!shell) {
      return reply.status(503).send({ error: 'GOVERNANCE_UNAVAILABLE' });
    }

    // Record MTTD via per-tenant detector registry
    const detectors = detectorRegistry.get(partnerId);
    const startMs = performance.now();
    const output = shell.process(parsed.data);
    const processingMs = performance.now() - startMs;

    // Record gate MTTD if triggered
    if (output.event?.layer) {
      detectors.mttdRegistry.tracker(output.event.layer).record(processingMs);
    }

    // Store event
    const record = eventStore.append(partnerId, output);

    return reply.status(200).send({
      requestId: output.verdict.requestId,
      action: output.verdict.action,
      authority: output.verdict.authority,
      integrity: output.verdict.integrity,
      routing: output.verdict.routing,
      evidenceHandle: record?.evidenceHandle ?? output.event?.evidenceHandle,
      processingMs: output.verdict.processingMs,
    });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/state
  // ─────────────────────────────────────────────────────
  app.get('/v1/state', async (_req: FastifyRequest, reply: FastifyReply) => {
    const state = watchdog.shellLoop?.currentState;
    if (!state) {
      return reply.status(503).send({ error: 'GOVERNANCE_UNAVAILABLE', watchdogStatus: watchdog.currentStatus });
    }
    return reply.status(200).send(state);
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/audit/:handle
  // ─────────────────────────────────────────────────────
  app.get('/v1/audit/:handle', async (req: FastifyRequest<{ Params: { handle: string } }>, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    const record = eventStore.getByHandle(partnerId, req.params.handle);
    if (!record) {
      return reply.status(404).send({ error: 'NOT_FOUND', message: `No event found for evidence handle: ${req.params.handle}` });
    }
    return reply.status(200).send({ evidenceHandle: record.evidenceHandle, event: record.event, verdict: record.verdict, storedAt: record.storedAt, sequenceNumber: record.sequenceNumber });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/events — paginated event log (NEW)
  // ─────────────────────────────────────────────────────
  app.get('/v1/events', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    const qParsed = EventQuerySchema.safeParse(req.query);
    if (!qParsed.success) {
      return reply.status(400).send({ error: 'INVALID_QUERY', issues: qParsed.error.issues });
    }

//  const query: EventQuery = { ...qParsed.data, partnerId };

//  const page = eventStore.query(query);
    const query: EventQuery = {
      partnerId,
      limit: qParsed.data.limit,
};

if (qParsed.data.layer !== undefined) query.layer = qParsed.data.layer;
if (qParsed.data.severity !== undefined) query.severity = qParsed.data.severity;
if (qParsed.data.action !== undefined) query.action = qParsed.data.action;
if (qParsed.data.fromDate !== undefined) query.fromDate = qParsed.data.fromDate;
if (qParsed.data.toDate !== undefined) query.toDate = qParsed.data.toDate;
if (qParsed.data.cursor !== undefined) query.cursor = qParsed.data.cursor;

const page = eventStore.query(query);
    
      return reply.status(200).send({
      records: page.records,
      pagination: {
        total: page.total,
        hasMore: page.hasMore,
        nextCursor: page.nextCursor,
        limit: qParsed.data.limit,
      },
    });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/events/stats — event log statistics (NEW)
  // ─────────────────────────────────────────────────────
  app.get('/v1/events/stats', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    return reply.status(200).send(eventStore.stats(partnerId));
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/mttd — MTTD statistics per detection layer (NEW)
  // ─────────────────────────────────────────────────────
  app.get('/v1/mttd', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    const stats = detectorRegistry.mttdStats(partnerId);
    const healthy = detectorRegistry.isSlaHealthy(partnerId);
    return reply.status(healthy ? 200 : 207).send({
      slaHealthy: healthy,
      layers: stats,
    });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/policy — get active policy (NEW)
  // ─────────────────────────────────────────────────────
  app.get('/v1/policy', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    return reply.status(200).send(policyStore.getActive(partnerId));
  });

  // ─────────────────────────────────────────────────────
  // POST /v1/policy — update active policy (NEW)
  // ─────────────────────────────────────────────────────
  app.post('/v1/policy', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    const result = policyStore.setActive(partnerId, req.body, 'ADMIN_API');
    if (!result.success) {
      return reply.status(400).send({ error: 'INVALID_POLICY', errors: result.errors });
    }
    return reply.status(200).send({ message: 'Policy updated successfully', policy: result.policy });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/policy/history — policy change history (NEW)
  // ─────────────────────────────────────────────────────
  app.get('/v1/policy/history', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    return reply.status(200).send({ history: policyStore.getHistory(partnerId) });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/detectors — per-tenant detector status (NEW)
  // ─────────────────────────────────────────────────────
  app.get('/v1/detectors', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = req.headers['x-partner-id'] as string;
    const detectors = detectorRegistry.get(partnerId);
    const mttd = detectorRegistry.mttdStats(partnerId);
    return reply.status(200).send({
      partnerId: detectors.partnerId,
      createdAt: detectors.createdAt,
      gateRules: detectors.gate.getRules().length,
      auditLogEntries: detectors.authority.log.getEntries().length,
      mttdStats: mttd,
    });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/health — upgraded with MTTD + detector status
  // ─────────────────────────────────────────────────────
  app.get('/v1/health', async (req: FastifyRequest, reply: FastifyReply) => {
    const partnerId = (req.headers['x-partner-id'] as string) ?? PARTNER_ID;
    const healthy = watchdog.currentStatus === 'RUNNING';
    const slaHealthy = detectorRegistry.isSlaHealthy(partnerId);

    return reply.status(healthy ? 200 : 503).send({
      status: healthy ? 'OK' : 'DEGRADED',
      watchdog: watchdog.currentStatus,
      shell: watchdog.shellLoop?.isRunning ?? false,
      policy: watchdog.shellLoop?.policyProfile.profileId ?? 'UNKNOWN',
      slaHealthy,
      activeTenants: detectorRegistry.activeTenantCount(),
      totalEvents: eventStore.stats(partnerId).total,
      timestamp: new Date().toISOString(),
    });
  });


  // ─────────────────────────────────────────────────────
  // GET /v1/events/sequence/:sequenceId — full sequence (NEW, Toru-William)
  // ─────────────────────────────────────────────────────
  app.get('/v1/events/sequence/:sequenceId', async (req: FastifyRequest<{ Params: { sequenceId: string } }>, reply: FastifyReply) => {
  //const partnerId = req.headers['x-partner-id'] as string;
    const query = req.query as any;

    const partnerId =
    (req.headers['x-partner-id'] as string) ??
    query?.partnerId ??
    query?.['x-partner-id'] ??
    PARTNER_ID;

    const { sequenceId } = req.params;
    const records = eventStore.getSequence(partnerId, sequenceId);
    return reply.status(200).send({
      sequenceId,
      records,
      count: records.length,
    });
  });

  // ─────────────────────────────────────────────────────
  // GET /v1/events/sequence/:sequenceId/summary — pattern summary (NEW, Toru-William)
  // Returns behavioral pattern evidence for Urielle audit consumption.
  // ─────────────────────────────────────────────────────
  app.get('/v1/events/sequence/:sequenceId/summary', async (req: FastifyRequest<{ Params: { sequenceId: string } }>, reply: FastifyReply) => {
  //const partnerId = req.headers['x-partner-id'] as string;
    const query = req.query as any;

    const partnerId =
    (req.headers['x-partner-id'] as string) ??
    query?.partnerId ??
    query?.['x-partner-id'] ??
    PARTNER_ID; 

    const { sequenceId } = req.params;
    const summary = eventStore.summarizeSequence(partnerId, sequenceId);
    if (!summary) {
      return reply.status(404).send({ error: 'NOT_FOUND', message: `No sequence found: ${sequenceId}` });
    }
    return reply.status(200).send(summary);
  });

/*
  // ─────────────────────────────────────────────────────
  // WS /v1/state/stream
  // ─────────────────────────────────────────────────────

  app.get('/v1/state/stream', { websocket: true }, (socket) => {
    wsClients.add(socket as any);
    const state = watchdog.shellLoop?.currentState;
    if (state) (socket as any).send(JSON.stringify({ type: 'state:snapshot', data: state }));
    (socket as any).on('close', () => wsClients.delete(socket as any));
  });
*/

// ─────────────────────────────────────────────────────
// WS /v1/state/stream
// ─────────────────────────────────────────────────────
/*
app.get('/v1/state/stream', { websocket: true }, (socket, req) => {
  const socket = connection.socket;
  const query = req.query as any;

  const partnerId =
    query?.partnerId ??
    query?.['x-partner-id'] ??
    PARTNER_ID;

  console.log('[WS] Client connected:', partnerId);

  wsClients.add(socket as any);

  const state = watchdog.shellLoop?.currentState;
  if (state) {
    (socket as any).send(
      JSON.stringify({
        type: 'state:snapshot',
        partnerId,
        data: state,
      })
    );
  }

  (socket as any).on('close', () => {
    console.log('[WS] Client disconnected:', partnerId);
    wsClients.delete(socket as any);
  });
});
*/
  // ─────────────────────────────────────────────────────
  // WS /v1/state/stream
  // ─────────────────────────────────────────────────────
app.get('/v1/state/stream', { websocket: true }, (connection, req) => {
  const socket = connection.socket;
  const query = req.query as any;

  const partnerId =
    query?.partnerId ??
    query?.['x-partner-id'] ??
    PARTNER_ID;

  console.log('[WS] Client connected:', partnerId);

  wsClients.add(socket as any);

  const state = watchdog.shellLoop?.currentState;

  if (state) {
    socket.send(
      JSON.stringify({
        type: 'state:snapshot',
        partnerId,
        data: state,
      })
    );
  }

  socket.on('close', () => {
    console.log('[WS] Client disconnected:', partnerId);
    wsClients.delete(socket as any);
  });
});


  // ── Graceful shutdown ──────────────────────────────────────────────────────
  const shutdown = async (): Promise<void> => {
    console.log('[API] Shutting down...');
    watchdog.stop();
    await app.close();
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown());
  process.on('SIGINT', () => void shutdown());

  return app;
}


// ─────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const app = await buildServer();
  await app.listen({ port: PORT, host: HOST });
  console.log(`[API] EGS API running on http://${HOST}:${PORT}`);
}

if (process.env['NODE_ENV'] !== 'test') {
main().catch((err) => {
  console.error('[API] Fatal startup error:', err);
  process.exit(1);
});
}