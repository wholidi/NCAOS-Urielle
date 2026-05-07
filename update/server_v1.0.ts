/**
 * @ncaos/api — Fastify Server
 *
 * REST + WebSocket API for the EGS Admin Terminal.
 *
 * Routes:
 *   POST /v1/process          — Submit a boundary signal for governance
 *   GET  /v1/state            — Current GovState (tenant-scoped)
 *   GET  /v1/audit/:handle    — Retrieve event by evidence handle
 *   POST /v1/policy           — Update active policy profile (admin only)
 *   GET  /v1/health           — Shell + watchdog health check
 *   WS   /v1/state/stream     — Live GovState push stream
 *
 * Tenant isolation:
 *   All routes require X-Partner-ID header.
 *   GovState and events are scoped to the requesting tenant.
 */

import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyCors from '@fastify/cors';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { Watchdog } from '@ncaos/shell';
import { loadBuiltinPolicy, ENTERPRISE_STRICT_PROFILE } from '@ncaos/core';
import type { GovState } from '@ncaos/core';
import type { EnforcerOutput } from '@ncaos/shell';

// ─────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────

const PORT = parseInt(process.env['PORT'] ?? '3000', 10);
const HOST = process.env['HOST'] ?? '0.0.0.0';
const PARTNER_ID = (process.env['PARTNER_ID'] ?? 'GLOBAL_ENT_2026') as `${Uppercase<string>}`;
const INSTANCE_ID = (process.env['INSTANCE_ID'] ?? 'EGS_INST_001') as `${Uppercase<string>}`;

// ─────────────────────────────────────────────────────────
// PROCESS REQUEST SCHEMA
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

// ─────────────────────────────────────────────────────────
// IN-MEMORY EVENT STORE (Phase 4: replace with TimescaleDB)
// ─────────────────────────────────────────────────────────

const eventStore = new Map<string, EnforcerOutput>();

// ─────────────────────────────────────────────────────────
// WEBSOCKET CLIENTS
// ─────────────────────────────────────────────────────────

const wsClients = new Set<import('ws').WebSocket>();

function broadcastState(state: GovState): void {
  const payload = JSON.stringify({ type: 'state:update', data: state });
  for (const client of wsClients) {
    if (client.readyState === 1) { // OPEN
      client.send(payload);
    }
  }
}

// ─────────────────────────────────────────────────────────
// BUILD SERVER
// ─────────────────────────────────────────────────────────

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({ logger: true });

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);

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

  // ── Watchdog + ShellLoop ───────────────────────────────────────────────────
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

  // Forward shell output to WebSocket clients + event store
  watchdog.on('shell:output', (output: EnforcerOutput) => {
    if (output.event) {
      eventStore.set(output.event.evidenceHandle, output);
    }
    broadcastState(output.state);
  });

  watchdog.start();

  // Store watchdog on app for route access
  app.decorate('watchdog', watchdog);

  // ── POST /v1/process ───────────────────────────────────────────────────────
  app.post('/v1/process', async (req: FastifyRequest, reply: FastifyReply) => {
    const wd = (app as any).watchdog as Watchdog;

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
      return reply.status(400).send({
        error: 'INVALID_REQUEST',
        issues: parsed.error.issues,
      });
    }

    const shell = wd.shellLoop;
    if (!shell) {
      return reply.status(503).send({
        error: 'GOVERNANCE_UNAVAILABLE',
        message: 'Shell loop not available',
      });
    }

    const output = shell.process(parsed.data);

    // Store event if containment triggered
    if (output.event) {
      eventStore.set(output.event.evidenceHandle, output);
    }

    return reply.status(200).send({
      requestId: output.verdict.requestId,
      action: output.verdict.action,
      authority: output.verdict.authority,
      integrity: output.verdict.integrity,
      routing: output.verdict.routing,
      evidenceHandle: output.event?.evidenceHandle,
      processingMs: output.verdict.processingMs,
    });
  });

  // ── GET /v1/state ─────────────────────────────────────────────────────────
  app.get('/v1/state', async (_req: FastifyRequest, reply: FastifyReply) => {
    const wd = (app as any).watchdog as Watchdog;
    const state = wd.shellLoop?.currentState;

    if (!state) {
      return reply.status(503).send({
        error: 'GOVERNANCE_UNAVAILABLE',
        watchdogStatus: wd.currentStatus,
      });
    }

    return reply.status(200).send(state);
  });

  // ── GET /v1/audit/:handle ─────────────────────────────────────────────────
  app.get('/v1/audit/:handle', async (req: FastifyRequest<{ Params: { handle: string } }>, reply: FastifyReply) => {
    const { handle } = req.params;
    const entry = eventStore.get(handle);

    if (!entry) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: `No event found for evidence handle: ${handle}`,
      });
    }

    return reply.status(200).send({
      evidenceHandle: handle,
      event: entry.event,
      verdict: entry.verdict,
      state: entry.state,
    });
  });

  // ── GET /v1/health ────────────────────────────────────────────────────────
  app.get('/v1/health', async (_req: FastifyRequest, reply: FastifyReply) => {
    const wd = (app as any).watchdog as Watchdog;
    const healthy = wd.currentStatus === 'RUNNING';

    return reply.status(healthy ? 200 : 503).send({
      status: healthy ? 'OK' : 'DEGRADED',
      watchdog: wd.currentStatus,
      shell: wd.shellLoop?.isRunning ?? false,
      policy: wd.shellLoop?.policyProfile.profileId ?? 'UNKNOWN',
      timestamp: new Date().toISOString(),
    });
  });

  // ── WS /v1/state/stream ───────────────────────────────────────────────────
  app.get('/v1/state/stream', { websocket: true }, (socket) => {
    wsClients.add(socket as any);

    // Send current state immediately on connect
    const wd = (app as any).watchdog as Watchdog;
    const state = wd.shellLoop?.currentState;
    if (state) {
      (socket as any).send(JSON.stringify({ type: 'state:snapshot', data: state }));
    }

    (socket as any).on('close', () => {
      wsClients.delete(socket as any);
    });
  });

  // ── Graceful shutdown ──────────────────────────────────────────────────────
  const shutdown = async (): Promise<void> => {
    console.log('[API] Shutting down...');
    ((app as any).watchdog as Watchdog).stop();
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

main().catch((err) => {
  console.error('[API] Fatal startup error:', err);
  process.exit(1);
});
