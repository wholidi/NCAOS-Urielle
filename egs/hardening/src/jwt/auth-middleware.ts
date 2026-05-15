/**
 * @ncaos/hardening — JWT Authentication Middleware
 *
 * Phase 06 security hardening: fixes STRIDE threat S-001 (HIGH risk).
 *
 * S-001: Attacker forges X-Partner-ID to impersonate another tenant.
 * Current state: X-Partner-ID header is unauthenticated — any string accepted.
 * Fix: JWT Bearer token in Authorization header. X-Partner-ID must match
 *      the 'sub' claim in the validated JWT.
 *
 * RBAC roles:
 *   operator  — POST /v1/process, GET /v1/state, GET /v1/events, GET /v1/audit/*
 *   admin     — + POST /v1/policy, GET /v1/policy/history, GET /v1/detectors
 *   auditor   — GET /v1/events, GET /v1/audit/*, GET /v1/events/sequence/*
 *
 * Fixes STRIDE threats: S-001, T-002, E-001
 */

import type { FastifyRequest, FastifyReply } from 'fastify';

// ─────────────────────────────────────────────────────────
// JWT PAYLOAD
// ─────────────────────────────────────────────────────────

export type JwtRole = 'operator' | 'admin' | 'auditor';

export interface JwtPayload {
  sub: string;        // PARTNER_ID — must match X-Partner-ID header
  role: JwtRole;
  iat: number;
  exp: number;
  iss: string;        // 'ncaos-egs'
}

export interface AuthContext {
  partnerId: string;
  role: JwtRole;
}

// ─────────────────────────────────────────────────────────
// RBAC ROUTE MAP
// ─────────────────────────────────────────────────────────

const ROUTE_ROLES: Record<string, JwtRole[]> = {
  'POST /v1/process':                    ['operator', 'admin'],
  'GET /v1/state':                       ['operator', 'admin', 'auditor'],
  'GET /v1/health':                      ['operator', 'admin', 'auditor'],
  'GET /v1/events':                      ['operator', 'admin', 'auditor'],
  'GET /v1/events/stats':                ['operator', 'admin', 'auditor'],
  'GET /v1/events/sequence/:id':         ['operator', 'admin', 'auditor'],
  'GET /v1/events/sequence/:id/summary': ['operator', 'admin', 'auditor'],
  'GET /v1/audit/:handle':               ['operator', 'admin', 'auditor'],
  'GET /v1/mttd':                        ['operator', 'admin', 'auditor'],
  'GET /v1/policy':                      ['operator', 'admin', 'auditor'],
  'POST /v1/policy':                     ['admin'],                         // admin only
  'GET /v1/policy/history':              ['admin', 'auditor'],
  'GET /v1/detectors':                   ['admin'],                         // admin only
  'WS /v1/state/stream':                 ['operator', 'admin'],
};

// ─────────────────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────────────────

/**
 * verifyJwt() — Fastify preHandler hook.
 *
 * 1. Extracts Bearer token from Authorization header
 * 2. Validates JWT signature (HS256, secret from JWT_SECRET env var)
 * 3. Checks exp, iss claims
 * 4. Verifies X-Partner-ID header matches JWT sub claim
 * 5. Checks RBAC role for the requested route
 *
 * Phase 06: Uses manual JWT parsing (no external lib) for minimal deps.
 * Phase 07 upgrade: Replace with @fastify/jwt for full RS256 support.
 *
 * In dev/test mode (JWT_SECRET=undefined), authentication is bypassed
 * and the X-Partner-ID header is used directly (Phase 02–05 behavior).
 */
export async function verifyJwt(
  req: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const secret = process.env['JWT_SECRET'];

  // Dev mode — no JWT enforcement (Phase 02–05 compatibility)
  if (!secret) {
    const partnerId = req.headers['x-partner-id'] as string | undefined;
    if (!partnerId) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'X-Partner-ID header required',
      });
    }
    // Attach auth context with default operator role
    (req as any).auth = { partnerId, role: 'operator' } as AuthContext;
    return;
  }

  // Production mode — JWT required
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'Bearer token required in Authorization header',
    });
  }

  const token = authHeader.slice(7);
  const payload = await verifyToken(token, secret);

  if (!payload) {
    return reply.status(401).send({
      error: 'INVALID_TOKEN',
      message: 'JWT validation failed — token invalid or expired',
    });
  }

  // Verify X-Partner-ID matches JWT sub
  const partnerId = req.headers['x-partner-id'] as string | undefined;
  if (!partnerId) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'X-Partner-ID header required',
    });
  }

  if (partnerId !== payload.sub) {
    return reply.status(403).send({
      error: 'FORBIDDEN',
      message: `X-Partner-ID (${partnerId}) does not match JWT sub (${payload.sub})`,
    });
  }

  // RBAC check
  const routeKey = `${req.method} ${req.routeOptions?.url ?? req.url}`;
  const allowedRoles = ROUTE_ROLES[routeKey];
  if (allowedRoles && !allowedRoles.includes(payload.role)) {
    return reply.status(403).send({
      error: 'FORBIDDEN',
      message: `Role '${payload.role}' is not authorized for ${routeKey}`,
    });
  }

  (req as any).auth = { partnerId, role: payload.role } as AuthContext;
}

// ─────────────────────────────────────────────────────────
// JWT VERIFICATION (manual HS256, no external deps)
// ─────────────────────────────────────────────────────────

async function verifyToken(token: string, secret: string): Promise<JwtPayload | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header64, payload64, sig64] = parts as [string, string, string];

    // Verify signature using Web Crypto API (Node 18+ / browser)
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const key = await crypto.subtle.importKey(
      'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );

    const sigBytes = base64urlDecode(sig64);
    const data = encoder.encode(`${header64}.${payload64}`);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) return null;

    // Decode payload
    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(payload64)),
    ) as JwtPayload;

    // Check expiry
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

    // Check issuer
    if (payload.iss !== 'ncaos-egs') return null;

    return payload;
  } catch {
    return null;
  }
}

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// ─────────────────────────────────────────────────────────
// RATE LIMITER — fixes D-001 (DoS via unbounded /v1/process)
// ─────────────────────────────────────────────────────────

/**
 * RateLimiter — token bucket per PARTNER_ID.
 * Fixes STRIDE threat D-001 (HIGH risk):
 * Attacker floods /v1/process to exhaust shell processing capacity.
 *
 * Config: 100 requests/second per tenant (burst: 150).
 * Phase 07: Move to Redis for multi-node deployments.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; lastRefill: number }>();
  private readonly ratePerSec: number;
  private readonly burst: number;

  constructor(ratePerSec = 100, burst = 150) {
    this.ratePerSec = ratePerSec;
    this.burst = burst;
  }

  /**
   * check() — returns true if request is allowed, false if rate-limited.
   */
  check(partnerId: string): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(partnerId);

    if (!bucket) {
      bucket = { tokens: this.burst, lastRefill: now };
      this.buckets.set(partnerId, bucket);
    }

    // Refill tokens based on elapsed time
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(this.burst, bucket.tokens + elapsed * this.ratePerSec);
    bucket.lastRefill = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }

    return false;
  }

  stats(partnerId: string): { tokens: number; ratePerSec: number; burst: number } {
    const bucket = this.buckets.get(partnerId);
    return {
      tokens: bucket ? Math.floor(bucket.tokens) : this.burst,
      ratePerSec: this.ratePerSec,
      burst: this.burst,
    };
  }
}

export const rateLimiter = new RateLimiter();

/**
 * rateLimitMiddleware() — Fastify preHandler hook for /v1/process.
 * Returns 429 Too Many Requests when rate limit exceeded.
 */
export async function rateLimitMiddleware(
  req: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const partnerId = (req as any).auth?.partnerId
    ?? (req.headers['x-partner-id'] as string)
    ?? 'UNKNOWN';

  if (!rateLimiter.check(partnerId)) {
    return reply.status(429).send({
      error: 'RATE_LIMITED',
      message: `Rate limit exceeded for partner ${partnerId}. Limit: 100 req/s.`,
      retryAfterMs: 1000,
    });
  }
}
