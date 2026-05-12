/**
 * @ncaos/ui — API Client
 *
 * Typed fetch wrappers for all EGS API endpoints.
 * All requests include X-Partner-ID header (tenant isolation).
 * WebSocket connection for live GovState streaming.
 */

// ─────────────────────────────────────────────────────────
// TYPES (mirrors API response shapes)
// ─────────────────────────────────────────────────────────

export interface GovStateResponse {
  tenant: { partnerId: string; instanceId: string; deployment: string };
  systemStatus: string;
  operationalMode: 'NORMAL' | 'LIMITED' | 'CONTAINMENT';
  shellIntegrity: boolean;
  failSafeEnabled: boolean;
  integrity: { level: string; score: number };
  authority: { authority: string; score: number };
  rawExposurePct: number;
  governedOutputPct: number;
  coreIsolationPct: number;
  contextDriftPressurePct: number;
  latencyOverheadMs: number;
  updateState: 'STABLE' | 'PROVISIONAL' | 'UNSTABLE';
  continuityScore: number;
  changeWindowActive: boolean;
  equivalenceTests: { passed: number; total: number };
  activeEvent?: string;
  lastRouting?: string;
  blockedLayer?: string;
  updatedAt: string;
}

export interface HealthResponse {
  status: 'OK' | 'DEGRADED';
  watchdog: string;
  shell: boolean;
  policy: string;
  slaHealthy: boolean;
  activeTenants: number;
  totalEvents: number;
  timestamp: string;
}

export interface EventRecord {
  evidenceHandle: string;
  partnerId: string;
  event: {
    requestId: string;
    type: string;
    layer: string;
    scope: string;
    severity: 'low' | 'med' | 'high';
    detectionMode: string;
    integrity: { level: string; score: number };
    authority: { authority: string; score: number };
    routing: { hint: string; recommendedAction: string };
    detectedAt: string;
    mttdMs: number;
    workflowId?: string;
  };
  verdict: {
    requestId: string;
    action: 'PASS' | 'DOWNGRADE' | 'BLOCK' | 'FAIL_SAFE';
    authority: string;
    integrity: { level: string; score: number };
    processingMs: number;
  };
  storedAt: string;
  sequenceNumber: number;
  sequenceId?: string;
}

export interface EventsResponse {
  records: EventRecord[];
  pagination: {
    total: number;
    hasMore: boolean;
    nextCursor: string | null;
    limit: number;
  };
}

export interface EventStatsResponse {
  total: number;
  byLayer: Record<string, number>;
  bySeverity: Record<string, number>;
  byAction: Record<string, number>;
  activeSequences: number;
}

export interface MttdLayer {
  layer: string;
  sampleCount: number;
  slaMs: number;
  slaBreach: number;
  slaBreachRate: number;
  min: number;
  max: number;
  p50: number;
  p95: number;
  p99: number;
  mean: number;
}

export interface MttdResponse {
  slaHealthy: boolean;
  layers: MttdLayer[];
}

export interface PolicyResponse {
  profileId: string;
  label: string;
  govLevel: string;
  integrityThresholds: { available: number; limited: number; degraded: number };
  continuityThresholds: { stable: number; provisional: number };
  mttdSlaMs: { gate: number; premise: number; authority: number; continuity: number };
  blockOnContainment: boolean;
  partnerId: string;
}

export interface SequenceSummary {
  sequenceId: string;
  partnerId: string;
  eventCount: number;
  firstDetectedAt: string;
  lastDetectedAt: string;
  layers: string[];
  severities: string[];
  actions: string[];
  escalationDetected: boolean;
  consistencyScore: number;
  patternType: 'STABLE' | 'DEGRADING' | 'CONTAINED' | 'VOLATILE' | 'UNKNOWN';
}

export interface DetectorsResponse {
  partnerId: string;
  createdAt: string;
  gateRules: number;
  auditLogEntries: number;
  mttdStats: MttdLayer[];
}

// ─────────────────────────────────────────────────────────
// BASE CLIENT
// ─────────────────────────────────────────────────────────

const BASE = '/v1';

function headers(partnerId: string): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'X-Partner-ID': partnerId,
  };
}

async function get<T>(path: string, partnerId: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: headers(partnerId) });
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, partnerId: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: headers(partnerId),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────
// API FUNCTIONS
// ─────────────────────────────────────────────────────────

export const api = {
  health: (partnerId: string) =>
    get<HealthResponse>('/health', partnerId),

  state: (partnerId: string) =>
    get<GovStateResponse>('/state', partnerId),

  events: (partnerId: string, params?: {
    layer?: string; severity?: string; action?: string;
    limit?: number; cursor?: string; sequenceId?: string;
  }) => {
    const qs = new URLSearchParams();
    if (params?.layer) qs.set('layer', params.layer);
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.action) qs.set('action', params.action);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.cursor) qs.set('cursor', params.cursor);
    if (params?.sequenceId) qs.set('sequenceId', params.sequenceId);
    const q = qs.toString();
    return get<EventsResponse>(`/events${q ? '?' + q : ''}`, partnerId);
  },

  eventStats: (partnerId: string) =>
    get<EventStatsResponse>('/events/stats', partnerId),

  audit: (partnerId: string, handle: string) =>
    get<{ evidenceHandle: string; event: EventRecord['event']; verdict: EventRecord['verdict']; storedAt: string; sequenceNumber: number }>(`/audit/${handle}`, partnerId),

  mttd: (partnerId: string) =>
    get<MttdResponse>('/mttd', partnerId),

  policy: (partnerId: string) =>
    get<PolicyResponse>('/policy', partnerId),

  policyHistory: (partnerId: string) =>
    get<{ history: Array<{ policy: PolicyResponse; activatedAt: string; activatedBy: string }> }>('/policy/history', partnerId),

  sequence: (partnerId: string, sequenceId: string) =>
    get<{ sequenceId: string; records: EventRecord[]; count: number }>(`/events/sequence/${sequenceId}`, partnerId),

  sequenceSummary: (partnerId: string, sequenceId: string) =>
    get<SequenceSummary>(`/events/sequence/${sequenceId}/summary`, partnerId),

  detectors: (partnerId: string) =>
    get<DetectorsResponse>('/detectors', partnerId),

  process: (partnerId: string, input: Record<string, unknown>) =>
    post<{ requestId: string; action: string; authority: string; integrity: object; evidenceHandle?: string; processingMs: number }>('/process', partnerId, input),
};

// ─────────────────────────────────────────────────────────
// WEBSOCKET — live GovState stream
// ─────────────────────────────────────────────────────────

export function createStateStream(
  onState: (state: GovStateResponse) => void,
  onError?: (err: Event) => void,
  onOpen?: () => void,
): () => void {
  const ws = new WebSocket(
    `ws://localhost:3000/v1/state/stream?partnerId=GLOBAL_ENT_2026`
  );

  ws.onopen = () => {
    console.log('[WS] connected');
    if (onOpen) onOpen();
  };

  ws.onmessage = (msg) => {
    try {
      const payload = JSON.parse(msg.data as string) as {
        type: string;
        data: GovStateResponse;
      };

      if (
        payload.type === 'state:update' ||
        payload.type === 'state:snapshot'
      ) {
        onState(payload.data);
      }
    } catch {
      // ignore malformed
    }
  };

  ws.onclose = (event) => {
    console.log('[WS] closed', event.code, event.reason);
  };

  ws.onerror = (err) => {
    console.error('[WS] error', err);
    if (onError) onError(err);
  };

  return () => ws.close();
}