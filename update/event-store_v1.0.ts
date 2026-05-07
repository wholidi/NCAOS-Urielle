/**
 * @ncaos/api — Event Store
 *
 * Phase 04 upgrade: structured event log replacing the simple Map<string, EnforcerOutput>.
 *
 * Provides:
 * - Append-only event log per tenant (isolation enforced)
 * - Pagination (cursor-based, not offset — safe for high-volume logs)
 * - Filtering by layer, severity, action, date range, sequenceId
 * - Evidence handle lookup (O(1) via Map index)
 * - Sequence linking via workflowId → sequenceId (Toru-William interface alignment)
 * - MTTD statistics aggregation
 * - TimescaleDB-ready interface (swap _store for DB calls in Phase 05)
 *
 * Design invariants:
 * - Events are immutable once stored
 * - Evidence handles are the primary key
 * - Tenant isolation: no cross-tenant data access
 * - In-memory store is bounded (MAX_EVENTS_PER_TENANT = 10,000)
 *
 * Toru-William alignment (Phase 04 addition):
 * - sequenceId groups events sharing a workflowId into behavioral sequences
 * - GET /v1/events?sequenceId=WF-001 reconstructs the full event chain
 * - This enables pattern-level audit evidence (DOWNGRADE→BLOCK escalation)
 *   without requiring internal state visibility
 */

import type { GovEvent, ContainmentLayer, Severity } from '@ncaos/core';
import type { EnforcerOutput } from '@ncaos/shell';

// ─────────────────────────────────────────────────────────
// EVENT RECORD
// ─────────────────────────────────────────────────────────

export interface EventRecord {
  evidenceHandle: string;
  partnerId: string;
  event: GovEvent;
  verdict: EnforcerOutput['verdict'];
  storedAt: string;             // ISO 8601
  sequenceNumber: number;       // Monotonically increasing per tenant
  /**
   * sequenceId — groups events belonging to the same workflow sequence.
   * Derived from GovEvent.workflowId when present.
   *
   * Toru-William interface alignment:
   * Enables sequence-level behavioral pattern analysis in the Urielle audit layer:
   * - Query all events in a sequence: GET /v1/events?sequenceId=WF-001
   * - Reconstruct DOWNGRADE→BLOCK escalation chains
   * - Measure enforcement consistency across a workflow
   * - Support "minimum viable signal layer" for audit evidence generation
   */
  sequenceId?: string;
}

// ─────────────────────────────────────────────────────────
// QUERY / FILTER
// ─────────────────────────────────────────────────────────

export interface EventQuery {
  partnerId: string;
  layer?: ContainmentLayer;
  severity?: Severity;
  action?: 'PASS' | 'DOWNGRADE' | 'BLOCK' | 'FAIL_SAFE';
  sequenceId?: string;          // Filter by workflow sequence (Toru-William)
  fromDate?: string;            // ISO 8601
  toDate?: string;              // ISO 8601
  cursor?: string;              // evidenceHandle of last seen record (pagination)
  limit?: number;               // Default: 20, max: 100
}

export interface EventPage {
  records: EventRecord[];
  total: number;
  hasMore: boolean;
  nextCursor: string | null;
}

// ─────────────────────────────────────────────────────────
// SEQUENCE SUMMARY (Toru-William interface)
// ─────────────────────────────────────────────────────────

/**
 * SequenceSummary — behavioral pattern summary for a workflow sequence.
 * This is the "minimum viable signal layer" that supports audit evidence
 * generation without internal state visibility.
 *
 * The Urielle audit layer consumes this to generate governance evidence:
 * - consistencyScore: were enforcement decisions consistent across the sequence?
 * - escalationDetected: did authority degrade progressively?
 * - patternType: what behavioral pattern did this sequence exhibit?
 */
export interface SequenceSummary {
  sequenceId: string;
  partnerId: string;
  eventCount: number;
  firstDetectedAt: string;
  lastDetectedAt: string;
  layers: ContainmentLayer[];
  severities: Severity[];
  actions: string[];
  escalationDetected: boolean;   // PASS→DOWNGRADE→BLOCK pattern
  consistencyScore: number;      // 0–100: how consistent was enforcement?
  patternType:
    | 'STABLE'                   // All PASS, no escalation
    | 'DEGRADING'                // Progressive severity increase
    | 'CONTAINED'                // Escalation detected but terminated
    | 'VOLATILE'                 // Mixed severity without clear pattern
    | 'UNKNOWN';
}

// ─────────────────────────────────────────────────────────
// EVENT STORE
// ─────────────────────────────────────────────────────────

const MAX_EVENTS_PER_TENANT = 10_000;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 100;

const ACTION_RANK: Record<string, number> = {
  PASS: 0, DOWNGRADE: 1, BLOCK: 2, FAIL_SAFE: 3,
};

export class EventStore {
  private readonly logs = new Map<string, EventRecord[]>();
  private readonly index = new Map<string, EventRecord>();
  private readonly sequences = new Map<string, number>();
  // sequenceId → EventRecord[] for fast sequence queries
  private readonly sequenceIndex = new Map<string, EventRecord[]>();

  /**
   * append() — stores a new event record for a tenant.
   */
  append(partnerId: string, output: EnforcerOutput): EventRecord | null {
    if (!output.event) return null;

    const seq = (this.sequences.get(partnerId) ?? 0) + 1;
    this.sequences.set(partnerId, seq);

    // Derive sequenceId from workflowId (Toru-William alignment)
    const sequenceId = output.event.workflowId ?? undefined;

    const record: EventRecord = {
      evidenceHandle: output.event.evidenceHandle,
      partnerId,
      event: output.event,
      verdict: output.verdict,
      storedAt: new Date().toISOString(),
      sequenceNumber: seq,
      sequenceId,
    };

    if (!this.logs.has(partnerId)) {
      this.logs.set(partnerId, []);
    }
    const log = this.logs.get(partnerId)!;

    if (log.length >= MAX_EVENTS_PER_TENANT) {
      const evicted = log.shift();
      if (evicted) {
        this.index.delete(evicted.evidenceHandle);
        if (evicted.sequenceId) {
          const seqLog = this.sequenceIndex.get(evicted.sequenceId) ?? [];
          const idx = seqLog.indexOf(evicted);
          if (idx !== -1) seqLog.splice(idx, 1);
        }
      }
    }

    log.push(record);
    this.index.set(record.evidenceHandle, record);

    // Index by sequenceId for fast sequence queries
    if (sequenceId) {
      if (!this.sequenceIndex.has(sequenceId)) {
        this.sequenceIndex.set(sequenceId, []);
      }
      this.sequenceIndex.get(sequenceId)!.push(record);
    }

    return record;
  }

  /**
   * getByHandle() — O(1) lookup by evidence handle with tenant isolation.
   */
  getByHandle(partnerId: string, evidenceHandle: string): EventRecord | null {
    const record = this.index.get(evidenceHandle) ?? null;
    if (record && record.partnerId !== partnerId) return null;
    return record;
  }

  /**
   * getSequence() — returns all events in a workflow sequence.
   * Core of the Toru-William behavioral pattern interface.
   */
  getSequence(partnerId: string, sequenceId: string): EventRecord[] {
    const records = this.sequenceIndex.get(sequenceId) ?? [];
    return records.filter(r => r.partnerId === partnerId);
  }

  /**
   * summarizeSequence() — derives behavioral pattern evidence from a sequence.
   * This is the "minimum viable signal layer" for Urielle audit consumption.
   */
  summarizeSequence(partnerId: string, sequenceId: string): SequenceSummary | null {
    const records = this.getSequence(partnerId, sequenceId);
    if (records.length === 0) return null;

    const actions = records.map(r => r.verdict.action);
    const severities = records.map(r => r.event.severity) as Severity[];
    const layers = [...new Set(records.map(r => r.event.layer))] as ContainmentLayer[];

    // Detect escalation: action rank increases over time
    const escalationDetected = actions.some((a, i) =>
      i > 0 && (ACTION_RANK[a] ?? 0) > (ACTION_RANK[actions[i - 1]!] ?? 0),
    );

    // Consistency score: lower variance in action rank = higher consistency
    const ranks = actions.map(a => ACTION_RANK[a] ?? 0);
    const mean = ranks.reduce((s, r) => s + r, 0) / ranks.length;
    const variance = ranks.reduce((s, r) => s + Math.pow(r - mean, 2), 0) / ranks.length;
    const consistencyScore = Math.max(0, Math.round(100 - variance * 25));

    // Pattern classification
    const allPass = actions.every(a => a === 'PASS');
    const maxRank = Math.max(...ranks);
    const patternType = ((): SequenceSummary['patternType'] => {
      if (allPass) return 'STABLE';
      if (escalationDetected && maxRank >= ACTION_RANK['BLOCK']!) return 'CONTAINED';
      if (escalationDetected) return 'DEGRADING';
      if (variance > 1) return 'VOLATILE';
      return 'UNKNOWN';
    })();

    return {
      sequenceId,
      partnerId,
      eventCount: records.length,
      firstDetectedAt: records[0]!.storedAt,
      lastDetectedAt: records[records.length - 1]!.storedAt,
      layers,
      severities,
      actions,
      escalationDetected,
      consistencyScore,
      patternType,
    };
  }

  /**
   * query() — paginated, filtered event log.
   */
  query(q: EventQuery): EventPage {
    const limit = Math.min(q.limit ?? DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);

    // Use sequence index for sequenceId queries (fast path)
    let source: EventRecord[];
    if (q.sequenceId) {
      source = this.getSequence(q.partnerId, q.sequenceId);
    } else {
      source = [...(this.logs.get(q.partnerId) ?? [])].reverse();
    }

    let filtered = source;
    if (q.layer)    filtered = filtered.filter(r => r.event.layer === q.layer);
    if (q.severity) filtered = filtered.filter(r => r.event.severity === q.severity);
    if (q.action)   filtered = filtered.filter(r => r.verdict.action === q.action);
    if (q.fromDate) {
      const from = new Date(q.fromDate).getTime();
      filtered = filtered.filter(r => new Date(r.storedAt).getTime() >= from);
    }
    if (q.toDate) {
      const to = new Date(q.toDate).getTime();
      filtered = filtered.filter(r => new Date(r.storedAt).getTime() <= to);
    }

    let startIdx = 0;
    if (q.cursor) {
      const cursorIdx = filtered.findIndex(r => r.evidenceHandle === q.cursor);
      if (cursorIdx !== -1) startIdx = cursorIdx + 1;
    }

    const page = filtered.slice(startIdx, startIdx + limit);
    const hasMore = startIdx + limit < filtered.length;

    return {
      records: page,
      total: filtered.length,
      hasMore,
      nextCursor: hasMore ? (page[page.length - 1]?.evidenceHandle ?? null) : null,
    };
  }

  /**
   * stats() — aggregate statistics for a tenant's event log.
   */
  stats(partnerId: string): {
    total: number;
    byLayer: Record<string, number>;
    bySeverity: Record<string, number>;
    byAction: Record<string, number>;
    activeSequences: number;
  } {
    const log = this.logs.get(partnerId) ?? [];
    const byLayer: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byAction: Record<string, number> = {};
    const sequenceIds = new Set<string>();

    for (const r of log) {
      byLayer[r.event.layer] = (byLayer[r.event.layer] ?? 0) + 1;
      bySeverity[r.event.severity] = (bySeverity[r.event.severity] ?? 0) + 1;
      byAction[r.verdict.action] = (byAction[r.verdict.action] ?? 0) + 1;
      if (r.sequenceId) sequenceIds.add(r.sequenceId);
    }

    return {
      total: log.length,
      byLayer,
      bySeverity,
      byAction,
      activeSequences: sequenceIds.size,
    };
  }

  tenantCount(): number {
    return this.logs.size;
  }

  clear(partnerId: string): void {
    const log = this.logs.get(partnerId) ?? [];
    for (const r of log) {
      this.index.delete(r.evidenceHandle);
      if (r.sequenceId) this.sequenceIndex.delete(r.sequenceId);
    }
    this.logs.delete(partnerId);
    this.sequences.delete(partnerId);
  }
}
