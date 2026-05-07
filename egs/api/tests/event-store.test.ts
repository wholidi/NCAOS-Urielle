/**
 * Unit tests — EventStore
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { EventStore } from '../src/store/event-store.js';
import type { EnforcerOutput } from '@ncaos/shell';

function makeOutput(handle: string, layer = 'gate', severity = 'high', action = 'BLOCK'): EnforcerOutput {
  return {
    verdict: {
      requestId: `REQ-${handle}` as any,
      action: action as any,
      authority: 'invalid',
      integrity: { level: 'Critical', score: 29 },
      policyProfileId: 'STRICT-PROD',
      enforcedAt: new Date().toISOString(),
      processingMs: 5,
    },
    event: {
      requestId: `REQ-${handle}` as any,
      evidenceHandle: handle as any,
      tenant: { partnerId: 'TEST_PARTNER' as any, instanceId: 'INST_001' as any, deployment: 'ENTERPRISE' },
      type: 'EXTERNAL_THREAT_BLOCKED',
      layer: layer as any,
      scope: 'sys',
      severity: severity as any,
      detectionMode: 'Real-time Gate Enforcement',
      integrity: { level: 'Critical', score: 29 },
      authority: { authority: 'invalid', score: 22 },
      routing: { hint: 'SOC / Security Queue', recommendedAction: 'Isolate inputs.' },
      detectedAt: new Date().toISOString(),
      mttdMs: 12,
    },
    state: null as any,
  };
}

describe('EventStore — append and retrieve', () => {
  let store: EventStore;
  beforeEach(() => { store = new EventStore(); });

  it('appends an event and returns a record', () => {
    const record = store.append('TENANT_A', makeOutput('EVD-001-AABB1122'));
    expect(record).not.toBeNull();
    expect(record?.evidenceHandle).toBe('EVD-001-AABB1122');
    expect(record?.partnerId).toBe('TENANT_A');
    expect(record?.sequenceNumber).toBe(1);
  });

  it('returns null when output has no event', () => {
    const output = makeOutput('EVD-002-AABB1122');
    output.event = null as any;
    const record = store.append('TENANT_A', output);
    expect(record).toBeNull();
  });

  it('retrieves by evidence handle', () => {
    store.append('TENANT_A', makeOutput('EVD-003-AABB1122'));
    const record = store.getByHandle('TENANT_A', 'EVD-003-AABB1122');
    expect(record?.evidenceHandle).toBe('EVD-003-AABB1122');
  });

  it('enforces tenant isolation on getByHandle', () => {
    store.append('TENANT_A', makeOutput('EVD-004-AABB1122'));
    const record = store.getByHandle('TENANT_B', 'EVD-004-AABB1122');
    expect(record).toBeNull();
  });

  it('assigns monotonically increasing sequence numbers', () => {
    store.append('TENANT_A', makeOutput('EVD-005-AA001122'));
    store.append('TENANT_A', makeOutput('EVD-005-AA002233'));
    store.append('TENANT_A', makeOutput('EVD-005-AA003344'));
    expect(store.getByHandle('TENANT_A', 'EVD-005-AA001122')?.sequenceNumber).toBe(1);
    expect(store.getByHandle('TENANT_A', 'EVD-005-AA002233')?.sequenceNumber).toBe(2);
    expect(store.getByHandle('TENANT_A', 'EVD-005-AA003344')?.sequenceNumber).toBe(3);
  });

  it('keeps sequence numbers independent per tenant', () => {
    store.append('TENANT_A', makeOutput('EVD-006-AA001122'));
    store.append('TENANT_B', makeOutput('EVD-006-BB001122'));
    expect(store.getByHandle('TENANT_A', 'EVD-006-AA001122')?.sequenceNumber).toBe(1);
    expect(store.getByHandle('TENANT_B', 'EVD-006-BB001122')?.sequenceNumber).toBe(1);
  });
});

describe('EventStore — query and pagination', () => {
  let store: EventStore;

  beforeEach(() => {
    store = new EventStore();
    // Populate with mixed events
    store.append('TENANT_A', makeOutput('EVD-Q01-AA001122', 'gate', 'high', 'BLOCK'));
    store.append('TENANT_A', makeOutput('EVD-Q02-AA002233', 'premise', 'med', 'DOWNGRADE'));
    store.append('TENANT_A', makeOutput('EVD-Q03-AA003344', 'gate', 'high', 'BLOCK'));
    store.append('TENANT_A', makeOutput('EVD-Q04-AA004455', 'authority', 'med', 'BLOCK'));
    store.append('TENANT_A', makeOutput('EVD-Q05-AA005566', 'gate', 'low', 'DOWNGRADE'));
  });

  it('returns all events for a tenant', () => {
    const page = store.query({ partnerId: 'TENANT_A', limit: 100 });
    expect(page.total).toBe(5);
    expect(page.records).toHaveLength(5);
  });

  it('returns newest first', () => {
    const page = store.query({ partnerId: 'TENANT_A', limit: 100 });
    expect(page.records[0]?.evidenceHandle).toBe('EVD-Q05-AA005566');
    expect(page.records[4]?.evidenceHandle).toBe('EVD-Q01-AA001122');
  });

  it('filters by layer', () => {
    const page = store.query({ partnerId: 'TENANT_A', layer: 'gate', limit: 100 });
    expect(page.total).toBe(3);
    for (const r of page.records) expect(r.event.layer).toBe('gate');
  });

  it('filters by severity', () => {
    const page = store.query({ partnerId: 'TENANT_A', severity: 'high', limit: 100 });
    expect(page.total).toBe(2);
    for (const r of page.records) expect(r.event.severity).toBe('high');
  });

  it('paginates with limit', () => {
    const page = store.query({ partnerId: 'TENANT_A', limit: 2 });
    expect(page.records).toHaveLength(2);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).toBeDefined();
  });

  it('uses cursor for second page', () => {
    const page1 = store.query({ partnerId: 'TENANT_A', limit: 2 });
    const page2 = store.query({ partnerId: 'TENANT_A', limit: 2, cursor: page1.nextCursor ?? undefined });
    expect(page2.records).toHaveLength(2);
    // No overlap between pages
    const handles1 = page1.records.map(r => r.evidenceHandle);
    const handles2 = page2.records.map(r => r.evidenceHandle);
    expect(handles1.filter(h => handles2.includes(h))).toHaveLength(0);
  });

  it('returns empty for unknown tenant', () => {
    const page = store.query({ partnerId: 'UNKNOWN', limit: 100 });
    expect(page.total).toBe(0);
    expect(page.records).toHaveLength(0);
    expect(page.hasMore).toBe(false);
  });
});

describe('EventStore — stats', () => {
  it('returns correct aggregate counts', () => {
    const store = new EventStore();
    store.append('TENANT_A', makeOutput('EVD-S01-AA001122', 'gate', 'high', 'BLOCK'));
    store.append('TENANT_A', makeOutput('EVD-S02-AA002233', 'gate', 'med', 'BLOCK'));
    store.append('TENANT_A', makeOutput('EVD-S03-AA003344', 'premise', 'high', 'DOWNGRADE'));
    const stats = store.stats('TENANT_A');
    expect(stats.total).toBe(3);
    expect(stats.byLayer['gate']).toBe(2);
    expect(stats.byLayer['premise']).toBe(1);
    expect(stats.bySeverity['high']).toBe(2);
    expect(stats.byAction['BLOCK']).toBe(2);
    expect(stats.byAction['DOWNGRADE']).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────
// SEQUENCE TESTS (Toru-William alignment)
// ─────────────────────────────────────────────────────────

function makeOutputWithWorkflow(handle: string, workflowId: string, action = 'BLOCK', severity = 'high'): EnforcerOutput {
  const output = makeOutput(handle, 'gate', severity, action);
  output.event!.workflowId = workflowId;
  return output;
}

describe('EventStore — sequence linking (Toru-William)', () => {
  let store: EventStore;
  beforeEach(() => { store = new EventStore(); });

  it('populates sequenceId from workflowId', () => {
    const record = store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ01-AA001122', 'WF-001'));
    expect(record?.sequenceId).toBe('WF-001');
  });

  it('groups events by sequenceId', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ02-AA001122', 'WF-001', 'DOWNGRADE', 'med'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ03-AA002233', 'WF-001', 'BLOCK', 'high'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ04-AA003344', 'WF-002', 'PASS', 'low'));
    const seq = store.getSequence('TENANT_A', 'WF-001');
    expect(seq).toHaveLength(2);
    expect(seq.every(r => r.sequenceId === 'WF-001')).toBe(true);
  });

  it('enforces tenant isolation on sequence queries', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ05-AA001122', 'WF-001'));
    const seq = store.getSequence('TENANT_B', 'WF-001');
    expect(seq).toHaveLength(0);
  });

  it('filters events by sequenceId in query()', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ06-AA001122', 'WF-001', 'BLOCK', 'high'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ07-AA002233', 'WF-001', 'DOWNGRADE', 'med'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SQ08-AA003344', 'WF-002', 'BLOCK', 'high'));
    const page = store.query({ partnerId: 'TENANT_A', sequenceId: 'WF-001', limit: 100 });
    expect(page.records).toHaveLength(2);
    expect(page.records.every(r => r.sequenceId === 'WF-001')).toBe(true);
  });
});

describe('EventStore — summarizeSequence (Toru-William)', () => {
  let store: EventStore;
  beforeEach(() => { store = new EventStore(); });

  it('returns null for unknown sequence', () => {
    const summary = store.summarizeSequence('TENANT_A', 'WF-UNKNOWN');
    expect(summary).toBeNull();
  });

  it('classifies STABLE when all actions are PASS', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SUM01-AA001122', 'WF-STABLE', 'PASS', 'low'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SUM02-AA002233', 'WF-STABLE', 'PASS', 'low'));
    const summary = store.summarizeSequence('TENANT_A', 'WF-STABLE');
    expect(summary?.patternType).toBe('STABLE');
    expect(summary?.escalationDetected).toBe(false);
    expect(summary?.consistencyScore).toBe(100);
  });

  it('classifies CONTAINED when BLOCK follows DOWNGRADE', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SUM03-AA001122', 'WF-CONT', 'DOWNGRADE', 'med'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SUM04-AA002233', 'WF-CONT', 'BLOCK', 'high'));
    const summary = store.summarizeSequence('TENANT_A', 'WF-CONT');
    expect(summary?.escalationDetected).toBe(true);
    expect(summary?.patternType).toBe('CONTAINED');
  });

  it('includes correct event count and layers', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SUM05-AA001122', 'WF-META', 'BLOCK', 'high'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-SUM06-AA002233', 'WF-META', 'BLOCK', 'high'));
    const summary = store.summarizeSequence('TENANT_A', 'WF-META');
    expect(summary?.eventCount).toBe(2);
    expect(summary?.partnerId).toBe('TENANT_A');
    expect(summary?.sequenceId).toBe('WF-META');
  });

  it('stats includes activeSequences count', () => {
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-STAT01-AA001122', 'WF-001'));
    store.append('TENANT_A', makeOutputWithWorkflow('EVD-STAT02-AA002233', 'WF-002'));
    store.append('TENANT_A', makeOutput('EVD-STAT03-AA003344')); // no workflowId
    const stats = store.stats('TENANT_A');
    expect(stats.activeSequences).toBe(2);
  });
});
