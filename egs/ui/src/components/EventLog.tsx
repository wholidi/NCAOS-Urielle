/**
 * @ncaos/ui — Secondary Components
 * EventLog · MttdPanel · SequencePanel · PolicyPanel · ContainmentChart
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import { api } from '../lib/api.js';
import type { EventRecord, MttdLayer } from '../lib/api.js';

// ─────────────────────────────────────────────────────────
// EVENT LOG
// ─────────────────────────────────────────────────────────

export function EventLog({
  partnerId,
  onSequenceSelect,
}: {
  partnerId: string;
  onSequenceSelect?: (id: string) => void;
}) {
  const [layerFilter, setLayerFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['events', partnerId, layerFilter, severityFilter],
    queryFn: () => api.events(partnerId, {
      layer: layerFilter || undefined,
      severity: severityFilter || undefined,
      limit: 30,
    }),
    refetchInterval: 8_000,
  });

  return (
    <div className="panel">
      <div className="panel-title">
        EVENT LOG
        <span style={{ color: 'var(--fg3)', fontWeight: 'normal', fontSize: '10px', marginLeft: 'auto' }}>
          {data?.pagination.total ?? '—'} total
        </span>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
        {['', 'gate', 'premise', 'authority', 'continuity'].map(v => (
          <button key={v} onClick={() => setLayerFilter(v)}
            style={{
              padding: '2px 8px', fontSize: '10px', cursor: 'pointer',
              border: '1px solid var(--border)',
              background: layerFilter === v ? 'rgba(0,195,255,0.15)' : 'transparent',
              color: layerFilter === v ? 'var(--accent2)' : 'var(--fg3)',
              fontFamily: 'var(--mono)',
            }}>
            {v || 'ALL'}
          </button>
        ))}
        <span style={{ color: 'var(--fg3)', padding: '2px 4px' }}>|</span>
        {['', 'high', 'med', 'low'].map(v => (
          <button key={v} onClick={() => setSeverityFilter(v)}
            style={{
              padding: '2px 8px', fontSize: '10px', cursor: 'pointer',
              border: '1px solid var(--border)',
              background: severityFilter === v ? 'rgba(0,195,255,0.15)' : 'transparent',
              color: severityFilter === v ? 'var(--accent2)' : 'var(--fg3)',
              fontFamily: 'var(--mono)',
            }}>
            {v || 'ALL SEV'}
          </button>
        ))}
      </div>

      {isLoading && <div className="loading">loading events...</div>}
      {data && (
        <div style={{ overflowX: 'auto' }}>
          <table className="event-table">
            <thead>
              <tr>
                <th>RID</th><th>LAYER</th><th>SEV</th><th>ACTION</th>
                <th>EVIDENCE HANDLE</th><th>DETECTED</th>
              </tr>
            </thead>
            <tbody>
              {data.records.length === 0 && (
                <tr><td colSpan={6} className="loading">no events</td></tr>
              )}
              {data.records.map((r: EventRecord) => (
                <tr key={r.evidenceHandle}>
                  <td style={{ color: 'var(--fg2)' }}>{r.event.requestId}</td>
                  <td style={{ color: 'var(--fg2)', textTransform: 'uppercase' }}>{r.event.layer}</td>
                  <td><span className={`sev-badge sev-${r.event.severity}`}>{r.event.severity.toUpperCase()}</span></td>
                  <td><span className={`action-badge action-${r.verdict.action}`}>{r.verdict.action}</span></td>
                  <td>
                    <span
                      className="evidence-handle"
                      onClick={() => r.sequenceId && onSequenceSelect?.(r.sequenceId)}
                      title={r.sequenceId ? `Click to view sequence ${r.sequenceId}` : undefined}
                    >
                      {r.evidenceHandle}
                      {r.sequenceId && <span style={{ color: 'var(--fg3)', marginLeft: '4px' }}>↗</span>}
                    </span>
                  </td>
                  <td className="timestamp">{new Date(r.storedAt).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// MTTD PANEL
// ─────────────────────────────────────────────────────────

export function MttdPanel({ partnerId, expanded = false }: { partnerId: string; expanded?: boolean }) {
  const { data } = useQuery({
    queryKey: ['mttd', partnerId],
    queryFn: () => api.mttd(partnerId),
    refetchInterval: 15_000,
  });

  const mttdColor = (layer: MttdLayer) =>
    layer.slaBreachRate > 0.1 ? 'bad' : layer.slaBreachRate > 0.05 ? 'warn' : 'ok';

  return (
    <div className="panel">
      <div className="panel-title">
        MTTD / SLA
        <span style={{ marginLeft: 'auto', fontSize: '10px', fontWeight: 'normal' }}>
          {data?.slaHealthy
            ? <span style={{ color: 'var(--ok)' }}>● WITHIN SLA</span>
            : <span style={{ color: 'var(--bad)' }}>● SLA BREACH</span>}
        </span>
      </div>
      {!data && <div className="loading">loading...</div>}
      {data?.layers.map((l: MttdLayer) => (
        <div key={l.layer} style={{ marginBottom: expanded ? '12px' : '6px' }}>
          <div className="bar-label" style={{ marginBottom: '3px' }}>
            <span style={{ textTransform: 'uppercase', color: 'var(--fg2)' }}>{l.layer}</span>
            <span style={{ color: `var(--${mttdColor(l)})` }}>
              p50:{l.p50.toFixed(1)}ms / SLA:{l.slaMs}ms
            </span>
          </div>
          <div className="bar-track">
            <div
              className={`bar-fill ${mttdColor(l)}`}
              style={{ width: `${Math.min(100, (l.p50 / l.slaMs) * 100)}%` }}
            />
          </div>
          {expanded && (
            <div style={{ display: 'flex', gap: '12px', marginTop: '3px', fontSize: '10px', color: 'var(--fg3)' }}>
              <span>samples:{l.sampleCount}</span>
              <span>p95:{l.p95.toFixed(1)}ms</span>
              <span>p99:{l.p99.toFixed(1)}ms</span>
              <span style={{ color: l.slaBreach > 0 ? 'var(--bad)' : 'var(--fg3)' }}>
                breach:{l.slaBreach}
              </span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// SEQUENCE PANEL (Toru-William interface)
// ─────────────────────────────────────────────────────────

export function SequencePanel({ partnerId, sequenceId }: { partnerId: string; sequenceId: string }) {
  const { data: summary } = useQuery({
    queryKey: ['sequence-summary', partnerId, sequenceId],
    queryFn: () => api.sequenceSummary(partnerId, sequenceId),
  });

  const { data: events } = useQuery({
    queryKey: ['sequence-events', partnerId, sequenceId],
    queryFn: () => api.sequence(partnerId, sequenceId),
  });

  if (!summary) return <div className="panel"><div className="loading">loading sequence...</div></div>;

  return (
    <div className="panel">
      <div className="panel-title">
        SEQUENCE ANALYSIS — {sequenceId}
        <span className={`pattern-badge pattern-${summary.patternType}`} style={{ marginLeft: 'auto' }}>
          {summary.patternType}
        </span>
      </div>

      <div className="seq-summary">
        <div className="stat">
          <div className="stat-label">EVENT COUNT</div>
          <div className="stat-value sm accent">{summary.eventCount}</div>
        </div>
        <div className="stat">
          <div className="stat-label">CONSISTENCY SCORE</div>
          <div className={`stat-value sm ${summary.consistencyScore >= 80 ? 'ok' : summary.consistencyScore >= 60 ? 'warn' : 'bad'}`}>
            {summary.consistencyScore}/100
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">ESCALATION</div>
          <div className={`stat-value sm ${summary.escalationDetected ? 'bad' : 'ok'}`}>
            {summary.escalationDetected ? 'DETECTED' : 'NONE'}
          </div>
        </div>
      </div>

      <div style={{ marginTop: '10px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {summary.actions.map((a, i) => (
          <span key={i} className={`action-badge action-${a}`}>{a}</span>
        ))}
      </div>

      <div style={{ marginTop: '8px', display: 'flex', gap: '16px', fontSize: '10px', color: 'var(--fg3)' }}>
        <span>from: {new Date(summary.firstDetectedAt).toLocaleTimeString()}</span>
        <span>to: {new Date(summary.lastDetectedAt).toLocaleTimeString()}</span>
        <span>layers: {summary.layers.join(', ')}</span>
      </div>

      {/* Event chain visualization */}
      {events && events.records.length > 0 && (
        <div style={{ marginTop: '12px', overflowX: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', paddingBottom: '4px' }}>
            {events.records.map((r: EventRecord, i: number) => (
              <div key={r.evidenceHandle} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <div style={{
                  padding: '4px 8px',
                  border: `1px solid ${r.verdict.action === 'BLOCK' ? 'var(--bad)' : r.verdict.action === 'DOWNGRADE' ? 'var(--warn)' : 'var(--ok)'}`,
                  fontSize: '10px', textAlign: 'center',
                  background: r.verdict.action === 'BLOCK' ? 'var(--bad-dim)' : r.verdict.action === 'DOWNGRADE' ? 'var(--warn-dim)' : 'var(--ok-dim)',
                }}>
                  <div style={{ color: 'var(--fg3)', fontSize: '9px' }}>#{r.sequenceNumber}</div>
                  <div className={`action-${r.verdict.action}`}>{r.verdict.action}</div>
                  <div style={{ color: 'var(--fg3)', fontSize: '9px' }}>{r.event.severity}</div>
                </div>
                {i < events.records.length - 1 && (
                  <div style={{ color: 'var(--fg3)', fontSize: '12px' }}>→</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// POLICY PANEL
// ─────────────────────────────────────────────────────────

export function PolicyPanel({ partnerId }: { partnerId: string }) {
  const { data } = useQuery({
    queryKey: ['policy', partnerId],
    queryFn: () => api.policy(partnerId),
    refetchInterval: 30_000,
  });

  if (!data) return <div className="panel"><div className="loading">loading policy...</div></div>;

  return (
    <div className="panel">
      <div className="panel-title">ACTIVE POLICY</div>
      <div className="field-row"><div className="field-key">PROFILE_ID</div><div className="field-val accent">{data.profileId}</div></div>
      <div className="field-row"><div className="field-key">GOV_LEVEL</div><div className="field-val">{data.govLevel}</div></div>
      <div className="field-row"><div className="field-key">BLOCK_ON_CONTAIN</div><div className={`field-val ${data.blockOnContainment ? 'bad' : 'warn'}`}>{data.blockOnContainment ? 'YES' : 'NO'}</div></div>
      <div className="field-row"><div className="field-key">GATE SLA</div><div className="field-val">{data.mttdSlaMs.gate}ms</div></div>
      <div className="field-row"><div className="field-key">PREMISE SLA</div><div className="field-val">{data.mttdSlaMs.premise}ms</div></div>
      <div className="field-row"><div className="field-key">AUTHORITY SLA</div><div className="field-val">{data.mttdSlaMs.authority}ms</div></div>
      <div className="field-row"><div className="field-key">CONTINUITY SLA</div><div className="field-val">{data.mttdSlaMs.continuity}ms</div></div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// CONTAINMENT CHART (RAW vs GOVERNED — Executive view)
// ─────────────────────────────────────────────────────────

export function ContainmentChart({ partnerId }: { partnerId: string }) {
  const { data: events } = useQuery({
    queryKey: ['events-chart', partnerId],
    queryFn: () => api.events(partnerId, { limit: 20 }),
    refetchInterval: 10_000,
  });

  const chartData = (events?.records ?? []).slice().reverse().map((r: EventRecord, i: number) => ({
    name: `#${r.sequenceNumber}`,
    integrity: r.event.integrity.score,
    authority: r.event.authority.score,
    mttd: Math.min(r.event.mttdMs, 500),
  }));

  return (
    <div className="panel">
      <div className="panel-title">INTEGRITY & AUTHORITY TREND (last 20 events)</div>
      {chartData.length === 0 ? (
        <div className="loading">no events yet — process some requests to see trend</div>
      ) : (
        <ResponsiveContainer width="100%" height={160}>
          <LineChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
            <XAxis dataKey="name" tick={{ fill: '#2a6b7a', fontSize: 9 }} />
            <YAxis domain={[0, 100]} tick={{ fill: '#2a6b7a', fontSize: 9 }} />
            <Tooltip
              contentStyle={{ background: '#040f1e', border: '1px solid rgba(0,195,255,0.2)', fontSize: 11, color: '#7efcff' }}
              cursor={{ stroke: 'rgba(0,195,255,0.1)' }}
            />
            <ReferenceLine y={80} stroke="rgba(0,255,136,0.2)" strokeDasharray="3 3" />
            <ReferenceLine y={60} stroke="rgba(255,209,102,0.2)" strokeDasharray="3 3" />
            <ReferenceLine y={40} stroke="rgba(255,77,109,0.2)" strokeDasharray="3 3" />
            <Line type="monotone" dataKey="integrity" stroke="#00ff88" strokeWidth={1.5} dot={{ r: 2, fill: '#00ff88' }} name="INTEGRITY" />
            <Line type="monotone" dataKey="authority" stroke="#00c3ff" strokeWidth={1.5} dot={{ r: 2, fill: '#00c3ff' }} name="AUTHORITY" />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
