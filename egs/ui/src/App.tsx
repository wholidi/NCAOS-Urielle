/**
 * @ncaos/ui — Admin Terminal
 *
 * Production React replacement for NCAOS_UI_final.html
 *
 * Aesthetic: cyberpunk terminal — dark, monospaced, cyan/red accent palette.
 * Matches the original PoC's visual language while adding live data binding.
 *
 * Role-based views:
 *   SOC Operator    — event log, routing, MTTD, containment status
 *   Architect       — shell decoupling, detection layers, MTTD SLA
 *   Auditor         — evidence handles, sequence analysis, audit trail
 *   Executive       — RAW vs GOVERNED, risk containment, system status
 */

import { useState, useEffect, useCallback } from 'react';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { api, createStateStream } from './lib/api.js';
import type { GovStateResponse, HealthResponse } from './lib/api.js';
import { DashboardPanel } from './components/DashboardPanel.js';
import { EventLog } from './components/EventLog.js';
// import { SequencePanel } from './components/SequencePanel.js';
// import { MttdPanel } from './components/MttdPanel.js';
// import { PolicyPanel } from './components/PolicyPanel.js';
// import { ContainmentChart } from './components/ContainmentChart.js';
import { MttdPanel, SequencePanel, PolicyPanel, ContainmentChart } from './components/EventLog.js';

const qc = new QueryClient({
  defaultOptions: { queries: { retry: 2, staleTime: 5_000, refetchInterval: 10_000 } },
});

type Role = 'SOC' | 'ARCHITECT' | 'AUDITOR' | 'EXECUTIVE';

const PARTNER_ID = 'GLOBAL_ENT_2026';

// ─────────────────────────────────────────────────────────
// STYLES (injected as CSS string — no Tailwind dependency)
// ─────────────────────────────────────────────────────────

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

  :root {
    --bg: #020812;
    --bg2: #040f1e;
    --bg3: #061525;
    --panel: rgba(0,195,255,0.04);
    --border: rgba(0,195,255,0.15);
    --border-hi: rgba(0,195,255,0.4);
    --fg: #7efcff;
    --fg2: #4ab8cc;
    --fg3: #2a6b7a;
    --accent: #00c3ff;
    --accent2: #35d3ff;
    --ok: #00ff88;
    --ok-dim: #00ff8844;
    --warn: #ffd166;
    --warn-dim: #ffd16633;
    --bad: #ff4d6d;
    --bad-dim: #ff4d6d33;
    --mono: 'Share Tech Mono', monospace;
    --head: 'Rajdhani', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--fg);
    font-family: var(--mono);
    font-size: 13px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      transparent 0px, transparent 1px,
      rgba(0,195,255,0.02) 2px, rgba(0,195,255,0.02) 3px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* Grid background */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,195,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,195,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  #root { position: relative; z-index: 1; }

  .app { max-width: 1400px; margin: 0 auto; padding: 12px 16px; }

  /* ── TOPBAR ── */
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 12px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }

  .topbar-left { display: flex; align-items: center; gap: 16px; }

  .logo {
    font-family: var(--head);
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--accent2);
    letter-spacing: 2px;
    text-shadow: 0 0 20px var(--accent);
  }

  .logo span { color: var(--fg); }

  .status-pill {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border: 1px solid var(--border-hi);
    border-radius: 2px;
    font-size: 11px;
    letter-spacing: 1px;
    background: var(--panel);
  }

  .pulse {
    width: 6px; height: 6px;
    border-radius: 50%;
    animation: pulse 1.6s ease-in-out infinite;
  }
  .pulse.ok { background: var(--ok); box-shadow: 0 0 8px var(--ok); }
  .pulse.bad { background: var(--bad); box-shadow: 0 0 8px var(--bad); }
  .pulse.warn { background: var(--warn); box-shadow: 0 0 8px var(--warn); }

  @keyframes pulse {
    0%,100% { opacity: 1; transform: scale(1); }
    50%      { opacity: 0.4; transform: scale(0.8); }
  }

  .meta-badges { display: flex; gap: 8px; flex-wrap: wrap; }

  .meta-badge {
    padding: 3px 8px;
    border: 1px solid var(--border);
    font-size: 10px;
    color: var(--fg2);
    letter-spacing: 0.5px;
    background: var(--panel);
  }

  .meta-badge b { color: var(--fg); }

  /* ── ROLE TABS ── */
  .role-tabs {
    display: flex;
    gap: 2px;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }

  .role-tab {
    padding: 7px 18px;
    border: none;
    background: transparent;
    color: var(--fg3);
    font-family: var(--head);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 1px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
  }

  .role-tab:hover { color: var(--fg2); }
  .role-tab.active {
    color: var(--accent2);
    border-bottom-color: var(--accent);
    text-shadow: 0 0 12px var(--accent);
  }

  /* ── GRID LAYOUTS ── */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }
  .grid-12 { display: grid; grid-template-columns: 1fr 2fr; gap: 10px; }
  .grid-21 { display: grid; grid-template-columns: 2fr 1fr; gap: 10px; }
  .col-span-2 { grid-column: span 2; }
  .col-span-3 { grid-column: span 3; }

  /* ── PANEL ── */
  .panel {
    border: 1px solid var(--border);
    background: var(--panel);
    padding: 12px 14px;
    position: relative;
    overflow: hidden;
  }

  .panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.4;
  }

  .panel-title {
    font-family: var(--head);
    font-size: 11px;
    font-weight: 600;
    color: var(--fg2);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .panel-title::before {
    content: '▸';
    color: var(--accent);
    font-size: 10px;
  }

  /* ── STAT BLOCK ── */
  .stat { display: flex; flex-direction: column; gap: 2px; }
  .stat-label { font-size: 10px; color: var(--fg3); letter-spacing: 1px; text-transform: uppercase; }
  .stat-value { font-size: 22px; font-family: var(--head); font-weight: 700; color: var(--accent2); }
  .stat-value.ok { color: var(--ok); }
  .stat-value.warn { color: var(--warn); }
  .stat-value.bad { color: var(--bad); }
  .stat-value.sm { font-size: 14px; }

  /* ── FIELD ROW ── */
  .field-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 0;
    border-bottom: 1px solid rgba(0,195,255,0.06);
    gap: 8px;
  }
  .field-row:last-child { border-bottom: none; }
  .field-key { font-size: 10px; color: var(--fg3); letter-spacing: 0.5px; flex-shrink: 0; }
  .field-val { font-size: 12px; color: var(--fg); text-align: right; word-break: break-all; }
  .field-val.ok { color: var(--ok); }
  .field-val.warn { color: var(--warn); }
  .field-val.bad { color: var(--bad); }
  .field-val.accent { color: var(--accent2); }

  /* ── BAR ── */
  .bar-wrap { display: flex; flex-direction: column; gap: 4px; margin: 6px 0; }
  .bar-label { display: flex; justify-content: space-between; font-size: 10px; color: var(--fg3); }
  .bar-track { height: 6px; background: rgba(0,195,255,0.08); border-radius: 1px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 1px; transition: width 0.6s ease; }
  .bar-fill.ok { background: var(--ok); box-shadow: 0 0 8px var(--ok-dim); }
  .bar-fill.warn { background: var(--warn); box-shadow: 0 0 8px var(--warn-dim); }
  .bar-fill.bad { background: var(--bad); box-shadow: 0 0 8px var(--bad-dim); }
  .bar-fill.accent { background: var(--accent); box-shadow: 0 0 8px rgba(0,195,255,0.3); }

  /* ── EVENT TABLE ── */
  .event-table { width: 100%; border-collapse: collapse; font-size: 11px; }
  .event-table th {
    text-align: left; padding: 5px 8px;
    color: var(--fg3); font-size: 10px; letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
    font-weight: normal;
  }
  .event-table td { padding: 5px 8px; border-bottom: 1px solid rgba(0,195,255,0.04); }
  .event-table tr:hover td { background: rgba(0,195,255,0.03); }

  .sev-badge {
    padding: 1px 6px; font-size: 10px; border-radius: 1px;
    font-family: var(--head); font-weight: 600; letter-spacing: 1px;
  }
  .sev-high { background: var(--bad-dim); color: var(--bad); border: 1px solid var(--bad); }
  .sev-med  { background: var(--warn-dim); color: var(--warn); border: 1px solid var(--warn); }
  .sev-low  { background: var(--ok-dim); color: var(--ok); border: 1px solid var(--ok); }

  .action-badge { padding: 1px 6px; font-size: 10px; border-radius: 1px; font-family: var(--head); font-weight: 600; }
  .action-BLOCK     { background: var(--bad-dim); color: var(--bad); }
  .action-DOWNGRADE { background: var(--warn-dim); color: var(--warn); }
  .action-PASS      { background: var(--ok-dim); color: var(--ok); }
  .action-FAIL_SAFE { background: #ff4d6d22; color: var(--bad); }

  /* ── SEQUENCE ── */
  .seq-summary {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin-top: 8px;
  }

  .pattern-badge {
    display: inline-block;
    padding: 3px 10px;
    font-family: var(--head);
    font-weight: 700;
    font-size: 13px;
    letter-spacing: 1px;
    border-radius: 2px;
  }
  .pattern-STABLE    { background: var(--ok-dim); color: var(--ok); }
  .pattern-CONTAINED { background: var(--warn-dim); color: var(--warn); }
  .pattern-DEGRADING { background: var(--bad-dim); color: var(--bad); }
  .pattern-VOLATILE  { background: #9b59b622; color: #c39bd3; }
  .pattern-UNKNOWN   { background: rgba(0,195,255,0.1); color: var(--fg2); }

  /* ── LOADING / ERROR ── */
  .loading { color: var(--fg3); font-size: 11px; padding: 16px; text-align: center; }
  .error-msg { color: var(--bad); font-size: 11px; padding: 8px; }

  /* ── SCROLLBAR ── */
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: 2px; }

  /* ── MB SPACING ── */
  .mb8 { margin-bottom: 8px; }
  .mb12 { margin-bottom: 12px; }

  .timestamp { color: var(--fg3); font-size: 10px; }

  .evidence-handle {
    color: var(--accent2);
    font-size: 10px;
    word-break: break-all;
    cursor: pointer;
  }
  .evidence-handle:hover { color: var(--fg); }

  .partner-select {
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--fg);
    font-family: var(--mono);
    font-size: 12px;
    padding: 4px 8px;
    outline: none;
  }
`;

// ─────────────────────────────────────────────────────────
// ROOT APP
// ─────────────────────────────────────────────────────────

function AdminTerminal() {
  const [role, setRole] = useState<Role>('SOC');
  const [partnerId, setPartnerId] = useState(PARTNER_ID);
  const [liveState, setLiveState] = useState<GovStateResponse | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  // Live WebSocket state stream
  useEffect(() => {
    const disconnect = createStateStream(
      (state) => { setLiveState(state); setWsConnected(true); },
      () => setWsConnected(false),
      () => setWsConnected(true),
    );
    return disconnect;
  }, []);

  const { data: health } = useQuery({
    queryKey: ['health', partnerId],
    queryFn: () => api.health(partnerId),
    refetchInterval: 5_000,
  });

  const opMode = liveState?.operationalMode ?? 'NORMAL';
  const statusColor = opMode === 'CONTAINMENT' ? 'bad' : opMode === 'LIMITED' ? 'warn' : 'ok';
//const statusText = liveState?.systemStatus ?? 'CONNECTING...';
    const statusText = wsConnected
  ? (liveState?.systemStatus ?? 'CONNECTED')
  : 'CONNECTING...';

  return (
    <div className="app">
      {/* Topbar */}
      <div className="topbar">
        <div className="topbar-left">
          <div className="logo">NCAOS <span>//</span> EGS</div>
          <div className={`status-pill`}>
            <div className={`pulse ${statusColor}`} />
            <span style={{ color: `var(--${statusColor})`, letterSpacing: '1px' }}>
              {statusText}
            </span>
          </div>
          {!wsConnected && (
            <div className="status-pill">
              <div className="pulse warn" />
              <span style={{ color: 'var(--warn)' }}>WS DISCONNECTED</span>
            </div>
          )}
        </div>

        <div className="meta-badges">
          <div className="meta-badge">
            <b>PARTNER</b> {partnerId}
          </div>
          <div className="meta-badge">
            <b>POLICY</b> {health?.policy ?? '—'}
          </div>
          <div className="meta-badge">
            <b>TENANTS</b> {health?.activeTenants ?? '—'}
          </div>
          <div className="meta-badge">
            <b>EVENTS</b> {health?.totalEvents ?? '—'}
          </div>
          <div className="meta-badge">
            <b>SLA</b>{' '}
            <span style={{ color: health?.slaHealthy ? 'var(--ok)' : 'var(--bad)' }}>
              {health?.slaHealthy === undefined ? '—' : health.slaHealthy ? 'HEALTHY' : 'BREACH'}
            </span>
          </div>
          <select
            className="partner-select"
            value={partnerId}
            onChange={e => setPartnerId(e.target.value)}
          >
            <option value="GLOBAL_ENT_2026">GLOBAL_ENT_2026</option>
            <option value="TEST">TEST</option>
          </select>
        </div>
      </div>

      {/* Role tabs */}
      <div className="role-tabs">
        {(['SOC', 'ARCHITECT', 'AUDITOR', 'EXECUTIVE'] as Role[]).map(r => (
          <button
            key={r}
            className={`role-tab ${role === r ? 'active' : ''}`}
            onClick={() => setRole(r)}
          >
            {r === 'SOC' ? '[ SOC OPERATOR ]'
              : r === 'ARCHITECT' ? '[ ARCHITECT ]'
              : r === 'AUDITOR' ? '[ AUDITOR ]'
              : '[ EXECUTIVE ]'}
          </button>
        ))}
      </div>

      {/* Role views */}
      {role === 'SOC'       && <SocView partnerId={partnerId} state={liveState} />}
      {role === 'ARCHITECT' && <ArchitectView partnerId={partnerId} state={liveState} />}
      {role === 'AUDITOR'   && <AuditorView partnerId={partnerId} />}
      {role === 'EXECUTIVE' && <ExecutiveView partnerId={partnerId} state={liveState} health={health} />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// SOC VIEW
// ─────────────────────────────────────────────────────────

function SocView({ partnerId, state }: { partnerId: string; state: GovStateResponse | null }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="grid-3">
        <DashboardPanel title="ACTIVE EVENT" state={state} />
        <DashboardPanel title="INTEGRITY" state={state} mode="integrity" />
        <DashboardPanel title="OUTPUT AUTHORITY" state={state} mode="authority" />
      </div>
      <div className="grid-21">
        <EventLog partnerId={partnerId} />
        <MttdPanel partnerId={partnerId} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// ARCHITECT VIEW
// ─────────────────────────────────────────────────────────

function ArchitectView({ partnerId, state }: { partnerId: string; state: GovStateResponse | null }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="grid-2">
        <div className="panel">
          <div className="panel-title">SHELL INTEGRITY</div>
          <div className="grid-2">
            <div className="stat">
              <div className="stat-label">Shell Status</div>
              <div className={`stat-value sm ${state?.shellIntegrity ? 'ok' : 'bad'}`}>
                {state?.shellIntegrity ? 'OPERATIONAL' : 'FAULT'}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Fail-Safe</div>
              <div className={`stat-value sm ${state?.failSafeEnabled ? 'ok' : 'bad'}`}>
                {state?.failSafeEnabled ? 'ENABLED' : 'DISABLED'}
              </div>
            </div>
            <div className="stat">
              <div className="stat-label">Core Isolation</div>
              <div className="stat-value sm accent">{state?.coreIsolationPct ?? '—'}%</div>
            </div>
            <div className="stat">
              <div className="stat-label">Latency Overhead</div>
              <div className="stat-value sm">{state?.latencyOverheadMs ?? '—'}ms</div>
            </div>
          </div>
        </div>
        <div className="panel">
          <div className="panel-title">CONTINUITY STATE</div>
          <div className="field-row">
            <div className="field-key">UPDATE_STATE</div>
            <div className={`field-val ${state?.updateState === 'STABLE' ? 'ok' : state?.updateState === 'UNSTABLE' ? 'bad' : 'warn'}`}>
              {state?.updateState ?? '—'}
            </div>
          </div>
          <div className="field-row">
            <div className="field-key">CONTINUITY_SCORE</div>
            <div className="field-val accent">{state?.continuityScore ?? '—'}/100</div>
          </div>
          <div className="field-row">
            <div className="field-key">CHANGE_WINDOW</div>
            <div className={`field-val ${state?.changeWindowActive ? 'warn' : 'ok'}`}>
              {state?.changeWindowActive ? 'ACTIVE' : 'CLOSED'}
            </div>
          </div>
          <div className="field-row">
            <div className="field-key">EQUIV TESTS</div>
            <div className="field-val">
              {state?.equivalenceTests
                ? `${state.equivalenceTests.passed}/${state.equivalenceTests.total} PASS`
                : '—'}
            </div>
          </div>
        </div>
      </div>
      <MttdPanel partnerId={partnerId} expanded />
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// AUDITOR VIEW
// ─────────────────────────────────────────────────────────

function AuditorView({ partnerId }: { partnerId: string }) {
  const [selectedSequence, setSelectedSequence] = useState('');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="grid-12">
        <EventLog partnerId={partnerId} onSequenceSelect={setSelectedSequence} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div className="panel">
            <div className="panel-title">EVIDENCE STATS</div>
            <EventStatsBlock partnerId={partnerId} />
          </div>
          <PolicyPanel partnerId={partnerId} />
        </div>
      </div>
      {selectedSequence && (
        <SequencePanel partnerId={partnerId} sequenceId={selectedSequence} />
      )}
    </div>
  );
}

function EventStatsBlock({ partnerId }: { partnerId: string }) {
  const { data } = useQuery({
    queryKey: ['event-stats', partnerId],
    queryFn: () => api.eventStats(partnerId),
    refetchInterval: 10_000,
  });
  if (!data) return <div className="loading">loading...</div>;
  return (
    <>
      <div className="field-row"><div className="field-key">TOTAL EVENTS</div><div className="field-val accent">{data.total}</div></div>
      <div className="field-row"><div className="field-key">ACTIVE SEQUENCES</div><div className="field-val accent">{data.activeSequences}</div></div>
      {Object.entries(data.byLayer).map(([k, v]) => (
        <div key={k} className="field-row"><div className="field-key">LAYER/{k.toUpperCase()}</div><div className="field-val">{v}</div></div>
      ))}
      {Object.entries(data.byAction).map(([k, v]) => (
        <div key={k} className="field-row">
          <div className="field-key">ACTION/{k}</div>
          <div className={`field-val action-${k}`}>{v}</div>
        </div>
      ))}
    </>
  );
}

// ─────────────────────────────────────────────────────────
// EXECUTIVE VIEW
// ─────────────────────────────────────────────────────────

function ExecutiveView({ partnerId, state, health }: {
  partnerId: string;
  state: GovStateResponse | null;
  health: HealthResponse | undefined;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div className="grid-3">
        <div className="panel">
          <div className="panel-title">SYSTEM STATUS</div>
          <div className="stat" style={{ marginBottom: '12px' }}>
            <div className="stat-label">OPERATIONAL MODE</div>
            <div className={`stat-value ${state?.operationalMode === 'CONTAINMENT' ? 'bad' : state?.operationalMode === 'LIMITED' ? 'warn' : 'ok'}`}>
              {state?.operationalMode ?? '—'}
            </div>
          </div>
          <div className="field-row">
            <div className="field-key">WATCHDOG</div>
            <div className={`field-val ${health?.watchdog === 'RUNNING' ? 'ok' : 'bad'}`}>{health?.watchdog ?? '—'}</div>
          </div>
          <div className="field-row">
            <div className="field-key">SHELL</div>
            <div className={`field-val ${health?.shell ? 'ok' : 'bad'}`}>{health?.shell ? 'ONLINE' : 'OFFLINE'}</div>
          </div>
          <div className="field-row">
            <div className="field-key">SLA HEALTH</div>
            <div className={`field-val ${health?.slaHealthy ? 'ok' : 'bad'}`}>{health?.slaHealthy ? 'WITHIN SLA' : 'BREACH DETECTED'}</div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-title">INTEGRITY</div>
          <div className="stat" style={{ marginBottom: '12px' }}>
            <div className="stat-label">LEVEL</div>
            <div className={`stat-value ${state?.integrity.level === 'Critical' ? 'bad' : state?.integrity.level === 'Degraded' ? 'bad' : state?.integrity.level === 'Limited' ? 'warn' : 'ok'}`}>
              {state?.integrity.level ?? '—'}
            </div>
          </div>
          <div className="bar-wrap">
            <div className="bar-label"><span>SCORE</span><span>{state?.integrity.score ?? '—'}/100</span></div>
            <div className="bar-track">
              <div className={`bar-fill ${(state?.integrity.score ?? 0) >= 80 ? 'ok' : (state?.integrity.score ?? 0) >= 60 ? 'warn' : 'bad'}`}
                style={{ width: `${state?.integrity.score ?? 0}%` }} />
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-title">CONTAINMENT EFFECT</div>
          <div className="bar-wrap">
            <div className="bar-label"><span>RAW EXPOSURE</span><span>{state?.rawExposurePct ?? '—'}%</span></div>
            <div className="bar-track">
              <div className="bar-fill bad" style={{ width: `${state?.rawExposurePct ?? 0}%` }} />
            </div>
          </div>
          <div className="bar-wrap">
            <div className="bar-label"><span>GOVERNED OUTPUT</span><span>{state?.governedOutputPct ?? '—'}%</span></div>
            <div className="bar-track">
              <div className="bar-fill ok" style={{ width: `${state?.governedOutputPct ?? 0}%` }} />
            </div>
          </div>
          <div className="bar-wrap">
            <div className="bar-label"><span>CORE ISOLATION</span><span>{state?.coreIsolationPct ?? '—'}%</span></div>
            <div className="bar-track">
              <div className="bar-fill accent" style={{ width: `${state?.coreIsolationPct ?? 0}%` }} />
            </div>
          </div>
          <div className="bar-wrap">
            <div className="bar-label"><span>DRIFT PRESSURE</span><span>{state?.contextDriftPressurePct ?? '—'}%</span></div>
            <div className="bar-track">
              <div className={`bar-fill ${(state?.contextDriftPressurePct ?? 0) > 50 ? 'bad' : 'warn'}`}
                style={{ width: `${state?.contextDriftPressurePct ?? 0}%` }} />
            </div>
          </div>
        </div>
      </div>

      <ContainmentChart partnerId={partnerId} />
    </div>
  );
}

// ─────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <style>{CSS}</style>
      <AdminTerminal />
    </QueryClientProvider>
  );
}
