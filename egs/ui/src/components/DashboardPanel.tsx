import type { GovStateResponse } from '../lib/api.js';

interface Props {
  title: string;
  state: GovStateResponse | null;
  mode?: 'integrity' | 'authority' | 'event';
}

export function DashboardPanel({ title, state, mode }: Props) {
  if (mode === 'integrity') {
    const level = state?.integrity.level ?? '—';
    const score = state?.integrity.score ?? 0;
    const color = level === 'Critical' || level === 'Degraded' ? 'bad'
      : level === 'Limited' ? 'warn' : 'ok';
    return (
      <div className="panel">
        <div className="panel-title">{title}</div>
        <div className={`stat-value ${color}`} style={{ marginBottom: '8px' }}>{level}</div>
        <div className="bar-wrap">
          <div className="bar-label"><span>SCORE</span><span>{score}/100</span></div>
          <div className="bar-track">
            <div className={`bar-fill ${color}`} style={{ width: `${score}%` }} />
          </div>
        </div>
      </div>
    );
  }

  if (mode === 'authority') {
    const auth = state?.authority.authority ?? '—';
    const color = auth === 'decision-ready' ? 'ok' : auth === 'reference-only' ? 'warn' : 'bad';
    const label = auth === 'decision-ready' ? 'DECISION-READY'
      : auth === 'reference-only' ? 'REFERENCE-ONLY'
      : auth === 'invalid' ? 'INVALID' : '—';
    return (
      <div className="panel">
        <div className="panel-title">{title}</div>
        <div className={`stat-value sm ${color}`}>{label}</div>
        <div style={{ marginTop: '10px' }}>
          <div className="field-row">
            <div className="field-key">SCORE</div>
            <div className="field-val accent">{state?.authority.score ?? '—'}/100</div>
          </div>
          {state?.lastRouting && (
            <div className="field-row">
              <div className="field-key">LAST ROUTING</div>
              <div className="field-val" style={{ fontSize: '10px' }}>{state.lastRouting}</div>
            </div>
          )}
          {state?.blockedLayer && (
            <div className="field-row">
              <div className="field-key">BLOCKED LAYER</div>
              <div className="field-val warn">{state.blockedLayer.toUpperCase()}</div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Default — active event
  return (
    <div className="panel">
      <div className="panel-title">{title}</div>
      {state?.activeEvent ? (
        <div className="field-val bad" style={{ fontSize: '13px', marginBottom: '8px' }}>
          {state.activeEvent}
        </div>
      ) : (
        <div className="field-val ok" style={{ marginBottom: '8px' }}>NO ACTIVE EVENT</div>
      )}
      <div className="field-row">
        <div className="field-key">OPERATIONAL MODE</div>
        <div className={`field-val ${state?.operationalMode === 'CONTAINMENT' ? 'bad' : state?.operationalMode === 'LIMITED' ? 'warn' : 'ok'}`}>
          {state?.operationalMode ?? '—'}
        </div>
      </div>
      <div className="field-row">
        <div className="field-key">CONTEXT DRIFT</div>
        <div className={`field-val ${(state?.contextDriftPressurePct ?? 0) > 50 ? 'warn' : 'ok'}`}>
          {state?.contextDriftPressurePct ?? '—'}%
        </div>
      </div>
    </div>
  );
}
