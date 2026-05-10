/**
 * @ncaos/shell — Observer Module
 *
 * The Observer is the first stage of the observe → judge → enforce loop.
 * It sits at the I/O boundary and watches all traffic entering and leaving
 * the protected core. It never modifies traffic — it only observes and emits.
 *
 * Design invariants:
 * - Observer runs in a SEPARATE PROCESS from the protected core (ADR-002)
 * - Any Observer failure triggers FAIL_SAFE — it does not silently pass traffic
 * - Observer emits ObservedRequest objects; it does NOT make verdicts
 * - No internal model state is accessed — boundary signals only
 *
 * In Phase 2 this is implemented as an in-process event emitter.
 * Phase 3 (Detection Layer) wires real I/O tap via IPC/Unix socket.
 */

import { EventEmitter } from 'node:events';
import type { TenantContext } from '@ncaos/core';
import { generateRequestId, generateEvidenceHandle, nowIso } from '@ncaos/core';

// ─────────────────────────────────────────────────────────
// OBSERVED REQUEST
// The raw observation emitted by the Observer before any judgment.
// ─────────────────────────────────────────────────────────

export interface ObservedRequest {
  requestId: string;
  evidenceHandle: string;
  tenant: TenantContext;
  workflowId?: string;

  // Boundary signals — what the Observer can see at the I/O perimeter
  sourceId: string;
  inputHash: string;
  inputFlags: string[];               // e.g. ['RATE_EXCEEDED', 'UNRECOGNIZED_SOURCE']

  // Premise signals — what the request claims about its context
  claimedPremises: string[];
  validatedPremises: string[];
  contractVersion: string;

  // Authority signals — what authority level the request is claiming
  requestedAuthority: 'decision-ready' | 'reference-only';
  policyGrantedAuthority: 'decision-ready' | 'reference-only' | 'invalid';
  overrideAttempted: boolean;

  // Continuity signals — post-update watch (populated when changeWindowActive)
  updateId?: string;
  equivalenceTestResults?: Array<{ testId: string; passed: boolean }>;
  continuityScore?: number;

  // Temporal
  observedAt: string;                 // ISO 8601
}

// ─────────────────────────────────────────────────────────
// OBSERVER EVENTS
// ─────────────────────────────────────────────────────────

export interface ObserverEvents {
  'request:observed': (req: ObservedRequest) => void;
  'observer:error': (err: Error) => void;
  'observer:started': () => void;
  'observer:stopped': () => void;
}

// ─────────────────────────────────────────────────────────
// OBSERVER CLASS
// ─────────────────────────────────────────────────────────

/**
 * The Observer watches the I/O boundary and emits ObservedRequests.
 *
 * Phase 2: Simulated via tap() — the shell calls tap() to inject an
 *          observation (e.g. from a test harness or API gateway middleware).
 * Phase 3: Replace tap() internals with real IPC socket listener
 *          receiving signals from the gateway process.
 */
export class Observer extends EventEmitter {
  private readonly tenant: TenantContext;
  private running = false;
  private requestCounter = 0;

  constructor(tenant: TenantContext) {
    super();
    this.tenant = tenant;
  }

  /**
   * Start the Observer — begin accepting boundary signals.
   * In Phase 3 this opens the IPC socket / kernel hook.
   */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.emit('observer:started');
  }

  /**
   * Stop the Observer — close the boundary tap.
   * Triggers FAIL_SAFE on the shell side (no more observations = deny).
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;
    this.emit('observer:stopped');
  }

  get isRunning(): boolean {
    return this.running;
  }

  /**
   * tap() — inject a boundary signal into the Observer.
   *
   * Phase 2: Called directly by the API middleware or test harness.
   * Phase 3: Called internally by the IPC socket listener.
   *
   * If the Observer is stopped, emits 'observer:error' and returns null.
   * The caller must treat null as a FAIL_SAFE trigger.
   */
  tap(input: Omit<ObservedRequest, 'requestId' | 'evidenceHandle' | 'tenant' | 'observedAt'>): ObservedRequest | null {
    if (!this.running) {
      this.emit('observer:error', new Error('Observer is stopped — FAIL_SAFE triggered'));
      return null;
    }

    try {
      this.requestCounter++;
      const observedAt = nowIso();
      const requestId = generateRequestId(this.requestCounter);
      const evidenceHandle = generateEvidenceHandle(requestId, observedAt);

      const observed: ObservedRequest = {
        requestId,
        evidenceHandle,
        tenant: this.tenant,
        observedAt,
        ...input,
      };

      this.emit('request:observed', observed);
      return observed;
    } catch (err) {
      this.emit('observer:error', err instanceof Error ? err : new Error(String(err)));
      return null;
    }
  }
}
