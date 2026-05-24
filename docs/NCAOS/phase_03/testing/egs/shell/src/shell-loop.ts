/**
 * @ncaos/shell — Shell Loop
 *
 * The ShellLoop wires the three stages into a single coherent process:
 *   Observer (tap) → Judge (judge) → Enforcer (enforce) → EnforcerOutput
 *
 * This is the primary entry point for the @ncaos/shell package.
 * The API layer calls ShellLoop.process() for each incoming request.
 *
 * Process isolation (ADR-002):
 * - ShellLoop runs as a separate Node.js process from the protected core
 * - The Watchdog (watchdog.ts) monitors this process and restarts it on crash
 * - During restart window, API returns 503 GOVERNANCE_UNAVAILABLE
 *
 * The ShellLoop is an EventEmitter — the API WebSocket layer subscribes to
 * 'shell:output' to push live GovState to the Admin Terminal.
 */

import { EventEmitter } from 'node:events';
import {
  DEFAULT_POLICY,
  loadBuiltinPolicy,
  validatePolicyConsistency,
  failSafeVerdict,
} from '@ncaos/core';
import type { GovState, PolicyProfile, TenantContext, Verdict } from '@ncaos/core';
import { Observer } from './observer/observer.js';
import { Judge } from './judge/judge.js';
import { Enforcer, type EnforcerOutput } from './enforcer/enforcer.js';
import type { ObservedRequest } from './observer/observer.js';

// ─────────────────────────────────────────────────────────
// SHELL LOOP
// ─────────────────────────────────────────────────────────

export interface ShellLoopConfig {
  tenant: TenantContext;
  policyProfileId?: string;
  policy?: PolicyProfile;           // Override for testing
}

export class ShellLoop extends EventEmitter {
  private readonly observer: Observer;
  private readonly judge: Judge;
  private readonly enforcer: Enforcer;
  private readonly policy: PolicyProfile;
  private running = false;

  constructor(config: ShellLoopConfig) {
    super();

    // Load and validate policy
    this.policy = config.policy
      ?? loadBuiltinPolicy(config.policyProfileId ?? 'STRICT-PROD');

    const consistency = validatePolicyConsistency(this.policy);
    if (!consistency.valid) {
      throw new Error(
        `[ShellLoop] Invalid policy profile: ${consistency.errors.join('; ')}`,
      );
    }

    this.observer = new Observer(config.tenant);
    this.judge = new Judge(this.policy);
    this.enforcer = new Enforcer(config.tenant, this.policy);

    // Wire: Enforcer output → ShellLoop event
    this.enforcer.on('enforcer:output', (output: EnforcerOutput) => {
      this.emit('shell:output', output);
    });

    // Wire: Observer error → FAIL_SAFE
    this.observer.on('observer:error', (err: Error) => {
      console.error('[ShellLoop] Observer error:', err.message);
      this.emit('shell:fail-safe', err);
    });
  }

  /**
   * start() — activates the Observer, begins accepting boundary signals.
   */
  start(): void {
    if (this.running) return;
    this.observer.start();
    this.running = true;
    console.log('[ShellLoop] Started — policy:', this.policy.profileId);
    this.emit('shell:started');
  }

  /**
   * stop() — deactivates the Observer, closes the boundary tap.
   * All subsequent process() calls will return FAIL_SAFE verdicts.
   */
  stop(): void {
    if (!this.running) return;
    this.observer.stop();
    this.running = false;
    console.log('[ShellLoop] Stopped');
    this.emit('shell:stopped');
  }

  get isRunning(): boolean {
    return this.running;
  }

  get currentState(): GovState | null {
    return this.enforcer.currentState;
  }

  get policyProfile(): PolicyProfile {
    return this.policy;
  }

  /**
   * process() — the primary entry point for the API layer.
   *
   * Takes a raw boundary signal, runs it through the full
   * observe → judge → enforce loop, and returns the EnforcerOutput.
   *
   * If the shell is stopped or any stage throws, returns FAIL_SAFE.
   */
  process(
    input: Omit<ObservedRequest, 'requestId' | 'evidenceHandle' | 'tenant' | 'observedAt'>,
  ): EnforcerOutput {
    // If shell is stopped, FAIL_SAFE immediately
    if (!this.running) {
      return this._failSafeOutput('Shell not running');
    }

    // Observe
    const observed = this.observer.tap(input);
    if (!observed) {
      return this._failSafeOutput('Observer returned null');
    }

    // Judge
    const judgment = this.judge.judge(observed);

    // Enforce
    return this.enforcer.enforce(judgment);
  }

  private _failSafeOutput(reason: string): EnforcerOutput {
    console.error(`[ShellLoop] FAIL_SAFE: ${reason}`);
    const rid = `REQ-000000` as `REQ-${string}`;
    return {
      verdict: failSafeVerdict(rid, this.policy.profileId),
      event: null,
      state: {
        tenant: { partnerId: 'UNKNOWN' as any, instanceId: 'UNKNOWN' as any, deployment: 'SANDBOX' },
        systemStatus: 'FAIL_SAFE',
        operationalMode: 'CONTAINMENT',
        shellIntegrity: false,
        failSafeEnabled: true,
        integrity: { level: 'Critical', score: 0 },
        authority: { authority: 'invalid', score: 0 },
        rawExposurePct: 100,
        governedOutputPct: 0,
        coreIsolationPct: 0,
        contextDriftPressurePct: 100,
        latencyOverheadMs: 0,
        updateState: 'UNSTABLE',
        continuityScore: 0,
        changeWindowActive: false,
        equivalenceTests: { passed: 0, total: 0 },
        activeEvent: 'FAIL_SAFE / CRITICAL',
        updatedAt: new Date().toISOString(),
      },
    };
  }
}
