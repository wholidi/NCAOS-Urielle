/**
 * @ncaos/shell — Watchdog
 *
 * The Watchdog monitors the ShellLoop and ensures it stays running.
 * If the shell crashes, the Watchdog restarts it within a bounded window.
 *
 * During the restart window, the API returns 503 GOVERNANCE_UNAVAILABLE.
 * This enforces the FAIL_SAFE invariant at the process level (ADR-002):
 * the protected core CANNOT serve output without an active governance shell.
 *
 * Phase 2: In-process watchdog (monitors ShellLoop instance).
 * Phase 3: Upgrade to OS-level process supervisor (systemd / PM2)
 *          for true cross-process isolation.
 *
 * Restart policy:
 * - Max 3 restarts in a 60-second window
 * - Exponential backoff: 500ms → 1000ms → 2000ms
 * - After max restarts: enter FAIL_SAFE permanently until manual intervention
 */

import { EventEmitter } from 'node:events';
import { ShellLoop, type ShellLoopConfig } from '../shell-loop.js';

export interface WatchdogConfig {
  shellConfig: ShellLoopConfig;
  maxRestarts?: number;         // Default: 3
  windowMs?: number;            // Default: 60_000 (60 seconds)
  baseBackoffMs?: number;       // Default: 500
}

export type WatchdogStatus =
  | 'RUNNING'
  | 'RESTARTING'
  | 'FAIL_SAFE'               // Max restarts exceeded
  | 'STOPPED';

export class Watchdog extends EventEmitter {
  private shell: ShellLoop | null = null;
  private readonly config: Required<WatchdogConfig>;
  private restartCount = 0;
  private windowStart = Date.now();
  private status: WatchdogStatus = 'STOPPED';

  constructor(config: WatchdogConfig) {
    super();
    this.config = {
      maxRestarts: config.maxRestarts ?? 3,
      windowMs: config.windowMs ?? 60_000,
      baseBackoffMs: config.baseBackoffMs ?? 500,
      shellConfig: config.shellConfig,
    };
  }

  get currentStatus(): WatchdogStatus {
    return this.status;
  }

  get shellLoop(): ShellLoop | null {
    return this.shell;
  }

  /**
   * Starts the shell and begins monitoring.
   */
  start(): void {
    if (this.status === 'RUNNING') return;
    this._spawnShell();
  }

  /**
   * Stops the watchdog and the shell cleanly.
   */
  stop(): void {
    this.status = 'STOPPED';
    this.shell?.stop();
    this.shell = null;
    this.emit('watchdog:stopped');
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private _spawnShell(): void {
    try {
      this.shell = new ShellLoop(this.config.shellConfig);

      this.shell.on('shell:fail-safe', (err: Error) => {
        console.error('[Watchdog] Shell FAIL_SAFE event:', err.message);
        this._handleCrash();
      });

      this.shell.on('shell:stopped', () => {
        if (this.status === 'RUNNING') {
          console.warn('[Watchdog] Shell stopped unexpectedly — restarting');
          this._handleCrash();
        }
      });

      // Forward shell output events to Watchdog listeners
      this.shell.on('shell:output', (output) => {
        this.emit('shell:output', output);
      });

      this.shell.start();
      this.status = 'RUNNING';
      this.emit('watchdog:running', this.shell);
      console.log('[Watchdog] Shell started');
    } catch (err) {
      console.error('[Watchdog] Shell spawn failed:', err);
      this._handleCrash();
    }
  }

  private _handleCrash(): void {
    this.shell = null;

    // Reset window counter if outside the window
    const now = Date.now();
    if (now - this.windowStart > this.config.windowMs) {
      this.restartCount = 0;
      this.windowStart = now;
    }

    if (this.restartCount >= this.config.maxRestarts) {
      console.error(
        `[Watchdog] Max restarts (${this.config.maxRestarts}) exceeded — entering FAIL_SAFE`,
      );
      this.status = 'FAIL_SAFE';
      this.emit('watchdog:fail-safe');
      return;
    }

    const backoffMs = this.config.baseBackoffMs * Math.pow(2, this.restartCount);
    this.restartCount++;
    this.status = 'RESTARTING';
    this.emit('watchdog:restarting', { attempt: this.restartCount, backoffMs });

    console.warn(
      `[Watchdog] Restarting shell in ${backoffMs}ms (attempt ${this.restartCount}/${this.config.maxRestarts})`,
    );

    setTimeout(() => {
      if (this.status === 'RESTARTING') {
        this._spawnShell();
      }
    }, backoffMs);
  }
}
