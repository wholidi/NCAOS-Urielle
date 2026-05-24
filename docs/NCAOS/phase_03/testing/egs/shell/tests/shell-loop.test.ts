/**
 * Integration tests — ShellLoop (observe → judge → enforce)
 *
 * Tests the full loop end-to-end using the PILOT profile
 * (observe mode — never blocks, safe for integration testing).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ShellLoop } from '../src/shell-loop.js';
import { ENTERPRISE_STRICT_PROFILE, PILOT_PROFILE } from '@ncaos/core';

const TENANT = {
  partnerId: 'TEST_PARTNER' as const,
  instanceId: 'TEST_INST_001' as const,
  deployment: 'SANDBOX' as const,
};

const CLEAN_INPUT = {
  sourceId: 'src-clean',
  inputHash: 'abc123',
  inputFlags: [],
  claimedPremises: ['A', 'B'],
  validatedPremises: ['A', 'B'],
  contractVersion: '1.0',
  requestedAuthority: 'decision-ready' as const,
  policyGrantedAuthority: 'decision-ready' as const,
  overrideAttempted: false,
};

const THREAT_INPUT = {
  sourceId: 'src-threat',
  inputHash: 'bad123',
  inputFlags: ['INJECTION_PATTERN'],
  claimedPremises: ['A', 'B', 'C'],
  validatedPremises: ['A'],
  contractVersion: '1.0',
  requestedAuthority: 'decision-ready' as const,
  policyGrantedAuthority: 'reference-only' as const,
  overrideAttempted: false,
};

describe('ShellLoop — lifecycle', () => {
  it('starts and stops cleanly', () => {
    const shell = new ShellLoop({ tenant: TENANT, policy: PILOT_PROFILE });
    expect(shell.isRunning).toBe(false);
    shell.start();
    expect(shell.isRunning).toBe(true);
    shell.stop();
    expect(shell.isRunning).toBe(false);
  });

  it('returns FAIL_SAFE when not running', () => {
    const shell = new ShellLoop({ tenant: TENANT, policy: PILOT_PROFILE });
    const output = shell.process(CLEAN_INPUT);
    expect(output.verdict.action).toBe('FAIL_SAFE');
    expect(output.verdict.authority).toBe('invalid');
  });

  it('throws on invalid policy consistency', () => {
    const badPolicy = {
      ...PILOT_PROFILE,
      integrityThresholds: { available: 50, limited: 60, degraded: 40 },
    };
    expect(() => new ShellLoop({ tenant: TENANT, policy: badPolicy })).toThrow();
  });
});

describe('ShellLoop — clean request (PILOT)', () => {
  let shell: ShellLoop;

  beforeEach(() => {
    shell = new ShellLoop({ tenant: TENANT, policy: PILOT_PROFILE });
    shell.start();
  });

  afterEach(() => shell.stop());

  it('returns PASS for clean input', () => {
    const output = shell.process(CLEAN_INPUT);
    expect(output.verdict.action).toBe('PASS');
    expect(output.verdict.authority).toBe('decision-ready');
  });

  it('sets operationalMode to NORMAL on PASS', () => {
    const output = shell.process(CLEAN_INPUT);
    expect(output.state.operationalMode).toBe('NORMAL');
    expect(output.state.systemStatus).toBe('ENFORCING');
  });

  it('sets shellIntegrity=true and failSafeEnabled=true', () => {
    const output = shell.process(CLEAN_INPUT);
    expect(output.state.shellIntegrity).toBe(true);
    expect(output.state.failSafeEnabled).toBe(true);
  });

  it('no containment event emitted on PASS', () => {
    const output = shell.process(CLEAN_INPUT);
    expect(output.event).toBeNull();
  });

  it('produces a valid requestId', () => {
    const output = shell.process(CLEAN_INPUT);
    expect(output.verdict.requestId).toMatch(/^REQ-\d+$/);
  });

  it('governed output < raw exposure', () => {
    const output = shell.process(CLEAN_INPUT);
    expect(output.state.governedOutputPct).toBeLessThan(output.state.rawExposurePct);
  });
});

describe('ShellLoop — threat request (ENTERPRISE_STRICT)', () => {
  let shell: ShellLoop;

  beforeEach(() => {
    shell = new ShellLoop({ tenant: TENANT, policy: ENTERPRISE_STRICT_PROFILE });
    shell.start();
  });

  afterEach(() => shell.stop());

  it('returns BLOCK for high-severity threat', () => {
    const output = shell.process(THREAT_INPUT);
    expect(output.verdict.action).toBe('BLOCK');
    expect(output.verdict.authority).toBe('invalid');
  });

  it('sets operationalMode to CONTAINMENT on BLOCK', () => {
    const output = shell.process(THREAT_INPUT);
    expect(output.state.operationalMode).toBe('CONTAINMENT');
    expect(output.state.systemStatus).toBe('ENFORCING (STRICT)');
  });

  it('emits containment event on BLOCK', () => {
    const output = shell.process(THREAT_INPUT);
    expect(output.event).not.toBeNull();
    expect(output.event?.layer).toBe('gate');
  });

  it('sets integrity to Critical on high severity', () => {
    const output = shell.process(THREAT_INPUT);
    expect(output.state.integrity.level).toBe('Critical');
    expect(output.state.integrity.score).toBeLessThan(40);
  });

  it('includes routing hint on BLOCK', () => {
    const output = shell.process(THREAT_INPUT);
    expect(output.verdict.routing).toBeDefined();
    expect(output.verdict.routing?.hint).toBe('SOC / Security Queue');
  });
});

describe('ShellLoop — event emission', () => {
  it('emits shell:output event on each process() call', () => {
    return new Promise<void>((resolve) => {
      const shell = new ShellLoop({ tenant: TENANT, policy: PILOT_PROFILE });
      shell.start();
      shell.on('shell:output', (output) => {
        expect(output.verdict).toBeDefined();
        expect(output.state).toBeDefined();
        shell.stop();
        resolve();
      });
      shell.process(CLEAN_INPUT);
    });
  });
});
