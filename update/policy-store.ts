/**
 * @ncaos/api — Policy Store
 *
 * Phase 04 upgrade: policy profile CRUD with tenant scoping.
 *
 * In Phase 02, the policy was hardcoded to ENTERPRISE_STRICT_PROFILE.
 * In Phase 04, each tenant can have its own active policy profile,
 * and admins can update it via POST /v1/policy.
 *
 * Provides:
 * - Per-tenant active policy (defaults to ENTERPRISE_STRICT on first access)
 * - Policy update with validation (validatePolicyConsistency check)
 * - Policy history (last 10 versions per tenant for audit)
 * - Change notification (emits 'policy:changed' for shell/detector reset)
 *
 * Phase 05: persist to PostgreSQL with full audit trail.
 */

import { EventEmitter } from 'node:events';
import {
  ENTERPRISE_STRICT_PROFILE,
  loadPolicy,
  validatePolicyConsistency,
} from '@ncaos/core';
import type { PolicyProfile } from '@ncaos/core';

// ─────────────────────────────────────────────────────────
// POLICY HISTORY ENTRY
// ─────────────────────────────────────────────────────────

export interface PolicyHistoryEntry {
  policy: PolicyProfile;
  activatedAt: string;
  activatedBy: string;          // e.g. 'ADMIN_API' or user ID
  reason?: string;
}

// ─────────────────────────────────────────────────────────
// POLICY STORE
// ─────────────────────────────────────────────────────────

const MAX_HISTORY = 10;

export class PolicyStore extends EventEmitter {
  private readonly active = new Map<string, PolicyProfile>();
  private readonly history = new Map<string, PolicyHistoryEntry[]>();

  /**
   * getActive() — returns the active policy for a tenant.
   * Defaults to ENTERPRISE_STRICT if no policy has been set.
   */
  getActive(partnerId: string): PolicyProfile {
    return this.active.get(partnerId) ?? ENTERPRISE_STRICT_PROFILE;
  }

  /**
   * setActive() — updates the active policy for a tenant.
   * Validates the policy before accepting it.
   * Emits 'policy:changed' so the shell and detectors can reset.
   *
   * Returns { success: true } or { success: false, errors: string[] }.
   */
  setActive(
    partnerId: string,
    rawPolicy: unknown,
    activatedBy = 'ADMIN_API',
    reason?: string,
  ): { success: true; policy: PolicyProfile } | { success: false; errors: string[] } {
    // Parse + validate schema
    let policy: PolicyProfile;
    try {
      policy = loadPolicy(rawPolicy);
    } catch (err) {
      return { success: false, errors: ['Invalid policy schema: ' + String(err)] };
    }

    // Validate internal consistency
    const consistency = validatePolicyConsistency(policy);
    if (!consistency.valid) {
      return { success: false, errors: consistency.errors };
    }

    // Store history
    const prev = this.active.get(partnerId);
    if (prev) {
      const hist = this.history.get(partnerId) ?? [];
      hist.unshift({ policy: prev, activatedAt: new Date().toISOString(), activatedBy, reason });
      if (hist.length > MAX_HISTORY) hist.pop();
      this.history.set(partnerId, hist);
    }

    // Activate
    this.active.set(partnerId, policy);
    this.emit('policy:changed', { partnerId, policy });

    return { success: true, policy };
  }

  /**
   * getHistory() — returns the last N policy versions for a tenant.
   */
  getHistory(partnerId: string): PolicyHistoryEntry[] {
    return [...(this.history.get(partnerId) ?? [])];
  }

  /**
   * reset() — reverts to ENTERPRISE_STRICT for a tenant.
   */
  reset(partnerId: string, activatedBy = 'ADMIN_API'): void {
    this.setActive(partnerId, ENTERPRISE_STRICT_PROFILE, activatedBy, 'Manual reset to default');
  }
}
