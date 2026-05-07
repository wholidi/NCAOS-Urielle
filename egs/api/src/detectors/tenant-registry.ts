/**
 * @ncaos/api — Tenant Detector Registry
 *
 * Phase 04 upgrade: each tenant gets its own detector instances.
 *
 * In Phase 02/03, all requests shared a single set of detectors.
 * This means custom gate rules, premise registries, and authority audit logs
 * were shared across tenants — a tenant isolation breach.
 *
 * The TenantDetectorRegistry fixes this:
 * - One GateDetector per tenant (custom rule sets)
 * - One PremiseRegistry per tenant (workflow-scoped premises)
 * - One AuthorityAuditLog per tenant (isolated audit trail)
 * - One ContinuityDetector per tenant (independent score history)
 * - One DetectionRegistry per tenant (independent MTTD stats)
 *
 * Instances are created lazily on first request and held in memory.
 * Phase 05: persist custom rules to DB; reload on startup.
 */

import {
  GateDetector,
  DEFAULT_GATE_RULES,
  PremiseDetector,
  PremiseRegistry,
  AuthorityDetector,
  AuthorityAuditLog,
  ContinuityDetector,
  DetectionRegistry,
} from '@ncaos/detection';
import type { MttdStats } from '@ncaos/detection';
import type { PolicyProfile } from '@ncaos/core';

// ─────────────────────────────────────────────────────────
// TENANT DETECTOR SET
// ─────────────────────────────────────────────────────────

export interface TenantDetectorSet {
  partnerId: string;
  gate: GateDetector;
  premise: PremiseDetector;
  authority: AuthorityDetector;
  continuity: ContinuityDetector;
  mttdRegistry: DetectionRegistry;
  createdAt: string;
}

// ─────────────────────────────────────────────────────────
// REGISTRY
// ─────────────────────────────────────────────────────────

export class TenantDetectorRegistry {
  private readonly store = new Map<string, TenantDetectorSet>();
  private readonly policyProvider: (partnerId: string) => PolicyProfile;

  constructor(policyProvider: (partnerId: string) => PolicyProfile) {
    this.policyProvider = policyProvider;
  }

  /**
   * get() — returns the detector set for a tenant, creating it if needed.
   * Lazy initialization: first request for a tenant creates the set.
   */
  get(partnerId: string): TenantDetectorSet {
    if (!this.store.has(partnerId)) {
      this.store.set(partnerId, this._create(partnerId));
    }
    return this.store.get(partnerId)!;
  }

  /**
   * reset() — destroys and recreates the detector set for a tenant.
   * Called when a tenant's policy profile changes.
   */
  reset(partnerId: string): TenantDetectorSet {
    this.store.delete(partnerId);
    return this.get(partnerId);
  }

  /**
   * mttdStats() — returns MTTD stats for all layers for a tenant.
   */
  mttdStats(partnerId: string): MttdStats[] {
    return this.get(partnerId).mttdRegistry.allStats();
  }

  /**
   * isSlaHealthy() — returns true if all layers are within SLA for a tenant.
   */
  isSlaHealthy(partnerId: string): boolean {
    return this.get(partnerId).mttdRegistry.isSlaHealthy();
  }

  activeTenantCount(): number {
    return this.store.size;
  }

  private _create(partnerId: string): TenantDetectorSet {
    const policy = this.policyProvider(partnerId);
    const premiseRegistry = new PremiseRegistry();
    const auditLog = new AuthorityAuditLog();

    return {
      partnerId,
      gate: new GateDetector([...DEFAULT_GATE_RULES]),
      premise: new PremiseDetector(premiseRegistry),
      authority: new AuthorityDetector(auditLog),
      continuity: new ContinuityDetector(),
      mttdRegistry: new DetectionRegistry(policy),
      createdAt: new Date().toISOString(),
    };
  }
}
