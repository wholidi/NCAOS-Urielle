/**
 * @ncaos/core — Policy Loader
 *
 * Loads and validates PolicyProfile configurations.
 * Policies are the enterprise's responsibility to define;
 * the EGS's responsibility to enforce.
 *
 * Provides:
 * - DEFAULT_POLICY: a safe starting profile for new deployments
 * - loadPolicy(): validates a raw config object against the schema
 * - BUILTIN_PROFILES: reference profiles for common deployment tiers
 */

import { PolicyProfileSchema } from '../types/contracts.js';
import type { PolicyProfile } from '../types/contracts.js';

// ─────────────────────────────────────────────────────────
// BUILTIN PROFILES
// ─────────────────────────────────────────────────────────

const NOW = new Date().toISOString();

/**
 * Enterprise strict production profile.
 * Blocks on med and high severity; requires post-update watch.
 * Recommended for live enterprise deployments.
 */
export const ENTERPRISE_STRICT_PROFILE: PolicyProfile = {
  profileId: 'STRICT-PROD',
  label: 'Enterprise Strict (Production)',
  govLevel: 'ENTERPRISE_STRICT',
  integrityThresholds: {
    available: 80,
    limited: 60,
    degraded: 40,
  },
  continuityThresholds: {
    stable: 75,
    provisional: 55,
  },
  mttdSlaMs: {
    gate: 50,
    premise: 200,
    authority: 100,
    continuity: 500,
  },
  blockOnContainment: true,
  partnerId: 'GLOBAL_ENT_2026',
  createdAt: NOW,
  updatedAt: NOW,
};

/**
 * Critical strict profile — maximum enforcement.
 * Blocks on any anomaly regardless of severity.
 * Use for high-assurance environments only.
 */
export const CRITICAL_STRICT_PROFILE: PolicyProfile = {
  profileId: 'CRITICAL-STRICT',
  label: 'Critical Strict (Maximum Enforcement)',
  govLevel: 'CRITICAL_STRICT',
  integrityThresholds: {
    available: 90,
    limited: 70,
    degraded: 50,
  },
  continuityThresholds: {
    stable: 85,
    provisional: 65,
  },
  mttdSlaMs: {
    gate: 20,
    premise: 100,
    authority: 50,
    continuity: 250,
  },
  blockOnContainment: true,
  partnerId: 'GLOBAL_ENT_2026',
  createdAt: NOW,
  updatedAt: NOW,
};

/**
 * Pilot profile — observe and report mode.
 * Does not block; logs all events for analysis.
 * Use for initial deployment and evaluation phases.
 */
export const PILOT_PROFILE: PolicyProfile = {
  profileId: 'PILOT-OBS',
  label: 'Pilot (Observe & Report)',
  govLevel: 'PILOT',
  integrityThresholds: {
    available: 70,
    limited: 50,
    degraded: 30,
  },
  continuityThresholds: {
    stable: 65,
    provisional: 45,
  },
  mttdSlaMs: {
    gate: 200,
    premise: 500,
    authority: 300,
    continuity: 1000,
  },
  blockOnContainment: false,
  partnerId: 'GLOBAL_ENT_2026',
  createdAt: NOW,
  updatedAt: NOW,
};

export const DEFAULT_POLICY = ENTERPRISE_STRICT_PROFILE;

export const BUILTIN_PROFILES: Record<string, PolicyProfile> = {
  'STRICT-PROD': ENTERPRISE_STRICT_PROFILE,
  'CRITICAL-STRICT': CRITICAL_STRICT_PROFILE,
  'PILOT-OBS': PILOT_PROFILE,
};

// ─────────────────────────────────────────────────────────
// POLICY LOADER
// ─────────────────────────────────────────────────────────

/**
 * Validates and loads a PolicyProfile from raw config.
 * Throws a ZodError with detailed field errors if validation fails.
 *
 * Enterprise admins provide raw JSON; this function is the contract enforcement point.
 */
export function loadPolicy(raw: unknown): PolicyProfile {
  return PolicyProfileSchema.parse(raw);
}

/**
 * Loads a builtin profile by ID, falling back to the default.
 * Safe to call at startup — always returns a valid policy.
 */
export function loadBuiltinPolicy(profileId: string): PolicyProfile {
  return BUILTIN_PROFILES[profileId] ?? DEFAULT_POLICY;
}

/**
 * Validates that the policy's threshold floors are internally consistent.
 * Catches misconfiguration that Zod schema alone cannot detect.
 *
 * Rules:
 * - available > limited > degraded (integrity thresholds must be ordered)
 * - stable > provisional (continuity thresholds must be ordered)
 * - MTTD SLAs must all be > 0
 */
export function validatePolicyConsistency(
  policy: PolicyProfile,
): { valid: true } | { valid: false; errors: string[] } {
  const errors: string[] = [];
  const { available, limited, degraded } = policy.integrityThresholds;

  if (available <= limited)
    errors.push('integrityThresholds.available must be > limited');
  if (limited <= degraded)
    errors.push('integrityThresholds.limited must be > degraded');
  if (degraded < 0)
    errors.push('integrityThresholds.degraded must be >= 0');

  const { stable, provisional } = policy.continuityThresholds;
  if (stable <= provisional)
    errors.push('continuityThresholds.stable must be > provisional');

  const mttd = policy.mttdSlaMs;
  for (const [layer, ms] of Object.entries(mttd)) {
    if (ms <= 0) errors.push(`mttdSlaMs.${layer} must be > 0`);
  }

  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}
