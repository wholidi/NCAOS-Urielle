/**
 * @ncaos/core — Routing Module
 *
 * Determines triage routing decisions for containment events.
 * Ported and typed from routeHint() in NCAOS_UI_final.html.
 *
 * Routing is structural — it directs events to the correct response queue
 * based on which containment layer triggered. Does not expose internal logic.
 */

import type { ContainmentLayer, ImpactScope, RoutingDecision } from '../types/contracts.js';

/**
 * Routing table: maps each ContainmentLayer to its canonical routing decision.
 * Recommended actions are structural labels — they guide the response team
 * without inferring root cause from the protected core.
 *
 * PoC origin: routeHint() in NCAOS_UI_final.html
 */
const ROUTING_TABLE: Record<ContainmentLayer, RoutingDecision> = {
  gate: {
    hint: 'SOC / Security Queue',
    recommendedAction:
      'Isolate inputs; validate perimeter; rotate credentials if needed.',
  },
  premise: {
    hint: 'Architecture / Requirements Review',
    recommendedAction:
      'Validate premise constraints; update workflow assumptions.',
  },
  authority: {
    hint: 'Governance / Policy Review',
    recommendedAction:
      'Check policy profile; confirm stop-right boundaries.',
  },
  continuity: {
    hint: 'Change Mgmt / Rollback Path',
    recommendedAction:
      'Enter post-update watch; consider rollback if system-wide.',
  },
};

/**
 * Returns the routing decision for a containment event.
 * Scope is available for future routing escalation logic
 * (e.g. system-wide continuity events always trigger Change Mgmt).
 */
export function computeRouting(
  layer: ContainmentLayer,
  _scope: ImpactScope,
): RoutingDecision {
  const decision = ROUTING_TABLE[layer];
  // Future: escalate routing based on scope === 'sys' + layer === 'continuity'
  return decision;
}

/**
 * Returns a human-readable blocked-layer label for the Admin Terminal.
 * Maps internal enum to the display string used in the UI.
 */
export function layerDisplayLabel(layer: ContainmentLayer): string {
  const labels: Record<ContainmentLayer, string> = {
    gate: 'External Gate',
    premise: 'Premise Consistency',
    authority: 'Authority',
    continuity: 'Continuity',
  };
  return labels[layer];
}

/**
 * Returns a human-readable impact scope label for the Admin Terminal.
 */
export function scopeDisplayLabel(scope: ImpactScope): string {
  const labels: Record<ImpactScope, string> = {
    req: 'Single Request',
    flow: 'Workflow-Level',
    sys: 'System-Wide',
  };
  return labels[scope];
}
