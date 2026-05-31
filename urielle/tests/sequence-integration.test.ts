import { describe, it, expect } from "vitest";
import {
  AuditSignalSchema,
  evidenceLevel,
  derivePosture,
} from "../src/index.js";

describe("NCAOS Sequence Integration", () => {
  it("validates WF-DEMO-LIVE-001 sequence", () => {

    const summary = {
      sequenceId: "WF-DEMO-LIVE-001",
      patternType: "CONTAINED",
      escalationDetected: true,
      consistencyScore: 94,
      eventCount: 3,
      actionChain: ["DOWNGRADE", "BLOCK", "BLOCK"],
      layersInvolved: ["gate"],
      firstDetectedAt: "2026-05-23T16:06:59.795Z",
    };

    const signal = AuditSignalSchema.parse({
      evidenceHandle: "EVD-001",
      sequenceNumber: 2,
      layer: "authority",
      severity: "high",
      action: "BLOCK",
      authority: "invalid",
      integrityScore: 29,
      detectionMode: "Authority Boundary Enforcement",
      routingHint: "Governance / Policy Review",
      mttdMs: 0,
      detectedAt: "2026-05-23T16:06:59.795Z",
      storedAt: "2026-05-23T16:06:59.796Z",
      policyProfileId: "STRICT-PROD",
      partnerId: "DEMO_ENT_2026",
      schemaVersion: "1.0",
      sequence: summary,
    });

    expect(derivePosture(summary)).toBe("CONTAINED");
    expect(evidenceLevel(signal)).toBe("STRONG");
  });
});