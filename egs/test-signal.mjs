import { AuditSignalSchema, fromEventRecord, evidenceLevel,
         auditFindingSummary, ISO42001_CONTROL_MAP }
  from './audit-signal/src/audit-signal.ts';
 
// Test 1: Validate core layer
const signal = {
  schemaVersion: "1.0",
  core: {
    evidenceHandle: "EVD-1778168626181-5164BEB0",
    sequenceNumber: 2,
    layer: "gate",
    severity: "high",
    action: "BLOCK",
    authority: "invalid",
    integrityScore: 29,
    detectionMode: "Real-time Gate Enforcement",
    routingHint: "SOC / Security Queue",
    mttdMs: 12.5,
    detectedAt: new Date().toISOString(),
    storedAt: new Date().toISOString(),
    policyProfileId: "STRICT-PROD",
    partnerId: "GLOBAL_ENT_2026"
  }
};
const parsed = AuditSignalSchema.parse(signal);
console.log("Schema valid:", !!parsed);
 
// Test 2: evidenceLevel
console.log("Evidence level:", evidenceLevel(parsed));
 
// Test 3: auditFindingSummary
console.log("Finding:", auditFindingSummary(parsed));
 
// Test 4: ISO 42001 controls
console.log("ISO controls:", ISO42001_CONTROL_MAP["gate"]);
 
// Test 5: Invalid schema throws
try { AuditSignalSchema.parse({ bad: "data" }); }
catch(e) { console.log("Validation correctly rejects invalid:", true); }

// Test 6: Add sequence layer to signal
const withSeq = {
  ...signal,
  sequence: {
    sequenceId: "WF-UI-TEST-001",
    patternType: "CONTAINED",
    escalationDetected: true,
    consistencyScore: 94,
    eventCount: 2,
    firstDetectedAt: new Date().toISOString(),
    actionChain: ["DOWNGRADE", "BLOCK"],
    layersInvolved: ["gate"]
  }
};

const parsedSeq = AuditSignalSchema.parse(withSeq);

console.log("Sequence layer valid:", !!parsedSeq.sequence);
console.log("Pattern type:", parsedSeq.sequence?.patternType);
console.log("Evidence level with sequence:", evidenceLevel(parsedSeq));

// Add optional enrichment
const withEnrich = {
  ...withSeq,
  enrichment: {
    identityRef: "user-ref-abc123",
    assetRef: "asset-ref-xyz789",
    sessionId: "sess-001",
    serviceComponent: "AuthService",
    tags: { env: "production", team: "security" }
  }
};
const parsedEnrich = AuditSignalSchema.parse(withEnrich);
console.log("Enrichment valid:", !!parsedEnrich.enrichment);
console.log("All three layers present:",
  !!parsedEnrich.core && !!parsedEnrich.sequence && !!parsedEnrich.enrichment);
