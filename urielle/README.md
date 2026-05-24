# Urielle AI

> Audit Intelligence Layer for Runtime Governance
## Architecture

**Interactive Architecture Diagram**

[Open Urielle Architecture](../docs/Urielle/phase_07/architecture/Urielle_Architecture.html)

[Architecture PDF](../docs/Urielle/phase_07/architecture/Urielle_Architecture.pdf)

---

Urielle AI transforms runtime governance signals into audit-ready evidence, findings, coverage assessments, and assurance reports.

Rather than enforcing governance controls directly, Urielle provides an independent assurance layer that evaluates whether governance controls operated as intended.

Urielle is designed to consume governance signals from NCAOS / EGS through the ADR-006 AuditSignal contract and produce structured audit outputs suitable for governance, compliance, assurance, and risk management workflows.

---

# Why Urielle Exists

Modern AI governance often struggles with a critical question:

> How do we know governance controls actually worked?

Policies may exist.

Controls may be configured.

Monitoring may be deployed.

Yet organisations frequently lack independent evidence showing:

- what governance events occurred
- which controls activated
- how containment decisions were made
- whether governance objectives were achieved

Urielle addresses this gap.

Its role is to transform runtime governance activity into independently verifiable governance evidence.

---

# Position in the Architecture

```text
Protected AI System
        │
        ▼

NCAOS / EGS
(Governance Enforcement)

Observer
Judge
Enforcer

        │
        ▼

AuditSignal
(ADR-006)

        │
        ▼

Urielle AI
(Audit Intelligence)

Finding Generation
Sequence Analysis
Evidence Mapping
MTTD Evaluation
Audit Reporting

        │
        ▼

Audit-Ready Outputs
```

Urielle never modifies the protected system.

Urielle never participates in enforcement decisions.

Urielle remains structurally independent from governance execution.

---

# Core Modules

## audit-signal-consumer

Boundary interface implementation.

Responsibilities:

- AuditSignal validation
- Evidence classification
- Signal normalization
- ISO control mapping
- Human-readable summaries

Key outputs:

```text
AuditSignal
EvidenceLevel
AuditSummary
```

---

## finding-generator

Transforms governance events into audit findings.

Produces:

- AuditFinding
- Severity Classification
- Control Status
- STRIDE Context

Supported severities:

```text
INFORMATIONAL
LOW
MEDIUM
HIGH
CRITICAL
```

---

## sequence-analyzer

Evaluates behavioural patterns across governance event chains.

Produces:

```text
GovernancePosture
SequenceAuditReport
TenantPostureSummary
```

Supported posture states:

```text
HEALTHY
UNDER_PRESSURE
CONTAINED
UNSTABLE
```

---

## iso42001-evidence

Builds structured evidence packages supporting AI management system audits.

Capabilities:

- Control Evidence Records
- Coverage Assessment
- Readiness Evaluation
- Clause Mapping

Current readiness states:

```text
READY
PARTIAL
NOT_READY
```

---

## mttd-monitor

Evaluates governance detection effectiveness.

Measures:

- Mean Time To Detection
- SLA Compliance
- Baseline Deviation
- Regression Indicators

Supports layer-specific governance monitoring.

---

## report-builder

Final orchestration layer.

Combines outputs from all modules into a complete audit package.

Produces:

```text
UrielleTenantAuditReport
```

including:

- Findings
- Sequence Reports
- Coverage Reports
- MTTD Reports
- Posture Assessments

---

# AuditSignal Contract

Urielle consumes only the ADR-006 boundary interface.

Supported signal categories include:

```text
Gate
Premise
Authority
Continuity
```

Urielle does not access:

- Model weights
- Internal prompts
- Hidden reasoning
- Protected runtime state

This preserves separation between governance enforcement and governance assurance.

---

# Evidence Model

Urielle evaluates evidence strength using three levels:

| Level | Meaning |
|---------|---------|
| WEAK | Limited governance evidence |
| MODERATE | Significant governance signal present |
| STRONG | Escalation or sequence-based evidence |

Evidence strength is derived from severity, action outcomes, escalation indicators, and governance sequence context.

---

# ISO 42001 Mapping

Urielle provides evidence mappings aligned to governance control areas including:

| Governance Layer | Example Controls |
|---------|---------|
| Gate | 6.1.2, 8.4, 9.1 |
| Premise | 6.1.3, 8.3, 9.2 |
| Authority | 8.5, 9.3, 10.1 |
| Continuity | 8.6, 9.1, 10.2 |

These mappings support audit readiness assessments and evidence packaging.

---

# Development

## Install

```bash
npm install
```

## Build

```bash
npm run build
```

## Test

```bash
npm test
```

## Watch Tests

```bash
npm run test:watch
```

---

# Source Layout

```text
urielle/
├── src/
│   ├── audit-signal-consumer.ts
│   ├── finding-generator.ts
│   ├── sequence-analyzer.ts
│   ├── iso42001-evidence.ts
│   ├── mttd-monitor.ts
│   ├── report-builder.ts
│   └── index.ts
│
├── tests/
│   └── urielle.test.ts
│
└── dist/
```

---

# Test Coverage

Current implementation includes:

- AuditSignal validation
- Evidence classification
- Finding generation
- Sequence analysis
- ISO 42001 evidence generation
- MTTD evaluation
- Report assembly
- ADR-006 integration validation

Current test suite:

```text
53 / 53 PASS
```

---

# Design Principles

### Independent Assurance

Assurance remains separate from enforcement.

### Boundary Visibility

Only boundary-level governance signals are consumed.

### Reproducible Evidence

Evidence generation must be deterministic and auditable.

### No Root-Cause Speculation

Urielle evaluates observable governance outcomes rather than internal system intent.

### Governance Traceability

Every finding must trace back to governance evidence.

### Audit Readiness

Outputs should support audit, assurance, governance, and compliance workflows.

---

# Relationship to NCAOS

NCAOS provides governance enforcement.

Urielle provides governance assurance.

Together they form a decoupled AI Governance Infrastructure:

```text
Governance Enforcement
        +
Governance Assurance
```

connected exclusively through the ADR-006 AuditSignal contract.

---

## Status

Version: v0.7.0

Classification: Concept Demonstration → Enterprise Pilot

Current focus areas:

- Runtime Verification
- Governance Evidence
- ISO 42001 Readiness
- Governance Telemetry
- Audit Signal Standards
- AI Assurance Engineering
