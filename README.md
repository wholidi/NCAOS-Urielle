# NCAOS-Urielle

> Decoupled AI Governance Infrastructure
>
> **NCAOS** provides governance enforcement.
>
> **Urielle AI** provides governance assurance.

## Architecture

Detailed architecture documentation is available for both governance enforcement and governance assurance layers.

### NCAOS / External Governance Shell (EGS)

Governance boundary responsible for observation, detection, containment and enforcement.

- 📐 [Interactive Architecture Diagram](docs/NCAOS/phase_07/architecture/NCAOS_Phase07_Architecture.html)
- 📄 [Architecture PDF](docs/NCAOS/phase_07/architecture/NCAOS_Phase07_Architecture.pdf)

### Urielle AI

Audit Intelligence Layer responsible for runtime verification, governance evidence and audit reporting.

- 📐 [Interactive Architecture Diagram](docs/Urielle/phase_07/architecture/Urielle_Architecture.html)
- 📄 [Architecture PDF](docs/Urielle/phase_07/architecture/Urielle_Architecture.pdf)
---

## Overview

NCAOS-Urielle demonstrates a decoupled approach to AI governance where governance enforcement and governance assurance remain structurally independent from the protected AI system.

The platform consists of two complementary layers:

### NCAOS / EGS (External Governance Shell)

An independent governance boundary responsible for:

- Observation
- Detection
- Policy Evaluation
- Containment
- Enforcement
- Runtime Governance Controls

### Urielle AI

An Audit Intelligence Layer responsible for:

- Runtime Verification
- Governance Evidence
- Audit Findings
- Sequence Analysis
- ISO 42001 Evidence Mapping
- MTTD Analysis
- Audit-Ready Reporting

Together they demonstrate how AI systems can be governed, monitored, and audited without requiring access to model weights, prompts, proprietary algorithms, or internal reasoning processes.

---

## Why This Matters

Most AI governance solutions focus on documentation, policies, or static controls.

NCAOS-Urielle explores a different approach:

> Treat governance as runtime infrastructure.

Instead of asking:

- Was a control designed?
- Was a policy written?

The system asks:

- Was a governance event detected?
- Was containment triggered?
- Was enforcement applied?
- Was evidence generated?
- Can the result be independently audited?

This creates a separation between:

| Layer | Responsibility |
|---------|---------|
| Protected AI System | Produces outputs |
| NCAOS / EGS | Governs behaviour |
| Urielle AI | Verifies governance outcomes |

---

## High-Level Architecture

```text
Protected AI System
        │
        ▼

 ┌───────────────────────┐
 │      NCAOS / EGS      │
 │ External Governance   │
 │        Shell          │
 └───────────────────────┘

 Observer
     │
     ▼
 Judge
     │
     ▼
 Enforcer

     │
     ▼

 AuditSignal (ADR-006)

     │
     ▼

 ┌───────────────────────┐
 │      Urielle AI       │
 │ Audit Intelligence    │
 │        Layer          │
 └───────────────────────┘

 Findings
 Evidence
 ISO42001 Mapping
 MTTD Analysis
 Audit Reports
```

The two systems communicate through the **ADR-006 AuditSignal Contract**, preserving structural independence between governance enforcement and governance assurance.

---

# NCAOS / EGS

## Core Engine

Shared governance framework providing:

- Governance Contracts
- Integrity Scoring
- Verdict Generation
- Routing Logic
- Policy Loading
- Detection Layer Integration

Core modules include:

- Verdict Engine
- Routing Engine
- Integrity Scoring
- Governance Contracts
- Policy Loader

---

## Detection Engine

Independent governance detectors:

### Gate Detector

Validates entry conditions and governance boundaries.

### Premise Detector

Evaluates contextual assumptions and policy premises.

### Authority Detector

Detects authority violations and decision boundary breaches.

### Continuity Detector

Monitors workflow continuity and governance consistency.

### MTTD Tracker

Measures Mean Time To Detection across governance layers.

---

## Governance Shell Runtime

The governance shell operates through a structured:

```text
Observer → Judge → Enforcer
```

pipeline.

Supporting services include:

- Shell Loop
- Observer Runtime
- Judge Runtime
- Enforcer Runtime
- Governance Watchdog

---

## Governance API

The API layer provides:

- Event Processing
- Audit Retrieval
- Policy Management
- Tenant Registry
- Event Store
- Governance State Access

Representative endpoints:

```text
/v1/events
/v1/events/sequence/:id
/v1/events/sequence/:id/summary
/v1/audit/:handle
/v1/mttd
/v1/state
/v1/policy
/v1/health
```

---

## Governance Dashboard

Provides operational visibility into:

- Governance Events
- Detection Activity
- Runtime Signals
- Audit Evidence
- Governance Health

Built using:

- React
- Vite
- TypeScript

---

# Urielle AI

## Audit Intelligence Layer

Urielle consumes governance signals generated by NCAOS through the ADR-006 interface contract.

Urielle does **not** access:

- model weights
- prompts
- protected system state
- internal scoring logic

Instead it processes governance evidence generated at the governance boundary.

---

## Audit Signal Consumer

Validates and interprets AuditSignal objects.

Functions include:

- schema validation
- evidence assessment
- control mapping
- audit summarisation

---

## Finding Generator

Transforms governance events into structured audit findings.

Produces:

- Audit Findings
- Severity Assessments
- Control Status Evaluations
- STRIDE Context References

---

## Sequence Analyzer

Evaluates behavioural patterns across governance event sequences.

Produces:

- Governance Posture
- Sequence Audit Reports
- Tenant Posture Summaries

Example posture states:

```text
HEALTHY
UNDER_PRESSURE
CONTAINED
UNSTABLE
```

---

## ISO 42001 Evidence Engine

Builds structured evidence packages supporting:

- ISO 42001 controls
- Coverage assessment
- Audit readiness evaluation

---

## MTTD Monitor

Measures governance detection effectiveness through:

- SLA Evaluation
- Baseline Monitoring
- Detection Regression Analysis

---

## Report Builder

Assembles complete audit deliverables including:

- Findings
- Sequence Reports
- Coverage Reports
- MTTD Reports
- Tenant Audit Reports

into a single audit package.

---

# Security & Governance Validation

Dedicated validation modules include:

## Threat Modelling

- STRIDE
- AI/ML Threat Models

## Governance Standards

- ISO 42001 Mapping

## Security Validation

- Authentication Validation
- Pentest Scenarios
- Chaos Testing
- Detection Regression Testing

---

# Architectural Principles

The platform follows several core principles:

1. Governance remains external to system intelligence
2. Enforcement and assurance remain independent
3. Fail-safe containment takes precedence over availability
4. Governance decisions must be observable
5. Audit evidence must be reproducible
6. Tenant isolation is mandatory
7. Detector independence reduces single-point governance failure

Architecture decisions are documented through ADR-001 to ADR-008.

---

# Repository Structure

```text
NCAOS-Urielle
│
├── egs/
│   ├── api/
│   ├── core/
│   ├── detection/
│   ├── shell/
│   ├── ui/
│   ├── hardening/
│   └── docs/
│
└── urielle/
    ├── audit-signal-consumer
    ├── finding-generator
    ├── sequence-analyzer
    ├── iso42001-evidence
    ├── mttd-monitor
    └── report-builder
```

---

# Current Status

Current implementation includes:

- External Governance Shell (EGS)
- Observer → Judge → Enforcer architecture
- Independent governance detectors
- Multi-tenant governance support
- Runtime event monitoring
- Audit signal generation
- Audit intelligence processing
- ISO 42001 evidence mapping
- Security hardening framework
- Governance dashboard
- ADR-based architecture documentation

---

# Research Areas

- AI Governance Infrastructure
- Runtime Verification
- Governance Evidence
- Audit Signal Standards
- Governance Observability
- Governance Containment
- Audit Automation
- AI Assurance Engineering

---

# Authors

**Toru Takahashi**  
NCAOS

**William Hartono**  
Urielle AI

---

## Concept

**Decoupled Governance Enforcement + Independent Governance Assurance**
