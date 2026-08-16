# NCAOS-Urielle

> **Decoupled Runtime Governance and Independent Assurance for Agentic AI**

**NCAOS** provides governance enforcement.
**Urielle AI** provides independent governance assurance.

NCAOS-Urielle explores how autonomous and agentic AI systems can be monitored, constrained, and audited at runtime while keeping governance enforcement structurally separate from governance assurance.

---

## Research Relevance

NCAOS-Urielle is an applied engineering and governance project exploring runtime control and accountability for agentic AI systems.

The project focuses on questions that become increasingly important as autonomous and multi-agent systems interact with external tools, APIs, and enterprise workflows:

* How can agent actions and workflow events be observed and reconstructed?
* How can unsafe or policy-violating behaviour be detected during execution?
* How can permissions, escalation, and fail-safe behaviour be enforced at runtime?
* What evidence is needed to support attribution and post-event investigation?
* How can responsibility be assessed when failures emerge across a sequence of agent interactions?
* How can governance assurance remain independent from the system being governed?

The architecture separates **runtime enforcement** from **independent assurance**.

NCAOS observes, evaluates, contains, and enforces governance boundaries. Urielle independently evaluates the resulting governance signals and converts them into evidence, findings, sequence analysis, and audit-ready reports.

The project does not claim that agent attribution, multi-agent safety, or accountability are solved problems. Instead, it provides testable infrastructure for studying runtime behaviour, traceability, control effectiveness, governance failure modes, and evidence quality in agentic systems.

---

## Architecture

Detailed architecture documentation is available for both governance enforcement and governance assurance layers.

### NCAOS / External Governance Shell (EGS)

Governance boundary responsible for observation, detection, containment, and enforcement.

* 📐 [Interactive Architecture Diagram](docs/NCAOS/phase_07/architecture/NCAOS_Phase07_Architecture.html)
* 📄 [Architecture PDF](docs/NCAOS/phase_07/architecture/NCAOS_Phase07_Architecture.pdf)

### Urielle AI

Audit Intelligence Layer responsible for runtime verification, governance evidence, and audit reporting.

* 📐 [Interactive Architecture Diagram](docs/Urielle/phase_07/architecture/Urielle_Architecture.html)
* 📄 [Architecture PDF](docs/Urielle/phase_07/architecture/Urielle_Architecture.pdf)

---

## Overview

NCAOS-Urielle demonstrates a decoupled approach to AI governance where governance enforcement and governance assurance remain structurally independent from the protected AI system.

The platform consists of two complementary layers.

### NCAOS / EGS

An independent governance boundary responsible for:

* Observation
* Detection
* Policy Evaluation
* Containment
* Enforcement
* Runtime Governance Controls

### Urielle AI

An independent Audit Intelligence Layer responsible for:

* Runtime Verification
* Governance Evidence
* Audit Findings
* Sequence Analysis
* ISO/IEC 42001 Evidence Mapping
* MTTD Analysis
* Audit-Ready Reporting

Together, the two layers demonstrate how AI systems can be governed, monitored, and audited without requiring access to model weights, internal prompts, proprietary algorithms, or hidden reasoning processes.

---

## Why This Matters

Many AI governance approaches emphasize documentation, policies, assessments, and static controls.

NCAOS-Urielle explores a complementary approach:

> **Treat governance as runtime infrastructure.**

Instead of asking only:

* Was a control designed?
* Was a policy written?
* Was a risk documented?

the system also asks:

* Was a governance event detected?
* Was the correct boundary applied?
* Was containment triggered?
* Was enforcement applied?
* Was evidence generated?
* Can the event sequence be reconstructed?
* Can the governance outcome be independently audited?

This creates an explicit separation of responsibilities:

| Layer               | Responsibility                             |
| ------------------- | ------------------------------------------ |
| Protected AI System | Produces outputs and executes tasks        |
| NCAOS / EGS         | Observes and governs behaviour             |
| Urielle AI          | Independently verifies governance outcomes |

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
 Sequence Analysis
 ISO/IEC 42001 Mapping
 MTTD Analysis
 Audit Reports
```

The two systems communicate through the **ADR-006 AuditSignal Contract**, preserving structural independence between governance enforcement and governance assurance.

---

# NCAOS / EGS

## Core Engine

Shared governance framework providing:

* Governance Contracts
* Integrity Scoring
* Verdict Generation
* Routing Logic
* Policy Loading
* Detection Layer Integration

Core modules include:

* Verdict Engine
* Routing Engine
* Integrity Scoring
* Governance Contracts
* Policy Loader

---

## Detection Engine

Independent governance detectors monitor different aspects of runtime behaviour.

### Gate Detector

Validates entry conditions and governance boundaries.

### Premise Detector

Evaluates contextual assumptions and policy premises.

### Authority Detector

Detects authority violations and decision-boundary breaches.

### Continuity Detector

Monitors workflow continuity and governance consistency.

### MTTD Tracker

Measures Mean Time To Detection across governance layers.

Detector independence is intended to reduce reliance on a single governance decision mechanism.

---

## Governance Shell Runtime

The governance shell operates through a structured:

```text
Observer → Judge → Enforcer
```

pipeline.

Supporting services include:

* Shell Loop
* Observer Runtime
* Judge Runtime
* Enforcer Runtime
* Governance Watchdog

This provides a runtime boundary between the protected AI system and the environment in which its actions are permitted.

---

## Governance API

The API layer provides:

* Event Processing
* Audit Retrieval
* Policy Management
* Tenant Registry
* Event Store
* Governance State Access

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

Sequence-oriented endpoints support reconstruction and analysis of governance behaviour across multiple related events.

---

## Governance Dashboard

Provides operational visibility into:

* Governance Events
* Detection Activity
* Runtime Signals
* Audit Evidence
* Governance Health

Built using:

* React
* Vite
* TypeScript

---

# Urielle AI

## Audit Intelligence Layer

Urielle consumes governance signals generated by NCAOS through the ADR-006 interface contract.

Urielle does **not** require access to:

* Model weights
* Internal prompts
* Protected system state
* Proprietary decision logic
* Hidden reasoning processes

Instead, it evaluates governance evidence generated at the external governance boundary.

This design supports separation between the system making or executing decisions and the layer evaluating whether governance controls operated as intended.

---

## Audit Signal Consumer

Validates and interprets `AuditSignal` objects.

Functions include:

* Schema Validation
* Evidence Assessment
* Control Mapping
* Audit Summarisation

---

## Finding Generator

Transforms governance events into structured audit findings.

Produces:

* Audit Findings
* Severity Assessments
* Control Status Evaluations
* STRIDE Context References

---

## Sequence Analyzer

Evaluates behavioural patterns across governance event sequences.

Produces:

* Governance Posture
* Sequence Audit Reports
* Tenant Posture Summaries

Example posture states:

```text
HEALTHY
UNDER_PRESSURE
CONTAINED
UNSTABLE
```

Sequence analysis is particularly relevant where a governance outcome cannot be understood from a single event and must instead be reconstructed across a workflow.

---

## ISO/IEC 42001 Evidence Engine

Builds structured evidence packages supporting:

* ISO/IEC 42001 controls
* Governance-control mapping
* Coverage assessment
* Audit-readiness evaluation

The objective is to connect runtime behaviour to evidence that can be reviewed independently.

---

## MTTD Monitor

Measures governance detection effectiveness through:

* SLA Evaluation
* Baseline Monitoring
* Detection Regression Analysis

---

## Report Builder

Assembles audit deliverables including:

* Findings
* Sequence Reports
* Coverage Reports
* MTTD Reports
* Tenant Audit Reports

into a consolidated audit package.

---

# Security & Governance Validation

Dedicated validation modules include:

## Threat Modelling

* STRIDE
* AI/ML Threat Models

## Governance Standards

* ISO/IEC 42001 Mapping

## Security Validation

* Authentication Validation
* Pentest Scenarios
* Chaos Testing
* Detection Regression Testing

These validation activities are intended to test both security assumptions and governance-control behaviour.

---

# Architectural Principles

The platform follows several core principles:

1. Governance remains external to system intelligence.
2. Enforcement and assurance remain structurally independent.
3. Fail-safe containment takes precedence over availability when required by policy.
4. Governance decisions must be observable.
5. Governance events should be reconstructable across a sequence.
6. Audit evidence must be reproducible.
7. Tenant isolation is mandatory.
8. Detector independence reduces single-point governance failure.
9. Runtime controls should produce evidence suitable for independent review.

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

* External Governance Shell (EGS)
* Observer → Judge → Enforcer architecture
* Independent governance detectors
* Multi-tenant governance support
* Runtime event monitoring
* Event-sequence analysis
* Audit signal generation
* Audit intelligence processing
* ISO/IEC 42001 evidence mapping
* Security hardening framework
* Governance dashboard
* ADR-based architecture documentation

---

# Research Areas

Current and potential research directions include:

* Agentic AI Runtime Governance
* Multi-Agent Failure Modes
* Runtime Verification
* Agent Action Traceability
* Attribution and Accountability
* Governance Evidence
* Audit Signal Standards
* Governance Observability
* Governance Containment
* Audit Automation
* AI Assurance Engineering
* Runtime Control Evaluation
* Human Oversight and Escalation
* AI Governance Infrastructure

---

# Scope and Limitations

NCAOS-Urielle is an experimental governance and assurance architecture.

It is intended to explore engineering patterns for runtime governance, evidence generation, and independent assurance.

The current implementation should not be interpreted as:

* a complete solution to agent attribution
* a complete solution to multi-agent safety
* proof that runtime controls eliminate unsafe behaviour
* independent audit assurance
* certification readiness
* a replacement for organizational governance, security review, or human oversight

The project is intended to make these governance questions more observable and testable.

---

# Authors

**Toru Takahashi**
NCAOS

**William Hartono**
Urielle AI

---

## Concept

**Decoupled Governance Enforcement + Independent Governance Assurance**
