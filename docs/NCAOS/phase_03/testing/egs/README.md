# NCAOS — External Governance Shell (EGS)

> **Structural decoupling of system governance from system intelligence.**

[![CI](https://github.com/wholidi/NCAOS-Urielle/actions/workflows/ci.yml/badge.svg)](https://github.com/wholidi/NCAOS-Urielle/actions)

---

## What This Is

NCAOS implements an **External Governance Shell (EGS)** — a decoupled
observer-judge-enforce layer that sits at the I/O boundary of an AI or autonomous
system. It governs outputs without interfering with internal model weights or
OS kernel logic.

**Three core capabilities:**

| Capability | What it means |
|---|---|
| **Boundary Governance** | Observes system outputs at the perimeter without touching internal state |
| **Visibility** | Translates high-entropy signals into human-readable integrity and authority indicators |
| **Containment** | Separates "unfiltered" internal state from "governed" external output |

## Architecture

```
External Environment
        │
        ▼
┌─────────────────────────────────────────┐
│       External Governance Shell (EGS)   │  ← this repo
│  Observer → Judge → Enforcer → Verdict  │
│  ┌──────┬──────────┬──────────┬───────┐ │
│  │ Gate │ Premise  │Authority │Contin.│ │  ← 4 detection layers
│  └──────┴──────────┴──────────┴───────┘ │
└─────────────────────────────────────────┘
        │
        ▼ (observe-only, no modification)
┌─────────────────────────────────────────┐
│       Protected Core (Black Box)        │
│       AI model / OS runtime             │
└─────────────────────────────────────────┘
```

## Repository Structure

```
ncaos/
├── core/           # @ncaos/core — Type contracts, scoring, detection, enforcement
│   ├── src/
│   │   ├── types/contracts.ts     # Canonical type definitions (Zod schemas)
│   │   ├── detection/layers.ts    # Four containment layer detection modules
│   │   ├── engine/verdict.ts      # Enforcer: event → verdict
│   │   ├── engine/routing.ts      # Triage routing decisions
│   │   ├── engine/ids.ts          # RequestId, EvidenceHandle generation
│   │   ├── scoring/integrity.ts   # Integrity, authority, containment metrics
│   │   └── policy/loader.ts       # PolicyProfile loader + builtin profiles
│   └── tests/                     # Unit tests (Vitest)
│
├── shell/          # @ncaos/shell — Process-isolated observer-judge-enforce loop
├── api/            # @ncaos/api   — REST + WebSocket server
├── ui/             # @ncaos/ui    — React Admin Terminal (replaces PoC HTML)
├── infra/          # Deployment configs (Docker, compose)
├── docs/adr/       # Architecture Decision Records
└── .github/        # CI/CD workflows
```

## Quick Start

```bash
# Install dependencies
npm install

# Run all tests
npm test

# Type-check all workspaces
npm run typecheck

# Start development (API + UI)
npm run dev:api   # Terminal 1
npm run dev:ui    # Terminal 2
```

## Design Invariants

1. **EGS never modifies internal model weights or OS kernel state.**
2. **The shell fails SAFE (BLOCK / `invalid` authority) on any internal error.**
   See [ADR-002](docs/adr/ADR-002-fail-safe-invariant.md).
3. **No root-cause inference.** The shell reports impact signals only —
   never claims to know why the protected core produced a given output.
4. **Evidence trail is structurally independent of the AI's internal logs.**
5. **Tenant isolation is enforced at every layer** — `PARTNER_ID` scopes all
   governance state, policy profiles, and event logs.

## Key Types

All shared contracts live in `@ncaos/core`. The four you'll use most:

```typescript
import type { GovEvent, GovState, PolicyProfile, Verdict } from '@ncaos/core';
```

See [`core/src/types/contracts.ts`](core/src/types/contracts.ts) for full definitions.

## Builtin Policy Profiles

| Profile ID | Gov Level | Blocks on |
|---|---|---|
| `STRICT-PROD` | `ENTERPRISE_STRICT` | med + high severity |
| `CRITICAL-STRICT` | `CRITICAL_STRICT` | any severity |
| `PILOT-OBS` | `PILOT` | never (observe only) |

## Architecture Decision Records

- [ADR-001: Type Contracts as Architectural Boundary](docs/adr/ADR-001-type-contracts.md)
- [ADR-002: Fail-Safe Default-Deny Invariant](docs/adr/ADR-002-fail-safe-invariant.md)

---

**Classification:** Non-Public / Concept Demonstration → Enterprise Pilot
**PoC Reference:** `NCAOS_UI_final.html` + `Proof_of_Concept_final.docx`
**GitHub:** [wholidi/NCAOS-Urielle](https://github.com/wholidi/NCAOS-Urielle)
