# NCAOS × Urielle — Decoupled Assurance Monitor

A lightweight proof of concept showing how boundary-emitted governance signals can be interpreted by an external audit layer without requiring access to internal system logic.

## What this demonstrates

This PoC validates that a minimal boundary event schema can be:

- consistently interpreted as governance-relevant signals
- mapped into control domains
- translated into structured audit artifacts
- used without breaking architectural independence between control and audit layers

## Context

The PoC uses an illustrative event set representing boundary-emitted governance signals:

- `policy_violation`
- `unauthorized_access`
- `state_anomaly`
- `integrity_breach`

These events are processed by a lightweight audit interpretation layer that generates:

- severity classification
- control category mapping
- NIST AI RMF references
- Japan AI Guidelines for Business references
- audit findings
- recommended analyst actions
- schema gap indicators

## Why this matters

The exercise validates a decoupled governance model:

- **NCAOS / boundary layer** emits structured governance signals
- **Urielle / audit layer** interprets them into assurance outputs

This suggests that external auditability can be achieved without internal model access, while preserving separation of concerns.

## Included artifacts

- `audit_results.json` — structured interpreted outputs
- `audit_results.csv` — tabular export for review
- `NCAOS_Urielle_Interface_Validation.pdf` — executive summary of interface validation
- UI screenshots — visual reference of the PoC console

## Reference implementation

CodeSandbox:
`https://codesandbox.io/p/sandbox/n4cfst`

## Validation outcome

The current boundary event schema is sufficient for:

- consistent interpretation
- control mapping
- audit artifact generation

The PoC also surfaced optional enrichment fields that would improve audit depth, such as:

- source identity
- session ID
- asset context
- anomaly context / baseline reference

## Scope note

This repository represents a **PoC evaluation artifact**, not a production system.

It is intended to demonstrate interface sufficiency and audit interpretation behavior only. It does not expose proprietary internal control logic or production audit methodology.

## Screenshot

Add one dashboard screenshot here, for example:

![Decoupled Assurance Monitor](./screenshots/dashboard-overview.png)

## Author

Toru Takahashi  / William Holidi Hartono  
NCAOS / Urielle AI
