# ADR-001: Shared Type Contracts as the Architectural Boundary

**Date:** 2026-04-26
**Status:** Accepted
**Authors:** MLP / NCAOS Architecture

---

## Context

The EGS spans four packages: `core`, `shell`, `api`, and `ui`. Without a single
source of truth for shared data shapes, each package risks developing divergent
representations of the same concepts (GovEvent, PolicyProfile, Verdict), leading
to silent type mismatches, runtime errors at package boundaries, and difficulty
reasoning about the system's behavior.

The PoC (`NCAOS_UI_final.html`) demonstrated the concepts using plain JavaScript
with string literals and magic numbers scattered across multiple functions. This
is acceptable for a demonstration artifact but not for a production system.

## Decision

All shared data shapes are defined once in `@ncaos/core/src/types/contracts.ts`
using **Zod schemas** as the primary definition, with TypeScript types derived
from them via `z.infer<>`.

This means:
- **Runtime validation is free.** Any package can call `.parse()` on untrusted
  input (API requests, config files, WebSocket messages) and get a typed result
  or a structured error.
- **Schema is the documentation.** The `.parse()` call and the Zod schema are
  the same artifact — no separate JSON Schema or OpenAPI spec to keep in sync.
- **Breaking changes are explicit.** Changing a contract type causes TypeScript
  errors across all consuming packages at compile time, not at runtime.

## Alternatives Considered

1. **Interface-only (no runtime validation):** Faster to write, but provides no
   protection against malformed API payloads or misconfigured policy files.
   Rejected — the shell's security guarantees require validated inputs.

2. **JSON Schema + AJV:** More interoperable (usable from non-TypeScript clients)
   but requires maintaining two schema representations. Rejected for Phase 1.
   May be added in Phase 4 for OpenAPI spec generation.

3. **Protobuf / gRPC:** Best choice if cross-language clients are needed.
   Deferred — current scope is TypeScript-only.

## Consequences

- All packages must declare `@ncaos/core` as a dependency.
- Changing any exported type in `contracts.ts` is a **breaking change** and
  requires a version bump on `@ncaos/core`.
- New fields must be added as `z.optional()` to avoid breaking existing callers.
- The Zod dependency is a runtime dependency of `@ncaos/core`, not dev-only.

## Type Contract Versioning Policy

Until v1.0: breaking changes are permitted with a minor version bump on core.
At v1.0 and beyond: breaking changes require a major version bump and a migration guide.
