# Wardline — Filigree Filing System Design

**Date:** 2026-03-22
**Purpose:** Defines how we represent Wardline's implementation work in filigree. This document is the reference for any agent creating or working with issues.

---

## Type Hierarchy

```
Milestone: "Wardline Python MVP"
  └── Phase (7 phases, sequence 0-6)
       └── Work Package (T-x.y tasks from execution sequence — the assignable unit)
            └── Step (created by implementing agent at execution time, not pre-populated)

Requirements (cross-cutting spec invariants, 19 total)
  └── (acceptance criteria in the requirement's `acceptance_criteria` field, not as separate issues)

Release: "v0.1.0"
  └── Release Items (one per Phase, tracking phase inclusion in release)
```

### What Each Type Represents

| Type | Represents | Created When | By Whom |
|------|-----------|-------------|---------|
| Milestone | The overall MVP delivery | Once, at project setup | Planner |
| Phase | Logical grouping (Phase 0: Foundation, etc.) | Once, at project setup | Planner |
| Work Package | A PR-sized unit of assignable work (maps 1:1 to execution sequence T-x.y tasks) | Once, at project setup | Planner |
| Step | Sub-tasks within a Work Package | At execution time, when agent claims the WP | Implementing agent |
| Requirement | A spec invariant that must be verified | Once, at project setup | Planner |
| Release | A versioned release to ship | Once, at project setup | Planner |
| Release Item | Tracks a phase's inclusion in a release | Once, at project setup | Planner |

---

## Dependency Relationships

### Work Package → Work Package (execution ordering)

WP dependencies mirror the Mermaid graph in the execution sequence. If T-1.2 depends on T-1.1, then WP "T-1.2 Canonical Decorator Registry" is `blocked_by` WP "T-1.1 Enums and Constants".

An agent running `filigree ready` will only see WPs whose upstream dependencies are all delivered.

### Requirement → Work Package (verification linkage)

A requirement is `blocked_by` the Work Package(s) that implement it. This means:
- The requirement **cannot be verified** until the WP is delivered
- The WP **does not need** the requirement to be in any particular state to start
- When the WP reaches `delivered`, the requirement is unblocked and can move to `verified`

This avoids circular dependencies. The WP's acceptance criteria should reference which requirements it satisfies.

### Parent-Child Relationships

- Milestone is `parent_id` of its Phases
- Phase is `parent_id` of its Work Packages
- Release is `parent_id` of its Release Items (one per phase)

---

## Label System

Labels use namespace prefixes for structured filtering.

### Phase Labels (applied to Work Packages)

| Label | Meaning |
|-------|---------|
| `phase:0` | Foundation |
| `phase:1` | Core Data Model |
| `phase:2` | Decorator Library |
| `phase:3` | Manifest System |
| `phase:4` | AST Scanner |
| `phase:5` | CLI |
| `phase:6` | Corpus + Self-Hosting |

### Subsystem Labels (applied to Work Packages and Requirements)

> **Note:** `area:` is a reserved auto-tag namespace in filigree (computed from file paths). Use `subsystem:` instead.

| Label | Meaning |
|-------|---------|
| `subsystem:core` | `src/wardline/core/` — enums, registry, taint lattice, matrix |
| `subsystem:runtime` | `src/wardline/runtime/` — type markers, descriptors, WardlineBase |
| `subsystem:decorators` | `src/wardline/decorators/` — factory, authority, audit, schema |
| `subsystem:manifest` | `src/wardline/manifest/` — loader, discovery, merge, coherence |
| `subsystem:scanner` | `src/wardline/scanner/` — engine, rules, taint, SARIF, discovery |
| `subsystem:cli` | `src/wardline/cli/` — skeleton, scan, manifest, corpus, explain |
| `subsystem:corpus` | `corpus/` — specimens, manifest, verification |
| `subsystem:ci` | `.github/` — CODEOWNERS, CI pipeline, baselines |

### Effort Labels (applied to Work Packages)

| Label | Meaning |
|-------|---------|
| `effort:xs` | Trivial — config, scaffolding |
| `effort:s` | Small — single file, straightforward |
| `effort:m` | Medium — multiple files, some design |
| `effort:l` | Large — substantial implementation, multiple concerns |

### Spec Labels (applied to Requirements)

| Label | Meaning |
|-------|---------|
| `spec:authority-tiers` | Authority tier model (spec 01-04, 01-05) |
| `spec:taint-model` | Taint state model (spec 01-04, binding 02-A) |
| `spec:pattern-rules` | Pattern rules (spec 01-07, binding 02-A) |
| `spec:enforcement` | Enforcement layers (spec 01-08) |
| `spec:governance` | Governance model (spec 01-09) |
| `spec:portability` | Manifest format (spec 01-13) |
| `spec:conformance` | Conformance profiles (spec 01-14) |

---

## Work Package Content

Each WP has lean fields pointing back to the execution sequence for full detail:

| Field | Content |
|-------|---------|
| `title` | `T-x.y: Short name` (matches execution sequence) |
| `description` | 1-2 sentence summary + link: `See docs/2026-03-22-execution-sequence.md § T-x.y` |
| `acceptance_criteria` | The "Done when" criteria from the execution sequence (verbatim) |
| `labels` | `phase:N`, `subsystem:X`, `effort:Y` |
| `deps` | Blocked by upstream WPs per the Mermaid graph |
| `priority` | P1 for critical path, P2 for default, P3 for runtime-only (not on critical path) |

### What the Implementing Agent Does

When an agent claims a WP:

1. Read the WP's acceptance criteria and the linked execution sequence section
2. Create Steps within the WP for their planned sub-tasks
3. Implement, commit, and close Steps as they go
4. When all Steps are done, deliver the WP with a reason summarising what was built
5. Check which Requirements are now unblocked and can be verified

---

## Requirement Content

Each requirement captures a spec invariant:

| Field | Content |
|-------|---------|
| `title` | Short invariant name |
| `description` | What must be true, referencing spec section |
| `req_type` | `functional`, `non_functional`, `constraint`, or `interface` |
| `rationale` | Why this requirement exists (threat it prevents or property it guarantees) |
| `acceptance_criteria` | Verification criteria (what to check, not how) |
| `verification_method` | `test`, `inspection`, `analysis`, or `demonstration` (required at verified) |
| `labels` | `spec:X`, `subsystem:Y` |
| `blocked_by` | WP(s) that must deliver before this can be verified |

---

## Workflow Lifecycle

### Typical Flow

```
1. Planner creates Milestone → Phases → Work Packages
2. Planner creates Requirements with Acceptance Criteria
3. Planner links Requirements blocked_by WPs
4. Planner creates Release + Release Items (one per phase)
5. Agent runs `ready` → filters for `work_package` type → claims highest-priority unblocked WP
6. Agent decomposes WP into Steps → executes → delivers WP
7. After delivering WP, agent checks for newly unblocked Requirements and verifies single-blocker ones immediately
8. Multi-blocker Requirements are verified only when ALL blocking WPs deliver
9. When all WPs delivered and Requirements verified → Milestone closes
10. Release moves through frozen → testing → staged → released
```

### State Mapping

| Type | Start | Working | Done |
|------|-------|---------|------|
| Work Package | `defined` | `assigned` → `executing` | `delivered` |
| Step | `pending` | `in_progress` | `completed` |
| Requirement | `drafted` → `approved` | `implementing` | `verified` |
| Phase | `pending` | `active` | `completed` |
| Milestone | `planning` | `active` → `closing` | `completed` |
| Release | `planning` | `development` → `frozen` → `testing` → `staged` | `released` |

---

## Reference Documents

- **Execution sequence:** `docs/2026-03-22-execution-sequence.md` — authoritative for WP content
- **Design doc:** `docs/2026-03-21-wardline-python-design.md` — implementation design
- **Specification:** `docs/wardline/` — framework spec (requirements trace here)
- **Review synthesis:** `docs/reviews/2026-03-22-execution-sequence-re-review-synthesis.md`
