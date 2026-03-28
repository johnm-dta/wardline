# ADR-002: Rename tier-source decorators to match posture vocabulary

**Status**: Accepted
**Date**: 2026-03-28
**Deciders**: Project Lead, Review Board
**Context**: Tier-source decorator names use audit-specific language inherited from the prototype exemplar

## Summary

Rename four tier-source and tier-critical decorators from audit-specific
names (`@audit_writer`, `@audit_critical`, `@tier1_read`,
`@authoritative_construction`) to posture-aligned names that match the
taint state rename in ADR-001.

Group 1 (data-flow) decorators use the `integral_` adjective prefix:
`@integral_writer`, `@integral_read`, `@integral_construction`.

Group 2 (consequence) decorator uses the `integrity_` noun prefix:
`@integrity_critical`.

Validation-transition decorators (`@validates_shape`, `@validates_semantic`,
`@validates_external`, `@external_boundary`) are unchanged — they describe
the transition action, not the tier.

**This ADR changes decorator names only. It does not change decorator
semantics, `_wardline_*` attribute contracts, or boundary transition types.**

## Context

The wardline decorator library provides two categories of decorators:

1. **Group 1: Tier-source decorators** — mark functions that produce or
   consume data at a specific tier level. These reference the tier by name.
2. **Group 2: Tier-critical decorators** — mark operations where silent
   failure is an integrity breach. These reference the consequence.

With ADR-001 renaming taint states from prototype names to posture
vocabulary (AUDIT_TRAIL -> INTEGRAL), the tier-source decorators must
track the rename. The current names:

| Decorator | Group | Problem |
|-----------|-------|---------|
| `@audit_writer` | 1 | Suggests only audit-log writes, not all T1 writes |
| `@audit_critical` | 2 | Suggests audit-log criticality, not integrity-critical operations |
| `@tier1_read` | 1 | Uses tier number — adequate but inconsistent with posture vocabulary |
| `@authoritative_construction` | 1 | Already good, but should track to `integral_` prefix for consistency |

The validation decorators (`@validates_shape`, `@validates_semantic`,
`@validates_external`, `@external_boundary`) describe what the function
*does* (validates shape, validates semantics), not what tier it belongs to.
They don't reference tier names and don't need renaming.

### Naming structure: adjective prefix (Group 1) vs noun prefix (Group 2)

Group 1 decorators describe **data flow** — what kind of data the function
reads, writes, or constructs. The `integral_` adjective prefix matches the
taint state token (`INTEGRAL`) and reads naturally: "writes integral data."

Group 2 decorators describe **consequence** — what happens if the operation
fails silently. The `integrity_` noun prefix names the stake: "critical to
integrity." This grammatical distinction between adjective (Group 1) and
noun (Group 2) naturally separates the two decorator families.

### PY-WL-006 impact

PY-WL-006 ("Audit-critical writes in broad exception handlers") uses
heuristic detection based on the names `audit*`, `record*`, `emit*`.
The decorator rename from `@audit_writer`/`@audit_critical` to
`@integral_writer`/`@integrity_critical` means PY-WL-006's heuristic must
be updated to match the new decorator names, or refactored to use
the `_wardline_*` attribute contract instead of name-based detection.

### Spec Group 2 name

The spec currently calls Group 2 "Audit Primacy." This should be renamed
to "Integrity Primacy" or "Integrity Ordering" to match the decorator
rename.

## Decision

Rename four decorators:

| Current | New | Group | Rationale |
|---------|-----|-------|-----------|
| `@audit_writer` | `@integral_writer` | 1 | Follows T1 rename to INTEGRAL; drops audit-specific framing |
| `@tier1_read` | `@integral_read` | 1 | Posture name instead of tier number |
| `@authoritative_construction` | `@integral_construction` | 1 | Consistency with `integral_` prefix |
| `@audit_critical` | `@integrity_critical` | 2 | Names the consequence (integrity breach), not the zone |

Unchanged:

| Decorator | Why unchanged |
|-----------|--------------|
| `@validates_shape` | Describes transition action, not tier |
| `@validates_semantic` | Describes transition action, not tier |
| `@validates_external` | Describes transition action, not tier |
| `@external_boundary` | Describes provenance boundary, not tier |

### What does not change

- `_wardline_*` attribute semantics on decorated functions
- Boundary transition type strings (`shape_validation`, `semantic_validation`, etc.)
- The decorator registry structure in `core/registry.py`
- Decorator grouping (Group 1: tier-source, Group 2: tier-critical)

## Alternatives Considered

### Alternative 1: Keep current names, document the mismatch

**Description**: Leave decorator names as-is, note in documentation that
`@audit_writer` means "T1/INTEGRAL writer."

**Pros**:
- Zero migration effort
- No risk of breaking adopter code

**Cons**:
- Adopters see `@audit_writer` on code that has nothing to do with auditing
- Two vocabularies: taint states say INTEGRAL, decorators say audit
- New adopter confusion: "I don't have an audit trail, do I need this?"

**Why rejected**: Pre-v1.0, zero adopters. The documentation workaround
creates the same "don't read the name literally" problem that ADR-001
eliminates for taint states.

### Alternative 2: Use `strict_` prefix throughout (both groups)

**Description**: `@strict_writer`, `@strict_read`, `@strict_construction`,
`@strict_critical`

**Pros**:
- Single consistent prefix
- Matches original §4.1 posture name

**Cons**:
- `@strict_critical` reads as "strictly critical" — two adjectives
  colliding with no clear meaning
- Doesn't communicate *why* it's strict (the integrity concern)
- STRICT was superseded by INTEGRAL for the taint state (ADR-001)

**Why rejected**: `@strict_critical` is grammatically broken. The
adjective/noun split between Group 1 (`integral_`) and Group 2
(`integrity_`) is more meaningful and naturally separates data-flow
decorators from consequence decorators.

### Alternative 3: Use tier-number decorators

**Description**: `@tier1_writer`, `@tier1_critical`, `@tier1_read`,
`@tier1_construction`

**Pros**:
- Simple, unambiguous
- `@tier1_read` already exists

**Cons**:
- Tier numbers are less meaningful than posture names
- "tier1_critical" doesn't communicate *why* it's critical
- Inconsistent with the posture vocabulary in ADR-001

**Why rejected**: Posture names communicate intent better than tier
numbers. The whole point of ADR-001 is that names should describe the
coding discipline, not an abstract numbering.

## Consequences

### Positive

- Group 1 decorators match taint state vocabulary (`INTEGRAL` /
  `@integral_writer`)
- Group 2 decorator names the consequence clearly
  (`@integrity_critical` = "if this fails silently, that's an integrity
  breach")
- Grammatical distinction between groups: adjective prefix (data flow)
  vs noun prefix (consequence) is self-documenting
- Consistent `integral_` prefix for all Group 1 decorators
- Works across domains: defence, healthcare, finance all understand
  "integrity-critical" without domain-specific context

### Negative

- PY-WL-006 heuristic detection needs updating for new decorator names
- Spec Group 2 name "Audit Primacy" needs renaming
- Four decorator definitions, their tests, and the registry need renaming
- Any documentation referencing old decorator names needs updating

### Neutral

- The decorator registry structure (`REGISTRY` in `core/registry.py`)
  is unchanged — only the keys change
- Validation decorators (`@validates_shape`, etc.) are unaffected

## Implementation Notes

### Blast radius

| Artifact | Changes |
|----------|---------|
| `decorators/audit.py` | Rename `@audit_writer`, `@audit_critical` |
| `decorators/authority.py` | Rename `@tier1_read`, `@authoritative_construction` |
| `core/registry.py` | Update registry keys |
| `scanner/rules/py_wl_006.py` | Update `_AUDIT_DECORATORS` set and heuristic prefixes |
| `scanner/taint/function_level.py` | Update `BODY_EVAL_TAINT` / `RETURN_TAINT` keys |
| Spec document | Rename Group 2 from "Audit Primacy" to "Integrity Primacy" |
| Corpus specimens | Update any specimens using old decorator names |
| Test assertions | Update decorator name references |

### Migration order

1. Rename decorator functions in `decorators/audit.py` and `decorators/authority.py`
2. Update `REGISTRY` keys in `core/registry.py`
3. Update `BODY_EVAL_TAINT` and `RETURN_TAINT` in `scanner/taint/function_level.py`
4. Update PY-WL-006 heuristic in `scanner/rules/py_wl_006.py`
5. Rename spec Group 2 from "Audit Primacy" to "Integrity Primacy"
6. Update tests and corpus specimens
7. Verify: `uv run pytest`, `uv run wardline corpus verify --json`

## Related Decisions

- **Depends on**: ADR-001 (taint state rename — establishes INTEGRAL vocabulary)
- **Affects**: PY-WL-006 rule heuristic (audit-name detection)

## References

- Wardline spec §5.2: Decorator definitions
- Wardline spec §5.2.2: Group 2 "Audit Primacy" (to be renamed)
- ADR-001: Rename taint state tokens to posture vocabulary
- Session analysis: First-principles terminology review (2026-03-28)
