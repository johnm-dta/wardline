# ADR-002: Rename tier-source decorators to match posture vocabulary

**Status**: Proposed
**Date**: 2026-03-28
**Deciders**: Project Lead, Review Board
**Context**: Tier-source decorator names use audit-specific language inherited from the prototype exemplar

## Summary

Rename four tier-source and tier-critical decorators from audit-specific
names (`@audit_writer`, `@audit_critical`, `@tier1_read`,
`@authoritative_construction`) to posture-based names (`@strict_writer`,
`@integrity_critical`, `@strict_read`, `@strict_construction`) that align
with the taint state rename in ADR-001.

Validation-transition decorators (`@validates_shape`, `@validates_semantic`,
`@validates_external`, `@external_boundary`) are unchanged — they describe
the transition action, not the tier.

**This ADR changes decorator names only. It does not change decorator
semantics, `_wardline_*` attribute contracts, or boundary transition types.**

## Context

The wardline decorator library provides two categories of decorators:

1. **Tier-source decorators** — mark functions that produce or consume
   data at a specific tier level. These reference the tier by name.
2. **Validation-transition decorators** — mark functions that perform
   validation, transforming data from one tier to another. These
   reference the transition action.

With ADR-001 renaming taint states from prototype names to posture
vocabulary (AUDIT_TRAIL -> STRICT, PIPELINE -> ASSURED), the tier-source
decorators must track the rename. The current names:

| Decorator | Problem |
|-----------|---------|
| `@audit_writer` | Suggests only audit-log writes, not all T1 authoritative writes |
| `@audit_critical` | Suggests audit-log criticality, not integrity-critical code paths |
| `@tier1_read` | Uses tier number — adequate but inconsistent with posture vocabulary |
| `@authoritative_construction` | Already good — but should track to `strict_` prefix for consistency |

The validation decorators (`@validates_shape`, `@validates_semantic`,
`@validates_external`, `@external_boundary`) describe what the function
*does* (validates shape, validates semantics), not what tier it belongs to.
They don't reference tier names and don't need renaming.

### Why rename decorators alongside taint states

Decorators are user-facing API. If taint states become STRICT/ASSURED/
GUARDED/UNTRUSTED but decorators still say `@audit_writer`, adopters see
two vocabularies for the same concept. The pre-v1.0 window that makes
the taint state rename free also makes the decorator rename free.

### PY-WL-006 impact

PY-WL-006 ("Audit-critical writes in broad exception handlers") uses
heuristic detection based on the names `audit*`, `record*`, `emit*`.
The decorator rename from `@audit_writer`/`@audit_critical` to
`@strict_writer`/`@integrity_critical` means PY-WL-006's heuristic must
also be updated to match the new decorator names, or refactored to use
the `_wardline_*` attribute contract instead of name-based detection.

## Decision

Rename four decorators:

| Current | New | Rationale |
|---------|-----|-----------|
| `@audit_writer` | `@strict_writer` | Follows T1 rename to STRICT; drops audit-specific framing |
| `@audit_critical` | `@integrity_critical` | The concern is data integrity, not audit-log criticality |
| `@tier1_read` | `@strict_read` | Posture name instead of tier number |
| `@authoritative_construction` | `@strict_construction` | Consistency with `strict_` prefix |

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
`@audit_writer` means "T1/STRICT writer."

**Pros**:
- Zero migration effort
- No risk of breaking adopter code

**Cons**:
- Adopters see `@audit_writer` on code that has nothing to do with auditing
- Two vocabularies: taint states say STRICT, decorators say audit
- New adopter confusion: "I don't have an audit trail, do I need this?"

**Why rejected**: Pre-v1.0, zero adopters. The documentation workaround
creates the same "don't read the name literally" problem that ADR-001
eliminates for taint states.

### Alternative 2: Use tier-number decorators

**Description**: `@tier1_writer`, `@tier1_critical`, `@tier1_read`,
`@tier1_construction`

**Pros**:
- Simple, unambiguous
- tier1_read already exists

**Cons**:
- Tier numbers are less meaningful than posture names
- "tier1_critical" doesn't communicate *why* it's critical
- Inconsistent with the posture vocabulary in ADR-001

**Why rejected**: Posture names (`strict_writer`) communicate intent
better than tier numbers (`tier1_writer`). The whole point of ADR-001
is that names should describe the coding discipline, not an abstract
numbering.

### Alternative 3: Deprecation cycle with aliases

**Description**: Add new names as aliases, deprecate old names with
warnings, remove old names in v2.0.

**Pros**:
- Backwards-compatible
- Adopters can migrate gradually

**Cons**:
- Complexity: two names for every decorator during transition
- Pre-v1.0 with zero adopters — there's nobody to deprecate for
- The alias machinery becomes permanent maintenance burden

**Why rejected**: Deprecation cycles are for breaking changes to
existing users. There are no existing users.

## Consequences

### Positive

- Decorator names match taint state vocabulary (STRICT)
- `@integrity_critical` immediately communicates "data integrity failure
  if this goes wrong" — domain-neutral, works for defence, healthcare,
  finance
- Consistent `strict_` prefix for all T1 decorators
- `@authoritative_construction` → `@strict_construction` removes
  the one inconsistency in the existing naming

### Negative

- PY-WL-006 heuristic detection needs updating for new decorator names
- Four decorator definitions, their tests, and the registry need renaming
- Any documentation referencing old decorator names needs updating
- `@integrity_critical` is the only decorator not using the `strict_`
  prefix — it's named for the *consequence* (integrity failure) rather
  than the *zone* (strict). This is intentional: it marks code where
  the integrity concern is the defining characteristic, not just the
  tier assignment.

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
| `scanner/rules/py_wl_006.py` | Update `_AUDIT_DECORATORS` set |
| `scanner/taint/function_level.py` | Update `BODY_EVAL_TAINT` / `RETURN_TAINT` keys |
| Corpus specimens | Update any specimens using old decorator names |
| Test assertions | Update decorator name references |

### Migration order

1. Rename decorator functions in `decorators/audit.py` and `decorators/authority.py`
2. Update `REGISTRY` keys in `core/registry.py`
3. Update `BODY_EVAL_TAINT` and `RETURN_TAINT` in `scanner/taint/function_level.py`
4. Update PY-WL-006 heuristic in `scanner/rules/py_wl_006.py`
5. Update tests and corpus specimens
6. Verify: `uv run pytest`, `uv run wardline corpus verify --json`

## Related Decisions

- **Depends on**: ADR-001 (taint state rename — establishes STRICT vocabulary)
- **Affects**: PY-WL-006 rule heuristic (audit-name detection)

## References

- Wardline spec §5.2: Decorator definitions
- ADR-001: Rename taint state tokens to posture vocabulary
- Session analysis: First-principles terminology review (2026-03-28)
