# ADR-001: Rename taint state tokens from prototype names to posture vocabulary

**Status**: Proposed
**Date**: 2026-03-28
**Deciders**: Project Lead, Review Board
**Context**: Canonical taint state tokens use prototype-era names that misrepresent their semantic scope

## Summary

Rename the four canonical taint state tokens and two compound states from
prototype-specific names (AUDIT_TRAIL, PIPELINE) to posture-based names
(STRICT, ASSURED, GUARDED, UNTRUSTED) that describe the coding discipline
required in each trust zone. This aligns the machine-readable tokens with the
spec's own conceptual model (§4.1 coding postures) and removes the need for
the defensive §5.1 NOTE warning adopters not to read the names literally.

**This ADR changes canonical token names only. It does not change tier
semantics, the join lattice, the severity matrix structure, or boundary
transition types.**

## Context

The wardline spec defines a four-tier trust hierarchy where each tier
prescribes a coding posture — a set of rules governing how code in that
zone must behave. The spec (§4.1) names these postures: strict,
governance-assured, structure-verified, untrusted-input.

However, the canonical taint state tokens — the machine-readable identifiers
used in manifests, SARIF output, severity matrix keys, and corpus specimens —
use names inherited from the prototype's orchestration-system exemplar:

| Tier | Current token | §4.1 posture | Problem |
|------|--------------|-------------|---------|
| T1 | `AUDIT_TRAIL` | Strict | Suggests audit logging, not high-integrity code paths |
| T2 | `PIPELINE` | Governance-assured | Suggests data pipelines/ETL, not validated data |
| T3 | `SHAPE_VALIDATED` | Structure-verified | Adequate — describes data state accurately |
| T4 | `EXTERNAL_RAW` | Untrusted-input | Adequate — describes provenance and status |

The spec already contains a normative workaround in §5.1:

> NOTE — Token names are canonical labels, not scope restrictions.
> AUDIT_TRAIL encompasses all Tier 1 authoritative internal data [...],
> not only audit trails specifically. [...] These names are historical;
> implementations MUST NOT narrow their semantics to match the everyday
> meaning of the token name.

When a spec needs a normative note saying "don't read the name literally,"
the name is wrong.

The asymmetry is telling: T3 (`SHAPE_VALIDATED`) and T4 (`EXTERNAL_RAW`)
describe what the data *is*. T1 (`AUDIT_TRAIL`) and T2 (`PIPELINE`) describe
what the *prototype used them for*.

### Why now

- Pre-v1.0 with zero external adopters — migration cost is at its absolute
  minimum
- Every adopter manifest, CI config, and SARIF consumer written against
  the current names becomes migration debt after v1.0
- The corpus has 244 specimens organized by taint state directory names —
  today that's our corpus, post-v1.0 it's everyone's
- A schema migration between token sets requires versioning and
  backwards-compatibility shims after v1.0; before v1.0 it's a
  find-and-replace

### Framing decision: posture, not data classification

The tokens should describe the **coding posture** — how code and data must
behave in that zone — not the data classification. This matches the mental
model of marking code regions with special rules, analogous to designating
code paths as thread-safe or high-availability. The spec's §4.1 posture
vocabulary already provides the names.

The one exception is `RAW`, which describes a **data state** ("we don't
know what we have yet — could be noise, null, or something that evaluates
into an exception"). RAW has a clear semantic meaning not captured elsewhere
in the spec. Raw data operates under untrusted rules, but the word carries
the additional meaning of "unexamined, potentially garbage." This distinction
is preserved in the compound states.

## Decision

Rename all taint state tokens to the posture vocabulary:

### Primary taint states

| Current | New | Rationale |
|---------|-----|-----------|
| `AUDIT_TRAIL` | `STRICT` | Invariant violation is an integrity failure, not a recoverable condition |
| `PIPELINE` | `ASSURED` | Values trusted within their declared validation scope |
| `SHAPE_VALIDATED` | `GUARDED` | Structure trusted, semantic values not yet verified |
| `EXTERNAL_RAW` | `EXTERNAL_RAW` | Keep — RAW describes data state (unexamined), EXTERNAL describes provenance |

### Compound taint states

| Current | New | Rationale |
|---------|-----|-----------|
| `UNKNOWN_RAW` | `UNKNOWN_RAW` | Keep — both terms accurate |
| `UNKNOWN_SHAPE_VALIDATED` | `UNKNOWN_GUARDED` | Tracks tier rename |
| `UNKNOWN_SEM_VALIDATED` | `UNKNOWN_ASSURED` | Tracks tier rename |
| `MIXED_RAW` | `MIXED_RAW` | Keep — both terms accurate |

### What does not change

- Tier numeric ordering (T1 > T2 > T3 > T4)
- The join lattice and `taint_join()` semantics
- The severity matrix structure (9 rules x 8 taint states)
- Boundary transition types (shape_validation, semantic_validation, etc.)
- The `AuthorityTier` IntEnum (Tier 1-4 numbering)
- Rule semantics and detection patterns
- Exception register semantics

## Alternatives Considered

### Alternative 1: Rename only T1 and T2

**Description**: Fix only the broken names (AUDIT_TRAIL, PIPELINE), leave
SHAPE_VALIDATED and EXTERNAL_RAW as-is.

**Pros**:
- Smaller blast radius
- T3 and T4 names are adequate

**Cons**:
- Inconsistent vocabulary: T1/T2 use posture framing, T3/T4 use
  data-classification framing
- Two mental models in one token set
- §5.1 NOTE can only be partially deleted

**Why rejected**: The migration cost for T3/T4 is the same (mechanical
find-and-replace) and the inconsistency undermines the clarity the rename
is trying to achieve. If we're going to do this, do it once.

### Alternative 2: Use data-classification names throughout

**Description**: AUTHORITATIVE / SEM_VALIDATED / SHAPE_VALIDATED / EXTERNAL_RAW

**Pros**:
- AUTHORITATIVE is already used in the spec
- SEM_VALIDATED creates symmetry with SHAPE_VALIDATED
- Smaller conceptual shift

**Cons**:
- "What the data is" doesn't capture the key insight: these are coding
  postures, not data labels
- Doesn't match the §4.1 posture vocabulary that the spec already defines
- A developer seeing `AUTHORITATIVE` still asks "authoritative *what*?"
  while `STRICT` immediately communicates "this zone has strict rules"

**Why rejected**: The posture framing better matches how developers think
about trust zones. STRICT/ASSURED/GUARDED/UNTRUSTED tells a
descending-trust story that's immediately intuitive without reading the
spec.

### Alternative 3: Do nothing, keep §5.1 NOTE

**Description**: Accept the current names and rely on the normative NOTE
to prevent misinterpretation.

**Pros**:
- Zero migration effort
- No risk of introducing bugs during rename

**Cons**:
- Every adopter onboarding includes "ignore what the names say"
- The §5.1 NOTE does load-bearing work that the names should do themselves
- Naming confusion compounds with every external deployment
- The cost of renaming only increases after v1.0

**Why rejected**: Pre-v1.0 is the only window where this rename is free.
After v1.0, it requires schema versioning, backwards-compatibility shims,
and a deprecation cycle.

## Consequences

### Positive

- Token names match the spec's own conceptual vocabulary (§4.1 postures)
- §5.1 defensive NOTE can be deleted entirely
- Descending-trust story (STRICT > ASSURED > GUARDED > UNTRUSTED) is
  self-documenting
- Adopters in defence, healthcare, and financial services are not
  misdirected by "audit trail" framing
- RAW retains its distinct semantic meaning for unexamined data

### Negative

- One-time migration cost across code (~60 references), schemas (3 JSON
  Schema files), corpus (specimen directory names), manifest, and tests
- Existing development notes and design documents reference old names
- Any external tooling consuming SARIF `wardline.taintState` properties
  must update (mitigated: zero external adopters pre-v1.0)

### Neutral

- The `AuthorityTier` IntEnum is unaffected (uses numeric tiers, not
  taint state names)
- Boundary transition names (`shape_validation`, `semantic_validation`)
  are unaffected — they describe the transition action, not the tier

## Implementation Notes

### Blast radius

| Artifact | Estimated changes |
|----------|------------------|
| `TaintState` enum in `core/taints.py` | 8 member renames |
| `TAINT_TO_TIER` mapping in `core/taints.py` | 8 key renames |
| `SEVERITY_MATRIX` in `core/matrix.py` | ~72 cell key updates |
| JSON schemas (3 files) | Enum value lists |
| `wardline.yaml` module_tiers | `default_taint` values |
| Corpus specimen directories | ~30 directory renames |
| Corpus specimen YAML files | `taint_state` field values |
| `corpus_manifest.json` | Regenerate |
| Exception register | `taint_state` field values |
| Test assertions | String comparisons |
| SARIF property values | Runtime output (no code change) |

### Migration strategy

1. Rename `TaintState` enum members (source of truth)
2. Update `TAINT_TO_TIER`, `SEVERITY_MATRIX`, `taint_join()`
3. Update JSON schemas
4. Rename corpus specimen directories and YAML `taint_state` values
5. Update `wardline.yaml` module_tiers
6. Migrate exception register taint_state values
7. Update test assertions
8. Regenerate `corpus_manifest.json`
9. Delete §5.1 defensive NOTE from spec

### Verification

- `uv run pytest` — all tests pass
- `uv run wardline corpus verify --json` — 72/72 PASS
- `uv run wardline scan src/wardline --manifest wardline.yaml` — no
  regressions in finding count or taint distribution

## Related Decisions

- **Related to**: ADR-002 (decorator rename — tracks taint state rename
  for tier-source decorators)
- **Tracked by**: `wardline-a660040169` (--migrate-mvp requirement)

## References

- Wardline spec §4.1: Tier definitions and coding postures
- Wardline spec §5.1: Canonical taint state tokens (contains defensive NOTE)
- Session analysis: First-principles terminology review (2026-03-28)
