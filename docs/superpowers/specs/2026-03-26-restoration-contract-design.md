# Restoration Contract Design

**Date:** 2026-03-26
**Status:** Approved (revised after 7-panel review)
**Spec requirements:** WL-FIT-CORE-007, WL-FIT-PY-004

## Problem

The restoration contract — the mechanism by which serialised data regains trust — is entirely unenforced. The infrastructure exists (overlay schema, `BoundaryEntry.restored_tier`, `BoundaryEntry.provenance`) but:

1. **No `@restoration_boundary` decorator** — Group 17 is unregistered and unimplemented. SCN-021 already references it in contradiction checks, but the library cannot produce it.
2. **No evidence matrix enforcement** — The §5.3 table (4 evidence categories → maximum restorable tier) has no implementation. A restoration boundary claiming `restored_tier: 1` with only structural evidence is not flagged.
3. **No taint demotion** — The scanner assigns `UNKNOWN_RAW` to `@int_data` functions by fallback, not by design. Composition with `@restoration_boundary` cannot produce a higher tier because no taint assignment logic exists for it.

## Decisions

- **Both enforcement levels.** Coherence-level (overlay evidence vs matrix) AND scanner-level (decorator evidence → taint demotion). No deferral.
- **Tier 1 restoration is permitted** per §5.3 normative text, requiring all 4 evidence categories. The Architect recommended capping at Tier 2; the spec explicitly allows Tier 1 with full evidence.
- **Group 17** (not 16). §6 defines Group 16 as "Generic Trust Boundary" (data_flow); Group 17 is "Restoration Boundaries."
- **Special-case taint branch.** `restoration_boundary` does NOT go in `BODY_EVAL_TAINT`/`RETURN_TAINT` static maps. A special-case branch in `taint_from_annotations()` calls `max_restorable_tier()` with evidence from decorator attrs.
- **No runtime tier stamping.** `_compute_output_tier()` returns `None` for restoration boundaries. Taint assignment is scanner-only. Document this explicitly.
- **Cross-layer reconciliation.** Scanner compares decorator evidence attrs against overlay provenance. Emits finding on divergence. Closes the "Accidental Adversaries" gap identified by Systems Thinker.
- **`object` type in registry** for optional string attrs (`integrity_evidence`, `institutional_provenance`). Pass `None` for absent values, not `""`. Matches `compensatable`'s `_wardline_rollback: object` precedent.

## Design

### Change 1: Registry Entry (Group 17)

Add to `src/wardline/core/registry.py`:

```python
# --- Group 17: Restoration Boundaries ---
"restoration_boundary": RegistryEntry(
    canonical_name="restoration_boundary",
    group=17,
    attrs={
        "_wardline_restoration_boundary": bool,
        "_wardline_restored_tier": int,
        "_wardline_structural_evidence": bool,
        "_wardline_semantic_evidence": bool,
        "_wardline_integrity_evidence": object,
        "_wardline_institutional_provenance": object,
    },
),
```

`integrity_evidence` and `institutional_provenance` use `object` because they are `str | None` — the registry does not perform `isinstance` checks, but `object` documents that any value is accepted (matching `compensatable`'s pattern).

### Change 2: Decorator

New file `src/wardline/decorators/restoration.py`:

```python
def restoration_boundary(
    *,
    restored_tier: int,
    structural_evidence: bool = False,
    semantic_evidence: bool = False,
    integrity_evidence: str | None = None,
    institutional_provenance: str | None = None,
) -> object:
    """Mark a function as a restoration boundary (Group 17, §5.3).

    Restoration boundaries do NOT stamp runtime output tier — taint
    assignment is scanner-only via max_restorable_tier(). The
    _compute_output_tier() path returns None for this decorator.
    """
    if restored_tier not in range(1, 5):
        raise ValueError(f"restored_tier must be 1-4, got {restored_tier}")
    return wardline_decorator(
        17,
        "restoration_boundary",
        _wardline_restoration_boundary=True,
        _wardline_restored_tier=restored_tier,
        _wardline_structural_evidence=structural_evidence,
        _wardline_semantic_evidence=semantic_evidence,
        _wardline_integrity_evidence=integrity_evidence,
        _wardline_institutional_provenance=institutional_provenance,
    )
```

Key points:
- Follows `compensatable(*, rollback)` pattern from `operations.py`
- `restored_tier` validated against 1-4 range
- Optional attrs pass `None` not `""` — no sentinel coercion
- Exported from `decorators/__init__.py`
- Declare `__all__` in the new module

### Change 3: Evidence Matrix

New file `src/wardline/core/evidence.py`:

```python
from wardline.core.taints import TaintState

def max_restorable_tier(
    structural: bool,
    semantic: bool,
    integrity: bool,
    institutional: bool,
) -> TaintState:
    """Return the maximum tier evidence supports per §5.3.

    The integrity parameter should be coerced to bool by the caller:
    any of "checksum"/"signature"/"hmac" → True, None → False.
    The original string value is preserved in decorator attrs for
    governance audit trail.

    Institutional evidence is the gate between known-provenance tiers
    (T1-T3) and unknown-provenance states (UNKNOWN_*).
    """
    if not structural:
        return TaintState.UNKNOWN_RAW
    if not institutional:
        if semantic:
            return TaintState.UNKNOWN_SEM_VALIDATED
        return TaintState.UNKNOWN_SHAPE_VALIDATED
    # institutional is True from here
    if semantic and integrity:
        return TaintState.AUDIT_TRAIL          # Tier 1
    if semantic:
        return TaintState.PIPELINE             # Tier 2
    return TaintState.SHAPE_VALIDATED          # Tier 3
```

**Off-table combinations:** When `structural=False`, all other flags are irrelevant — result is always `UNKNOWN_RAW`. When `institutional=False`, integrity is irrelevant — result is `UNKNOWN_SHAPE_VALIDATED` or `UNKNOWN_SEM_VALIDATED` based on semantic only. The spec gap `(S=T, Sem=T, I=T, Inst=F)` returns `UNKNOWN_SEM_VALIDATED` per the institutional-gate invariant.

**Location:** `src/wardline/core/evidence.py` in the `core/` package alongside `taints.py`, `tiers.py`, `matrix.py`. Pure domain logic with no scanner or manifest dependencies.

### Change 4: Coherence Check — Evidence Validation

New function `check_restoration_evidence()` in `src/wardline/manifest/coherence.py`:

For each boundary where `transition == "restoration"` and `restored_tier` is not None:
1. Extract evidence from `boundary.provenance` (`structural`, `semantic`, `integrity`, `institutional`)
2. Call `max_restorable_tier()` to get evidence-supported ceiling
3. Map the ceiling `TaintState` to a tier number via `TAINT_TO_TIER`
4. If `boundary.restored_tier` exceeds the evidence-supported tier → `CoherenceIssue` with `kind="insufficient_restoration_evidence"`, severity ERROR

Register in `COHERENCE_SEVERITY_MAP` as `"ERROR"` and `CATEGORY_MAP` as `"enforcement"`.

Wire into `coherence_cmd.py` alongside the existing 12 checks (becomes check 13).

Skip boundaries where `restored_tier is None` (no claim to validate) or `provenance is None` (no evidence to check — handled separately by `check_validation_scope_presence` for semantic evidence).

### Change 5: Scanner Taint Assignment

Modify `src/wardline/scanner/taint/function_level.py`:

Add a special-case branch in `taint_from_annotations()` (NOT a `BODY_EVAL_TAINT`/`RETURN_TAINT` map entry):

When the function has `_wardline_restoration_boundary=True` in its annotation attrs:
1. Extract evidence booleans from annotation attrs
2. Coerce `_wardline_integrity_evidence` to bool (truthy string → True, None → False)
3. Coerce `_wardline_institutional_provenance` to bool (truthy string → True, None → False)
4. Call `max_restorable_tier(structural, semantic, integrity, institutional)`
5. Use result as the function's effective taint state (both body and return)

If `_wardline_int_data=True` is also present, the composition produces `max_restorable_tier(evidence)` — not `UNKNOWN_RAW`. If only `_wardline_int_data=True` (no restoration boundary), the existing fallback to `UNKNOWN_RAW` applies (document this as intentional, not coincidental).

### Change 6: Cross-Layer Reconciliation

New coherence function `check_restoration_evidence_consistency()` in `coherence.py`:

For each restoration boundary, compare the overlay's `provenance` evidence against the decorator's evidence attrs (available via `WardlineAnnotation.attrs` from discovery). If the decorator claims higher evidence than the overlay declares → `CoherenceIssue` with `kind="restoration_evidence_divergence"`, severity WARNING.

This closes the "Accidental Adversaries" gap: overlay and decorator evidence are authored independently but must agree. The overlay is the governance source of truth; the decorator must not exceed it.

Register in `COHERENCE_SEVERITY_MAP` and `CATEGORY_MAP`.

### Change 7: SCN-021 Additional Contradiction

Add to `scn_021.py`:

```python
_CombinationSpec(
    "external_boundary",
    "restoration_boundary",
    _CONTRADICTORY,
    "External boundaries receive new untrusted data; "
    "restoration reconstructs previously-known data",
),
```

Existing `tier1_read + restoration_boundary` and `audit_writer + restoration_boundary` entries are already present and correct.

### Change 8: PY-WL-008 Restoration Boundaries

`py_wl_008.py` already recognises `"restoration"` as a `_BOUNDARY_TRANSITIONS` token. Verify this works with the new decorator — restoration boundaries must have rejection paths (structural verification per §5.3). No code change expected, but add explicit tests.

## Test Plan

### Evidence Matrix (`test_evidence.py`)

Parametrize all 16 boolean combinations (4 booleans = 16 inputs):

| Category | Cases | Expected |
|----------|-------|----------|
| 6 spec-table rows | Full evidence → AUDIT_TRAIL, no integrity → PIPELINE, no semantic → SHAPE_VALIDATED, no institutional+semantic → UNKNOWN_SEM_VALIDATED, no institutional → UNKNOWN_SHAPE_VALIDATED, nothing → UNKNOWN_RAW | Per §5.3 |
| 10 off-table rows | All combinations where `structural=False` with any downstream True, plus `(T,T,T,F)` | `UNKNOWN_RAW` for structural=False; `UNKNOWN_SEM_VALIDATED` for `(T,T,T,F)` per institutional-gate invariant |

Encode the table independently from the implementation (follow `test_matrix.py` discipline). Add a fixture count assertion.

### Registry (`test_registry.py`)

- Entry exists with canonical_name `"restoration_boundary"`, group 17
- All 6 attrs present with correct types
- Registry count incremented

### Decorator (`test_restoration.py`)

- Sets all `_wardline_*` attrs correctly
- `restored_tier` out of range (0, 5) raises `ValueError`
- Works with async and sync functions
- Stacks with `@int_data` (both orderings produce same attrs)
- `_wardline_groups` accumulates correctly
- `_compute_output_tier()` returns `None` (no runtime tier stamping)
- Optional attrs default to `None` not `""`

### Coherence — Evidence Validation (`test_coherence.py`)

- `restored_tier=1` with full evidence → no issue
- `restored_tier=1` with only structural → ERROR (insufficient)
- `restored_tier=2` with structural+semantic+institutional → no issue
- `restored_tier=3` with structural+institutional → no issue
- `restored_tier=None` → skipped (no claim)
- `provenance=None` → skipped
- `restored_tier` exactly equals evidence ceiling → no issue (boundary case)
- `restored_tier` one above ceiling → ERROR

### Coherence — Evidence Consistency (`test_coherence.py`)

- Decorator and overlay evidence match → no issue
- Decorator claims higher than overlay → WARNING
- Decorator claims lower than overlay → no issue (conservative)

### Taint Assignment (`test_function_level.py`)

- `@int_data` alone → `UNKNOWN_RAW` (explicit test, not fallback)
- `@int_data + @restoration_boundary(full evidence)` → `AUDIT_TRAIL`
- `@int_data + @restoration_boundary(structural only)` → `UNKNOWN_SHAPE_VALIDATED`
- `@restoration_boundary(full evidence)` alone → `AUDIT_TRAIL`
- `@restoration_boundary(no evidence)` alone → `UNKNOWN_RAW`

### Discovery (`test_discovery.py`)

- AST extraction of keyword args from `@restoration_boundary(restored_tier=1, structural_evidence=True, ...)`
- Verify all 5 kwargs extracted correctly

### SCN-021 (`test_scn_021.py`)

- `external_boundary + restoration_boundary` → contradictory (new entry)
- Existing `tier1_read + restoration_boundary` → still fires
- Existing `audit_writer + restoration_boundary` → still fires

### PY-WL-008 (`test_py_wl_008.py`)

- Restoration boundary with rejection path → no finding
- Restoration boundary without rejection path → finding

## Files Touched

**New files:**
- `src/wardline/core/evidence.py`
- `src/wardline/decorators/restoration.py`
- `tests/unit/core/test_evidence.py`
- `tests/unit/decorators/test_restoration.py`

**Modified production code:**
- `src/wardline/core/registry.py` (Group 17 entry)
- `src/wardline/decorators/__init__.py` (export)
- `src/wardline/manifest/coherence.py` (2 new check functions)
- `src/wardline/cli/coherence_cmd.py` (wiring + maps)
- `src/wardline/cli/_helpers.py` (COHERENCE_SEVERITY_MAP entries)
- `src/wardline/scanner/taint/function_level.py` (special-case branch)
- `src/wardline/scanner/rules/scn_021.py` (external_boundary entry)

**Modified tests:**
- `tests/unit/manifest/test_coherence.py`
- `tests/unit/scanner/test_function_level.py` (or equivalent taint test)
- `tests/unit/scanner/test_scn_021.py`
- `tests/unit/scanner/test_py_wl_008.py`
- `tests/unit/scanner/test_discovery.py`
- `tests/unit/core/test_registry.py` (count update)

## Out of scope

- Constraining `institutional_provenance` to a closed enum of attestation types (improvement for governance, not spec-required).
- Preventing rule overrides from suppressing PY-WL-008 for restoration boundaries (would require merge-level restriction).
- Runtime tier stamping for restoration boundaries (scanner-only enforcement per design decision).
- Group 16 (data_flow) decorator implementation (separate gap).
