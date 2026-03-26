# Restoration Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the restoration contract — decorator, evidence matrix, coherence checks, and scanner taint assignment — so that serialised data can regain trust based on declared evidence per §5.3.

**Architecture:** Group 17 registry entry + `@restoration_boundary(...)` decorator with evidence parameters → pure `max_restorable_tier()` function in `core/evidence.py` → two coherence checks (evidence validation + cross-layer reconciliation) → special-case taint branch in `function_level.py`. No runtime tier stamping.

**Tech Stack:** Python 3.12+, frozen dataclasses, MappingProxyType, pytest parametrize, AST discovery.

---

### Task 1: Evidence Matrix (`core/evidence.py`)

**Files:**
- Create: `src/wardline/core/evidence.py`
- Create: `tests/unit/core/test_evidence.py`

This is the pure domain function with no dependencies beyond `TaintState`. Build and test it first — everything else consumes it.

- [ ] **Step 1: Write the full 16-combination parametrized test**

```python
# tests/unit/core/test_evidence.py
"""Tests for the §5.3 evidence-to-tier matrix.

The expected values are encoded directly from the spec, not imported
from the implementation. This follows the test_matrix.py discipline
of independent oracle encoding.
"""
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState

# Do NOT import max_restorable_tier at module level — the test fixture
# must be independent of the implementation.

# §5.3 evidence matrix: 6 defined rows + 10 off-table rows.
# Off-table rows all resolve to the most conservative applicable state.
EVIDENCE_MATRIX = [
    # --- 6 spec-table rows ---
    # (structural, semantic, integrity, institutional, expected)
    (True, True, True, True, TaintState.AUDIT_TRAIL),            # T1: full evidence
    (True, True, False, True, TaintState.PIPELINE),              # T2: no integrity
    (True, False, False, True, TaintState.SHAPE_VALIDATED),      # T3: no semantic
    (True, True, False, False, TaintState.UNKNOWN_SEM_VALIDATED),  # no institutional, has semantic
    (True, False, False, False, TaintState.UNKNOWN_SHAPE_VALIDATED),  # structural only
    (False, False, False, False, TaintState.UNKNOWN_RAW),        # no evidence
    # --- Off-table: structural=False with downstream True ---
    (False, True, False, False, TaintState.UNKNOWN_RAW),
    (False, False, True, False, TaintState.UNKNOWN_RAW),
    (False, False, False, True, TaintState.UNKNOWN_RAW),
    (False, True, True, False, TaintState.UNKNOWN_RAW),
    (False, True, False, True, TaintState.UNKNOWN_RAW),
    (False, False, True, True, TaintState.UNKNOWN_RAW),
    (False, True, True, True, TaintState.UNKNOWN_RAW),
    # --- Off-table: structural=True, institutional-gate invariant ---
    (True, True, True, False, TaintState.UNKNOWN_SEM_VALIDATED),  # integrity ignored without institutional
    (True, False, True, False, TaintState.UNKNOWN_SHAPE_VALIDATED),  # integrity ignored without institutional
    (True, False, True, True, TaintState.SHAPE_VALIDATED),       # T3: integrity alone doesn't add semantic
]


@pytest.mark.parametrize(
    "structural,semantic,integrity,institutional,expected",
    EVIDENCE_MATRIX,
    ids=[
        "full_evidence_T1",
        "no_integrity_T2",
        "no_semantic_T3",
        "no_institutional_sem_UNKNOWN_SEM",
        "structural_only_UNKNOWN_SHAPE",
        "no_evidence_UNKNOWN_RAW",
        "no_structural_with_semantic",
        "no_structural_with_integrity",
        "no_structural_with_institutional",
        "no_structural_with_sem_int",
        "no_structural_with_sem_inst",
        "no_structural_with_int_inst",
        "no_structural_with_all_downstream",
        "institutional_gate_sem_int_no_inst",
        "institutional_gate_int_no_inst",
        "integrity_without_semantic_T3",
    ],
)
def test_evidence_matrix(
    structural: bool,
    semantic: bool,
    integrity: bool,
    institutional: bool,
    expected: TaintState,
) -> None:
    from wardline.core.evidence import max_restorable_tier

    assert max_restorable_tier(structural, semantic, integrity, institutional) == expected


def test_fixture_has_16_cells() -> None:
    """Guard: if the spec adds a row, this test reminds us to update."""
    assert len(EVIDENCE_MATRIX) == 16
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/core/test_evidence.py -v --tb=short`
Expected: FAIL with `ModuleNotFoundError: No module named 'wardline.core.evidence'`

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/core/evidence.py
"""§5.3 evidence-to-tier matrix — pure domain function.

Maps the four restoration evidence categories to the maximum tier the
evidence supports. Consumed by coherence checks (manifest validation)
and scanner taint assignment (decorator evidence → effective taint).
"""

from __future__ import annotations

from wardline.core.taints import TaintState


def max_restorable_tier(
    structural: bool,
    semantic: bool,
    integrity: bool,
    institutional: bool,
) -> TaintState:
    """Return the maximum tier evidence supports per §5.3.

    The caller coerces string evidence values to bool before calling:
    ``integrity_evidence="hmac"`` → ``integrity=True``,
    ``integrity_evidence=None`` → ``integrity=False``.
    The original string value is preserved in decorator attrs for
    governance audit trail.

    Institutional evidence is the gate between known-provenance tiers
    (T1–T3) and unknown-provenance states (UNKNOWN_*). Without it,
    only UNKNOWN states are reachable regardless of other evidence.
    """
    if not structural:
        return TaintState.UNKNOWN_RAW
    if not institutional:
        if semantic:
            return TaintState.UNKNOWN_SEM_VALIDATED
        return TaintState.UNKNOWN_SHAPE_VALIDATED
    # institutional is True from here
    if semantic and integrity:
        return TaintState.AUDIT_TRAIL  # Tier 1
    if semantic:
        return TaintState.PIPELINE  # Tier 2
    return TaintState.SHAPE_VALIDATED  # Tier 3
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/core/test_evidence.py -v`
Expected: 17 passed

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/evidence.py tests/unit/core/test_evidence.py
git commit -m "Add §5.3 evidence-to-tier matrix with 16-combination tests"
```

---

### Task 2: Registry Entry (Group 17)

**Files:**
- Modify: `src/wardline/core/registry.py` (add entry before closing `}`)
- Modify: `tests/unit/core/test_registry.py` (update count)

- [ ] **Step 1: Write the registry entry**

In `src/wardline/core/registry.py`, add before the closing `})` at line 190:

```python
    # --- Group 17: Restoration Boundaries ---
    "restoration_boundary": RegistryEntry(
        canonical_name="restoration_boundary",
        group=17,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_restoration_boundary": bool,
            "_wardline_restored_tier": int,
            "_wardline_structural_evidence": bool,
            "_wardline_semantic_evidence": bool,
            "_wardline_integrity_evidence": object,
            "_wardline_institutional_provenance": object,
        },
    ),
```

- [ ] **Step 2: Update registry count test**

In `tests/unit/core/test_registry.py`, change:
```python
assert len(REGISTRY) == 38
```
to:
```python
assert len(REGISTRY) == 39
```

Update the docstring from "38 decorators" to "39 decorators".

- [ ] **Step 3: Run tests**

Run: `python -m pytest tests/unit/core/test_registry.py -v --tb=short`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/wardline/core/registry.py tests/unit/core/test_registry.py
git commit -m "Register restoration_boundary as Group 17 in canonical registry"
```

---

### Task 3: Decorator (`decorators/restoration.py`)

**Files:**
- Create: `src/wardline/decorators/restoration.py`
- Modify: `src/wardline/decorators/__init__.py` (add import + export)
- Create: `tests/unit/decorators/test_restoration.py`

- [ ] **Step 1: Write tests**

```python
# tests/unit/decorators/test_restoration.py
"""Tests for @restoration_boundary decorator (Group 17)."""
from __future__ import annotations

import asyncio

import pytest

from wardline.decorators.provenance import int_data
from wardline.decorators.restoration import restoration_boundary


class TestRestorationBoundary:
    """@restoration_boundary decorator behaviour."""

    def test_sets_all_attrs(self) -> None:
        @restoration_boundary(
            restored_tier=1,
            structural_evidence=True,
            semantic_evidence=True,
            integrity_evidence="hmac",
            institutional_provenance="org-db",
        )
        def restore(raw: bytes) -> object: ...

        assert restore._wardline_restoration_boundary is True  # type: ignore[attr-defined]
        assert restore._wardline_restored_tier == 1  # type: ignore[attr-defined]
        assert restore._wardline_structural_evidence is True  # type: ignore[attr-defined]
        assert restore._wardline_semantic_evidence is True  # type: ignore[attr-defined]
        assert restore._wardline_integrity_evidence == "hmac"  # type: ignore[attr-defined]
        assert restore._wardline_institutional_provenance == "org-db"  # type: ignore[attr-defined]

    def test_optional_attrs_default_to_none(self) -> None:
        @restoration_boundary(restored_tier=3, structural_evidence=True)
        def restore(raw: bytes) -> object: ...

        assert restore._wardline_semantic_evidence is False  # type: ignore[attr-defined]
        assert restore._wardline_integrity_evidence is None  # type: ignore[attr-defined]
        assert restore._wardline_institutional_provenance is None  # type: ignore[attr-defined]

    def test_restored_tier_validated(self) -> None:
        with pytest.raises(ValueError, match="restored_tier must be 1-4"):
            restoration_boundary(restored_tier=0)

        with pytest.raises(ValueError, match="restored_tier must be 1-4"):
            restoration_boundary(restored_tier=5)

    def test_valid_tier_values(self) -> None:
        for tier in (1, 2, 3, 4):
            @restoration_boundary(restored_tier=tier, structural_evidence=True)
            def restore(raw: bytes) -> object: ...

            assert restore._wardline_restored_tier == tier  # type: ignore[attr-defined]

    def test_async_function(self) -> None:
        @restoration_boundary(restored_tier=2, structural_evidence=True)
        async def restore(raw: bytes) -> object:
            return object()

        assert asyncio.iscoroutinefunction(restore)
        assert restore._wardline_restoration_boundary is True  # type: ignore[attr-defined]

    def test_stacks_with_int_data_inner(self) -> None:
        @restoration_boundary(restored_tier=1, structural_evidence=True)
        @int_data
        def restore(raw: bytes) -> object: ...

        assert restore._wardline_restoration_boundary is True  # type: ignore[attr-defined]
        assert restore._wardline_int_data is True  # type: ignore[attr-defined]
        assert 4 in restore._wardline_groups  # type: ignore[attr-defined]
        assert 17 in restore._wardline_groups  # type: ignore[attr-defined]

    def test_stacks_with_int_data_outer(self) -> None:
        @int_data
        @restoration_boundary(restored_tier=1, structural_evidence=True)
        def restore(raw: bytes) -> object: ...

        assert restore._wardline_restoration_boundary is True  # type: ignore[attr-defined]
        assert restore._wardline_int_data is True  # type: ignore[attr-defined]
        assert 4 in restore._wardline_groups  # type: ignore[attr-defined]
        assert 17 in restore._wardline_groups  # type: ignore[attr-defined]

    def test_groups_accumulates(self) -> None:
        @restoration_boundary(restored_tier=2, structural_evidence=True)
        def restore(raw: bytes) -> object: ...

        assert 17 in restore._wardline_groups  # type: ignore[attr-defined]

    def test_no_runtime_tier_stamping(self) -> None:
        """_compute_output_tier returns None → no tier stamped on result."""
        @restoration_boundary(restored_tier=1, structural_evidence=True)
        def restore(raw: bytes) -> object:
            return {"data": "test"}

        result = restore(b"raw")
        # No _wardline_tier attribute on the return value
        assert not hasattr(result, "_wardline_tier")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/decorators/test_restoration.py -v --tb=short`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the decorator module**

```python
# src/wardline/decorators/restoration.py
"""Group 17 decorator — restoration boundaries (§5.3).

Restoration boundaries govern the act by which raw serialised
representations may be restored to a tier supported by available
evidence. Distinct from Group 4 (int_data), which declares
provenance-sensitive data sources.

Restoration boundaries do NOT stamp runtime output tier — taint
assignment is scanner-only via max_restorable_tier(). The
_compute_output_tier() path returns None for this decorator because
it has no _wardline_transition or _wardline_tier_source.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = ["restoration_boundary"]


def restoration_boundary(
    *,
    restored_tier: int,
    structural_evidence: bool = False,
    semantic_evidence: bool = False,
    integrity_evidence: str | None = None,
    institutional_provenance: str | None = None,
) -> object:
    """Mark a function as a restoration boundary (Group 17, §5.3).

    Args:
        restored_tier: The tier this restoration claims to achieve (1-4).
        structural_evidence: Whether shape validation is performed.
        semantic_evidence: Whether domain constraint checking is performed.
        integrity_evidence: Integrity mechanism name ("checksum", "signature",
            "hmac") or None if absent.
        institutional_provenance: Institutional attestation string or None.
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

- [ ] **Step 4: Add export to `__init__.py`**

In `src/wardline/decorators/__init__.py`, add the import:
```python
from wardline.decorators.restoration import restoration_boundary
```

And add `"restoration_boundary"` to `__all__` (alphabetically, between `"requires_identity"` and `"schema_default"`).

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/unit/decorators/test_restoration.py -v --tb=short`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/decorators/restoration.py src/wardline/decorators/__init__.py tests/unit/decorators/test_restoration.py
git commit -m "Add @restoration_boundary decorator (Group 17)"
```

---

### Task 4: Coherence Check — Evidence Validation

**Files:**
- Modify: `src/wardline/manifest/coherence.py` (add `check_restoration_evidence`)
- Modify: `src/wardline/cli/_helpers.py` (add severity entry)
- Modify: `src/wardline/cli/coherence_cmd.py` (add category + wiring)
- Modify: `tests/unit/manifest/test_coherence.py` (add test class)

- [ ] **Step 1: Write tests**

Add to `tests/unit/manifest/test_coherence.py`:

```python
from wardline.manifest.coherence import check_restoration_evidence

class TestRestorationEvidence:
    """check_restoration_evidence() — §5.3 evidence matrix enforcement."""

    def test_full_evidence_tier_1_passes(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.restore_audit",
            transition="restoration",
            restored_tier=1,
            provenance={
                "structural": True,
                "semantic": True,
                "integrity": "hmac",
                "institutional": "org-db",
            },
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_tier_1_with_only_structural_fails(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=1,
            provenance={"structural": True},
        )
        issues = check_restoration_evidence((boundary,))
        assert len(issues) == 1
        assert issues[0].kind == "insufficient_restoration_evidence"
        assert "mymod.restore" in issues[0].detail

    def test_tier_2_with_sufficient_evidence_passes(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=2,
            provenance={
                "structural": True,
                "semantic": True,
                "institutional": "org-db",
            },
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_tier_3_with_structural_institutional_passes(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=3,
            provenance={"structural": True, "institutional": "org-db"},
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_restored_tier_none_skipped(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=None,
            provenance={"structural": True},
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_provenance_none_skipped(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=2,
            provenance=None,
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_exact_ceiling_passes(self) -> None:
        """restored_tier exactly equals evidence ceiling → no issue."""
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=2,
            provenance={
                "structural": True,
                "semantic": True,
                "institutional": "org-db",
            },
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_one_above_ceiling_fails(self) -> None:
        """restored_tier one above evidence ceiling → ERROR."""
        boundary = BoundaryEntry(
            function="mymod.restore",
            transition="restoration",
            restored_tier=1,
            provenance={
                "structural": True,
                "semantic": True,
                "institutional": "org-db",
            },
        )
        issues = check_restoration_evidence((boundary,))
        assert len(issues) == 1
        assert issues[0].kind == "insufficient_restoration_evidence"

    def test_non_restoration_boundary_skipped(self) -> None:
        boundary = BoundaryEntry(
            function="mymod.validate",
            transition="semantic_validation",
            restored_tier=None,
        )
        assert check_restoration_evidence((boundary,)) == []

    def test_empty_boundaries(self) -> None:
        assert check_restoration_evidence(()) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/manifest/test_coherence.py::TestRestorationEvidence -v --tb=short`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Write the coherence function**

Add to `src/wardline/manifest/coherence.py` after `check_validation_scope_presence`:

```python
def check_restoration_evidence(
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Check that restoration boundaries don't overclaim their tier.

    For each boundary with ``transition == "restoration"`` and a
    non-None ``restored_tier``, compares the claimed tier against the
    maximum tier the declared evidence supports per §5.3.

    Args:
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per overclaim (kind
        ``"insufficient_restoration_evidence"``).
    """
    from wardline.core.evidence import max_restorable_tier
    from wardline.core.tiers import TAINT_TO_TIER

    issues: list[CoherenceIssue] = []
    for boundary in boundaries:
        if boundary.transition != "restoration":
            continue
        if boundary.restored_tier is None or boundary.provenance is None:
            continue

        structural = bool(boundary.provenance.get("structural"))
        semantic = bool(boundary.provenance.get("semantic"))
        integrity = bool(boundary.provenance.get("integrity"))
        institutional = bool(boundary.provenance.get("institutional"))

        ceiling_taint = max_restorable_tier(
            structural, semantic, integrity, institutional,
        )
        ceiling_tier = TAINT_TO_TIER[ceiling_taint].value

        if boundary.restored_tier < ceiling_tier:
            # restored_tier uses lower=better (T1=1), so a lower number
            # is a higher claim. If claimed tier < ceiling tier number,
            # the claim exceeds the evidence.
            issues.append(
                CoherenceIssue(
                    kind="insufficient_restoration_evidence",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' claims "
                        f"restored_tier={boundary.restored_tier} but evidence "
                        f"supports at most tier {ceiling_tier} "
                        f"({ceiling_taint.value}). §5.3 evidence matrix."
                    ),
                )
            )
    return issues
```

- [ ] **Step 4: Register severity and category**

In `src/wardline/cli/_helpers.py`, add to `COHERENCE_SEVERITY_MAP`:
```python
"insufficient_restoration_evidence": "ERROR",
```

In `src/wardline/cli/coherence_cmd.py`, add to `CATEGORY_MAP`:
```python
"insufficient_restoration_evidence": "enforcement",
```

- [ ] **Step 5: Wire the check**

In `src/wardline/cli/coherence_cmd.py`, add the import of `check_restoration_evidence` from `wardline.manifest.coherence`, then add after the existing `check_validation_scope_presence` call:

```python
    all_issues.extend(
        check_restoration_evidence(boundaries)
    )
```

Update the check count comment (13 checks).

- [ ] **Step 6: Run tests**

Run: `python -m pytest tests/unit/manifest/test_coherence.py::TestRestorationEvidence -v --tb=short`
Expected: All pass

Run: `python -m pytest tests/ -x -q --tb=short`
Expected: All pass (no regressions)

- [ ] **Step 7: Commit**

```bash
git add src/wardline/manifest/coherence.py src/wardline/cli/_helpers.py src/wardline/cli/coherence_cmd.py tests/unit/manifest/test_coherence.py
git commit -m "Add check_restoration_evidence coherence check (§5.3 matrix)"
```

---

### Task 5: Scanner Taint Assignment

**Files:**
- Modify: `src/wardline/scanner/taint/function_level.py` (special-case branch)
- Modify: tests for taint assignment (find existing test file and add cases)

- [ ] **Step 1: Find the existing taint test file**

Run: `find tests/ -name "*taint*" -o -name "*function_level*" | head -10`

Read the file to understand the test patterns (how annotations are constructed, how `_walk_and_assign` or `taint_from_annotations` is tested).

- [ ] **Step 2: Write tests**

Add a new test class (adjust import paths to match existing patterns):

```python
class TestRestorationTaintAssignment:
    """Taint assignment for @restoration_boundary with evidence."""

    def test_int_data_alone_unknown_raw(self):
        """@int_data without @restoration_boundary → UNKNOWN_RAW."""
        # Construct annotation with canonical_name="int_data", group=4
        # Call taint_from_annotations with BODY_EVAL_TAINT
        # Assert result is None (falls to fallback → UNKNOWN_RAW)
        ...

    def test_restoration_full_evidence_audit_trail(self):
        """@restoration_boundary(full evidence) → AUDIT_TRAIL."""
        # Construct annotation with canonical_name="restoration_boundary",
        # group=17, attrs including all evidence
        # Call the restoration taint resolution
        # Assert AUDIT_TRAIL
        ...

    def test_restoration_structural_only_unknown_shape(self):
        """@restoration_boundary(structural only) → UNKNOWN_SHAPE_VALIDATED."""
        ...

    def test_restoration_no_evidence_unknown_raw(self):
        """@restoration_boundary(no evidence) → UNKNOWN_RAW."""
        ...

    def test_int_data_plus_restoration_full_audit_trail(self):
        """@int_data + @restoration_boundary(full) → AUDIT_TRAIL (not UNKNOWN_RAW)."""
        ...
```

Note: The exact test patterns depend on how the existing taint tests construct `WardlineAnnotation` objects and call the taint functions. Read the test file first and follow its patterns exactly.

- [ ] **Step 3: Implement the special-case branch**

In `src/wardline/scanner/taint/function_level.py`, modify the `_walk_and_assign` function. After the existing `body_taint = taint_from_annotations(...)` call at line 261, add a restoration-specific branch:

```python
            # Precedence: decorator > module_tiers > UNKNOWN_RAW
            body_taint = taint_from_annotations(
                file_path, qualname, annotations,
                decorator_map=BODY_EVAL_TAINT,
                conflicts=taint_conflicts,
            )

            # Special case: restoration_boundary uses evidence-based taint,
            # not a static map entry. Check before falling to module default.
            if body_taint is None:
                restoration_taint = _restoration_taint_from_annotations(
                    file_path, qualname, annotations,
                )
                if restoration_taint is not None:
                    body_taint = restoration_taint
                    ret_taint = restoration_taint
                    source = "decorator"
                    # Skip the normal decorator/module/fallback chain
                    body_taint_map[qualname] = body_taint
                    return_taint_map[qualname] = ret_taint
                    taint_sources[qualname] = source
                    _walk_and_assign(
                        child, file_path, annotations, module_default,
                        body_taint_map, return_taint_map, taint_sources,
                        taint_conflicts, scope=qualname,
                    )
                    continue

            if body_taint is not None:
                source: TaintSource = "decorator"
                # ... existing logic continues ...
```

Add the helper function before `_walk_and_assign`:

```python
def _restoration_taint_from_annotations(
    file_path: str,
    qualname: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
) -> TaintState | None:
    """Resolve taint for restoration_boundary via §5.3 evidence matrix.

    Returns the evidence-derived taint state if the function has a
    restoration_boundary annotation, or None if it does not.
    """
    from wardline.core.evidence import max_restorable_tier

    key = (file_path, qualname)
    anns = annotations.get(key)
    if not anns:
        return None

    for ann in anns:
        if ann.canonical_name == "restoration_boundary":
            structural = bool(ann.attrs.get("structural_evidence", False))
            semantic = bool(ann.attrs.get("semantic_evidence", False))
            integrity = bool(ann.attrs.get("integrity_evidence"))
            institutional = bool(ann.attrs.get("institutional_provenance"))
            return max_restorable_tier(
                structural, semantic, integrity, institutional,
            )
    return None
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/ -x -q --tb=short`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/function_level.py tests/unit/scanner/...
git commit -m "Add evidence-based taint assignment for restoration_boundary"
```

---

### Task 6: Cross-Layer Reconciliation

**Files:**
- Modify: `src/wardline/manifest/coherence.py` (add `check_restoration_evidence_consistency`)
- Modify: `src/wardline/cli/_helpers.py` (severity entry)
- Modify: `src/wardline/cli/coherence_cmd.py` (category + wiring)
- Modify: `tests/unit/manifest/test_coherence.py`

- [ ] **Step 1: Write tests**

```python
class TestRestorationEvidenceConsistency:
    """check_restoration_evidence_consistency() — cross-layer reconciliation."""

    def test_matching_evidence_no_issue(self):
        """Decorator and overlay evidence match → no issue."""
        ...

    def test_decorator_claims_higher_than_overlay_warning(self):
        """Decorator structural=True but overlay structural=False → WARNING."""
        ...

    def test_decorator_claims_lower_than_overlay_no_issue(self):
        """Decorator is conservative (less evidence) → no issue."""
        ...

    def test_no_annotation_for_boundary_skipped(self):
        """Overlay boundary with no corresponding annotation → skipped."""
        ...
```

Note: This check requires both `boundaries` (from overlays) and `annotations` (from discovery). Look at how `check_unmatched_contracts` takes both parameters for the pattern to follow.

- [ ] **Step 2: Write the implementation**

```python
def check_restoration_evidence_consistency(
    boundaries: tuple[BoundaryEntry, ...],
    annotations: dict[tuple[str, str], list[object]],
) -> list[CoherenceIssue]:
    """Check decorator evidence doesn't exceed overlay provenance.

    The overlay is the governance source of truth. If the decorator
    claims higher evidence than the overlay declares, emit a WARNING.
    """
    issues: list[CoherenceIssue] = []
    for boundary in boundaries:
        if boundary.transition != "restoration":
            continue
        if boundary.provenance is None:
            continue

        # Find matching annotation
        # ... match by function name, extract decorator attrs
        # ... compare each evidence category
        # ... if decorator claims True but overlay has False/absent → WARNING
    return issues
```

- [ ] **Step 3: Register severity and category**

Add to `_helpers.py` `COHERENCE_SEVERITY_MAP`:
```python
"restoration_evidence_divergence": "WARNING",
```

Add to `coherence_cmd.py` `CATEGORY_MAP`:
```python
"restoration_evidence_divergence": "enforcement",
```

- [ ] **Step 4: Wire the check**

Add to coherence_cmd.py after the restoration evidence check. This function needs both `boundaries` and `annotations`:
```python
    all_issues.extend(
        check_restoration_evidence_consistency(boundaries, annotations)
    )
```

Update check count comment (14 checks).

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/ -x -q --tb=short`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/manifest/coherence.py src/wardline/cli/_helpers.py src/wardline/cli/coherence_cmd.py tests/unit/manifest/test_coherence.py
git commit -m "Add cross-layer restoration evidence consistency check"
```

---

### Task 7: SCN-021 Contradiction + PY-WL-008 Verification

**Files:**
- Modify: `src/wardline/scanner/rules/scn_021.py` (add external_boundary entry)
- Modify: `tests/unit/scanner/test_scn_021.py` (verify new + existing entries)
- Modify: `tests/unit/scanner/test_py_wl_008.py` (add restoration tests)

- [ ] **Step 1: Add the SCN-021 contradiction entry**

In `src/wardline/scanner/rules/scn_021.py`, add to `_COMBINATIONS` after the existing `audit_writer + restoration_boundary` entry:

```python
    _CombinationSpec(
        "external_boundary",
        "restoration_boundary",
        _CONTRADICTORY,
        "External boundaries receive new untrusted data; "
        "restoration reconstructs previously-known data",
    ),
```

- [ ] **Step 2: Run existing SCN-021 tests**

Run: `python -m pytest tests/unit/scanner/test_scn_021.py -v --tb=short`
Expected: All pass (the parametrized `TestAllCombinations` auto-covers new entries)

- [ ] **Step 3: Add PY-WL-008 restoration tests**

Read `tests/unit/scanner/test_py_wl_008.py` to understand the pattern for testing boundary transitions. Add:

```python
class TestRestorationBoundaryRejectionPath:
    """PY-WL-008: restoration boundaries must have rejection paths."""

    def test_restoration_with_rejection_path_no_finding(self):
        """Restoration boundary with isinstance check → no finding."""
        ...

    def test_restoration_without_rejection_path_fires(self):
        """Restoration boundary with no rejection path → finding."""
        ...
```

Follow the existing test patterns for constructing AST fixtures with boundary entries.

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/unit/scanner/test_scn_021.py tests/unit/scanner/test_py_wl_008.py -v --tb=short`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/rules/scn_021.py tests/unit/scanner/test_scn_021.py tests/unit/scanner/test_py_wl_008.py
git commit -m "Add external_boundary+restoration_boundary contradiction and PY-WL-008 restoration tests"
```

---

### Task 8: Discovery Verification + Full Integration

**Files:**
- Modify: `tests/unit/scanner/test_discovery.py` (add restoration kwarg extraction test)
- Run full test suite

- [ ] **Step 1: Add discovery test**

Read `tests/unit/scanner/test_discovery.py` to find how decorator keyword arg extraction is tested. Add a test that verifies AST extraction of:

```python
@restoration_boundary(
    restored_tier=1,
    structural_evidence=True,
    semantic_evidence=True,
    integrity_evidence="hmac",
    institutional_provenance="org-db",
)
def restore(raw): ...
```

Verify the `WardlineAnnotation.attrs` dict contains all 5 keyword values.

- [ ] **Step 2: Run full test suite**

Run: `python -m pytest tests/ -x -q --tb=short`
Expected: All pass, zero regressions

- [ ] **Step 3: Commit**

```bash
git add tests/unit/scanner/test_discovery.py
git commit -m "Add discovery test for restoration_boundary keyword extraction"
```

- [ ] **Step 4: Final verification**

Run: `python -m pytest tests/ -q --tb=short`
Verify total test count increased and no failures.

Run: `grep -r "bounded_context" src/ tests/` — verify still zero hits (regression check from Gap 2).
