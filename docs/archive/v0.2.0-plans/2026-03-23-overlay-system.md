# WP 1.3: Overlay System — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire overlay merge enforcement, boundary-scoped scanner context, and `schema_default()` governance verification to close the MVP conformance gap.

**Architecture:** Four changes layered bottom-up: (1) activate boundary tier checks in merge, (2) extract `resolve_boundaries()` and inject into `ScanContext`, (3) make PY-WL-001 boundary-aware with directory scoping, (4) update SARIF enum references. Each task produces independently testable, committable code.

**Tech Stack:** Python 3.9+, frozen dataclasses, `ast` module, `pytest`, SARIF v2.1.0

**Spec:** `docs/superpowers/specs/2026-03-23-overlay-system-design.md`

---

### Task 1: Add `overlay_scope` field to `BoundaryEntry`

**Files:**
- Modify: `src/wardline/manifest/models.py:101-110`
- Modify: `src/wardline/manifest/loader.py:230-259`
- Test: `tests/unit/manifest/test_models.py`

- [ ] **Step 1: Write the failing test**

In `tests/unit/manifest/test_models.py`, add:

```python
class TestBoundaryEntryOverlayScope:
    def test_overlay_scope_defaults_to_empty(self) -> None:
        b = BoundaryEntry(function="fn", transition="construction")
        assert b.overlay_scope == ""

    def test_overlay_scope_set_at_construction(self) -> None:
        b = BoundaryEntry(
            function="fn", transition="construction", overlay_scope="adapters/"
        )
        assert b.overlay_scope == "adapters/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestBoundaryEntryOverlayScope -v`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'overlay_scope'`

- [ ] **Step 3: Add `overlay_scope` field to `BoundaryEntry`**

In `src/wardline/manifest/models.py`, add after `bounded_context` (line 110):

```python
    overlay_scope: str = ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestBoundaryEntryOverlayScope -v`
Expected: PASS

- [ ] **Step 5: Run full model test suite**

Run: `uv run pytest tests/unit/manifest/test_models.py -v`
Expected: All PASS (existing tests unaffected — new field has default)

- [ ] **Step 6: Commit**

```bash
git add src/wardline/manifest/models.py tests/unit/manifest/test_models.py
git commit -m "feat(models): add overlay_scope field to BoundaryEntry"
```

---

### Task 2: Activate boundary-level narrow-only enforcement in `merge()`

**Files:**
- Modify: `src/wardline/manifest/merge.py:67-131` (merge function), `152-194` (rewrite helpers)
- Test: `tests/unit/manifest/test_merge.py`

**Context:** `merge()` currently receives `base: WardlineManifest` which already contains `base.tiers` and `base.module_tiers`. The existing `_check_boundary_tier` and `_assert_tier_not_widened` are dead code that uses the wrong key namespace. We rewrite them.

- [ ] **Step 1: Write the helper test**

In `tests/unit/manifest/test_merge.py`, add:

```python
from wardline.manifest.merge import _resolve_module_tier

class TestResolveModuleTier:
    """Test the module-tier prefix matching helper."""

    def test_exact_path_match(self) -> None:
        module_tiers = (ModuleTierEntry(path="src/adapters", default_taint="EXTERNAL_RAW"),)
        tiers = (TierEntry(id="EXTERNAL_RAW", tier=4),)
        tier_map = {t.id: t.tier for t in tiers}

        result = _resolve_module_tier("src/adapters.Handler.handle", module_tiers, tier_map)
        assert result == 4

    def test_longest_prefix_wins(self) -> None:
        module_tiers = (
            ModuleTierEntry(path="src/adapters", default_taint="EXTERNAL_RAW"),
            ModuleTierEntry(path="src/adapters/partner", default_taint="PIPELINE"),
        )
        tiers = (
            TierEntry(id="EXTERNAL_RAW", tier=4),
            TierEntry(id="PIPELINE", tier=2),
        )
        tier_map = {t.id: t.tier for t in tiers}

        result = _resolve_module_tier("src/adapters/partner.Client.call", module_tiers, tier_map)
        assert result == 2

    def test_no_matching_module_returns_none(self) -> None:
        module_tiers = (ModuleTierEntry(path="src/core", default_taint="AUDIT_TRAIL"),)
        tiers = (TierEntry(id="AUDIT_TRAIL", tier=1),)
        tier_map = {t.id: t.tier for t in tiers}

        result = _resolve_module_tier("src/other.fn", module_tiers, tier_map)
        assert result is None

    def test_default_taint_not_in_tiers_returns_none(self) -> None:
        module_tiers = (ModuleTierEntry(path="src/x", default_taint="NONEXISTENT"),)
        tier_map: dict[str, int] = {}

        result = _resolve_module_tier("src/x.fn", module_tiers, tier_map)
        assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/manifest/test_merge.py::TestResolveModuleTier -v`
Expected: FAIL with `ImportError: cannot import name '_resolve_module_tier'`

- [ ] **Step 3: Implement `_resolve_module_tier` helper**

In `src/wardline/manifest/merge.py`, replace `_check_boundary_tier` and `_assert_tier_not_widened` (lines 152-194) with:

```python
def _resolve_module_tier(
    function: str,
    module_tiers: tuple[ModuleTierEntry, ...],
    tier_number_map: dict[str, int],
) -> int | None:
    """Resolve the module tier for a boundary function via longest prefix match.

    Returns the tier number, or None if no module tier covers this function.
    """
    best_match: int | None = None
    best_length = -1

    for mt in module_tiers:
        if function.startswith(mt.path) and len(mt.path) > best_length:
            tier_num = tier_number_map.get(mt.default_taint)
            if tier_num is not None:
                best_match = tier_num
                best_length = len(mt.path)

    return best_match
```

Add `ModuleTierEntry` to the imports from `wardline.manifest.models` (line 13-19).

- [ ] **Step 4: Run helper tests**

Run: `uv run pytest tests/unit/manifest/test_merge.py::TestResolveModuleTier -v`
Expected: PASS

- [ ] **Step 5: Write boundary enforcement tests**

In `tests/unit/manifest/test_merge.py`, add:

```python
from wardline.manifest.merge import ManifestWidenError

class TestBoundaryTierEnforcement:
    """merge() enforces narrow-only at the boundary level."""

    def _manifest_with_tiers(self) -> WardlineManifest:
        return WardlineManifest(
            tiers=(
                TierEntry(id="AUDIT_TRAIL", tier=1),
                TierEntry(id="PIPELINE", tier=2),
                TierEntry(id="EXTERNAL_RAW", tier=4),
            ),
            module_tiers=(
                ModuleTierEntry(path="src/core", default_taint="AUDIT_TRAIL"),
                ModuleTierEntry(path="src/adapters", default_taint="EXTERNAL_RAW"),
            ),
        )

    def test_from_tier_exceeds_module_tier_raises(self) -> None:
        base = self._manifest_with_tiers()
        overlay = _overlay(
            name="core-overlay",
            boundaries=(
                BoundaryEntry(
                    function="src/core.Handler.handle",
                    transition="construction",
                    from_tier=3,  # module is tier 1 — widening
                ),
            ),
        )
        with pytest.raises(ManifestWidenError) as exc_info:
            merge(base, overlay)
        assert exc_info.value.overlay_name == "core-overlay"
        assert exc_info.value.field_name == "from_tier"
        assert exc_info.value.base_value == 1
        assert exc_info.value.attempted_value == 3

    def test_to_tier_exceeds_module_tier_raises(self) -> None:
        base = self._manifest_with_tiers()
        overlay = _overlay(
            name="core-overlay",
            boundaries=(
                BoundaryEntry(
                    function="src/core.Processor.run",
                    transition="construction",
                    to_tier=2,  # module is tier 1 — widening
                ),
            ),
        )
        with pytest.raises(ManifestWidenError) as exc_info:
            merge(base, overlay)
        assert exc_info.value.field_name == "to_tier"
        assert exc_info.value.base_value == 1
        assert exc_info.value.attempted_value == 2

    def test_tighten_passes(self) -> None:
        base = self._manifest_with_tiers()
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="src/adapters.Client.call",
                    transition="construction",
                    from_tier=2,  # module is tier 4 — tightening
                ),
            ),
        )
        result = merge(base, overlay)
        assert len(result.boundaries) == 1

    def test_same_tier_passes(self) -> None:
        base = self._manifest_with_tiers()
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="src/adapters.Client.call",
                    transition="construction",
                    from_tier=4,
                ),
            ),
        )
        result = merge(base, overlay)
        assert len(result.boundaries) == 1

    def test_no_module_tier_passes(self) -> None:
        base = self._manifest_with_tiers()
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="src/unknown.fn",
                    transition="construction",
                    from_tier=99,
                ),
            ),
        )
        result = merge(base, overlay)
        assert len(result.boundaries) == 1

    def test_none_tiers_pass(self) -> None:
        base = self._manifest_with_tiers()
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="src/core.fn",
                    transition="construction",
                ),
            ),
        )
        result = merge(base, overlay)
        assert len(result.boundaries) == 1
```

- [ ] **Step 6: Run enforcement tests to verify they fail**

Run: `uv run pytest tests/unit/manifest/test_merge.py::TestBoundaryTierEnforcement -v`
Expected: FAIL — merge() does not call the check yet

- [ ] **Step 7: Wire enforcement into `merge()`**

In `src/wardline/manifest/merge.py`, in the `merge()` function, after `resolved_boundaries = overlay.boundaries` (line 124), add:

```python
    # -- Boundary-level narrow-only check -----------------------------------
    tier_number_map: dict[str, int] = {t.id: t.tier for t in base.tiers}
    for boundary in resolved_boundaries:
        module_tier = _resolve_module_tier(
            boundary.function, base.module_tiers, tier_number_map
        )
        if module_tier is None:
            continue
        if boundary.from_tier is not None and boundary.from_tier > module_tier:
            raise ManifestWidenError(
                overlay_name=overlay.overlay_for,
                field_name="from_tier",
                base_value=module_tier,
                attempted_value=boundary.from_tier,
            )
        if boundary.to_tier is not None and boundary.to_tier > module_tier:
            raise ManifestWidenError(
                overlay_name=overlay.overlay_for,
                field_name="to_tier",
                base_value=module_tier,
                attempted_value=boundary.to_tier,
            )
```

- [ ] **Step 8: Convert existing `test_boundary_with_tier_accepted`**

In `tests/unit/manifest/test_merge.py`, update `test_boundary_with_tier_accepted` (lines 92-114). The comment says widening is accepted — under the new spec it must raise. Update the test:

```python
    def test_boundary_with_tier_widening_raises(self) -> None:
        """Boundary that widens a tier raises ManifestWidenError.

        Previously this was deferred to coherence checks. Now enforced
        at merge time (WP 1.3).
        """
        base = WardlineManifest(
            tiers=(TierEntry(id="AUDIT_TRAIL", tier=1),),
            module_tiers=(
                ModuleTierEntry(
                    path="process_payment", default_taint="AUDIT_TRAIL"
                ),
            ),
        )
        overlay = _overlay(
            name="payments-overlay",
            boundaries=(
                BoundaryEntry(
                    function="process_payment.handle",
                    transition="TRUST_ELEVATION",
                    from_tier=3,
                ),
            ),
        )
        with pytest.raises(ManifestWidenError):
            merge(base, overlay)
```

- [ ] **Step 9: Run all merge tests**

Run: `uv run pytest tests/unit/manifest/test_merge.py -v`
Expected: All PASS

- [ ] **Step 10: Commit**

```bash
git add src/wardline/manifest/merge.py tests/unit/manifest/test_merge.py
git commit -m "feat(merge): activate boundary-level narrow-only enforcement"
```

---

### Task 3: Create `resolve_boundaries()` function

**Files:**
- Create: `src/wardline/manifest/resolve.py`
- Test: `tests/unit/manifest/test_resolve.py`

**Context:** This function discovers overlays, loads each, merges with the manifest, and collects boundaries with `overlay_scope` populated. Error handling: `GovernanceError`/`ManifestWidenError` propagate; I/O errors degrade to `()`.

- [ ] **Step 1: Write the tests**

Create `tests/unit/manifest/test_resolve.py`:

```python
"""Tests for wardline.manifest.resolve — boundary resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.manifest.discovery import GovernanceError
from wardline.manifest.models import (
    BoundaryEntry,
    ModuleTierEntry,
    TierEntry,
    WardlineManifest,
)
from wardline.manifest.resolve import resolve_boundaries


def _write_overlay(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _minimal_manifest(module_paths: tuple[str, ...] = ()) -> WardlineManifest:
    return WardlineManifest(
        module_tiers=tuple(
            ModuleTierEntry(path=p, default_taint="EXTERNAL_RAW")
            for p in module_paths
        ),
        tiers=(TierEntry(id="EXTERNAL_RAW", tier=4),),
    )


class TestResolveBoundaries:
    def test_no_overlays_returns_empty(self, tmp_path: Path) -> None:
        manifest = _minimal_manifest()
        result = resolve_boundaries(tmp_path, manifest)
        assert result == ()

    def test_overlay_boundaries_returned_with_scope(self, tmp_path: Path) -> None:
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/0.1/overlay.schema.json"\n'
                "overlay_for: adapters\n"
                "boundaries:\n"
                '  - function: "Handler.handle"\n'
                '    transition: "construction"\n'
            ),
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        result = resolve_boundaries(tmp_path, manifest)

        assert len(result) == 1
        assert result[0].function == "Handler.handle"
        assert result[0].overlay_scope == "adapters"

    def test_governance_error_propagates(self, tmp_path: Path) -> None:
        # Overlay in undeclared directory
        rogue_dir = tmp_path / "rogue"
        rogue_dir.mkdir()
        _write_overlay(
            rogue_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/0.1/overlay.schema.json"\n'
                "overlay_for: rogue\n"
                "boundaries: []\n"
            ),
        )
        manifest = _minimal_manifest()  # no module_tiers covering "rogue"

        with pytest.raises(GovernanceError):
            resolve_boundaries(tmp_path, manifest)

    def test_bad_yaml_returns_empty(self, tmp_path: Path) -> None:
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        (overlay_dir / "wardline.overlay.yaml").write_text(
            "not: valid: yaml: {{{\n", encoding="utf-8"
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        # Should degrade gracefully, not crash
        result = resolve_boundaries(tmp_path, manifest)
        assert result == ()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/manifest/test_resolve.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wardline.manifest.resolve'`

- [ ] **Step 3: Implement `resolve_boundaries()`**

Create `src/wardline/manifest/resolve.py`:

```python
"""Boundary resolution — discover overlays, merge, collect boundaries.

Callers receive an opaque tuple of BoundaryEntry objects with
overlay_scope populated. The engine passes this to ScanContext.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.manifest.discovery import discover_overlays
from wardline.manifest.loader import ManifestLoadError, load_overlay
from wardline.manifest.merge import merge

if TYPE_CHECKING:
    from wardline.manifest.models import BoundaryEntry, WardlineManifest

logger = logging.getLogger(__name__)


def resolve_boundaries(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[BoundaryEntry, ...]:
    """Discover overlays, merge each with *manifest*, return all boundaries.

    Error handling:
    - ``GovernanceError`` / ``ManifestWidenError``: propagate (policy violation).
    - I/O / parse errors from individual overlay files: log + skip.
    """
    overlay_paths = discover_overlays(root, manifest)

    all_boundaries: list[BoundaryEntry] = []
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except (ManifestLoadError, OSError, Exception) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        resolved = merge(manifest, overlay)

        # Tag each boundary with the overlay's scope
        for boundary in resolved.boundaries:
            scoped = replace(boundary, overlay_scope=overlay.overlay_for)
            all_boundaries.append(scoped)

    return tuple(all_boundaries)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/manifest/test_resolve.py -v`
Expected: All PASS

- [ ] **Step 5: Run full manifest test suite**

Run: `uv run pytest tests/unit/manifest/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/wardline/manifest/resolve.py tests/unit/manifest/test_resolve.py
git commit -m "feat(manifest): add resolve_boundaries() for overlay discovery + merge"
```

---

### Task 4: Add `boundaries` to `ScanContext` and wire into engine

**Files:**
- Modify: `src/wardline/scanner/context.py:59-83`
- Modify: `src/wardline/scanner/engine.py:57-68`
- Modify: `src/wardline/cli/scan.py:275-283`
- Test: `tests/unit/scanner/test_engine.py`

- [ ] **Step 1: Write the ScanContext test**

In `tests/unit/scanner/test_engine.py` (or appropriate context test file), add:

```python
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext

class TestScanContextBoundaries:
    def test_boundaries_default_empty(self) -> None:
        ctx = ScanContext(file_path="test.py", function_level_taint_map={})
        assert ctx.boundaries == ()

    def test_boundaries_set_at_construction(self) -> None:
        b = BoundaryEntry(function="fn", transition="construction")
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},
            boundaries=(b,),
        )
        assert len(ctx.boundaries) == 1
        assert ctx.boundaries[0].function == "fn"

    def test_boundaries_frozen(self) -> None:
        ctx = ScanContext(file_path="test.py", function_level_taint_map={})
        with pytest.raises(AttributeError):
            ctx.boundaries = ()  # type: ignore[misc]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestScanContextBoundaries -v`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'boundaries'`

- [ ] **Step 3: Add `boundaries` field to `ScanContext`**

In `src/wardline/scanner/context.py`, add to the `TYPE_CHECKING` block (line 13-15):

```python
    from wardline.manifest.models import BoundaryEntry
```

Add field after `function_level_taint_map` (after line 74):

```python
    boundaries: tuple[BoundaryEntry, ...] = ()
```

- [ ] **Step 4: Run context tests**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestScanContextBoundaries -v`
Expected: PASS

- [ ] **Step 5: Write engine boundaries test**

In `tests/unit/scanner/test_engine.py`, add:

```python
class TestEngineBoundaryInjection:
    def test_engine_passes_boundaries_to_context(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")

        b = BoundaryEntry(function="foo", transition="construction")
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            boundaries=(b,),
        )
        engine.scan()

        assert rule.captured_context is not None
        assert len(rule.captured_context.boundaries) == 1
        assert rule.captured_context.boundaries[0].function == "foo"

    def test_engine_no_boundaries_backward_compat(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        engine.scan()

        assert rule.captured_context is not None
        assert rule.captured_context.boundaries == ()
```

Note: `_ContextCapturingRule` should already exist in the test file from the taint wiring tests. If not, check `test_engine_taint_wiring.py` for the pattern and add it.

- [ ] **Step 6: Run engine test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestEngineBoundaryInjection -v`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'boundaries'`

- [ ] **Step 7: Add `boundaries` parameter to `ScanEngine.__init__()`**

In `src/wardline/scanner/engine.py`, update `__init__` (lines 57-68):

Add `boundaries: tuple[BoundaryEntry, ...] = ()` parameter and store it:

```python
    def __init__(
        self,
        *,
        target_paths: tuple[Path, ...],
        exclude_paths: tuple[Path, ...] = (),
        rules: tuple[RuleBase, ...] = (),
        manifest: WardlineManifest | None = None,
        boundaries: tuple[BoundaryEntry, ...] = (),
    ) -> None:
        self._target_paths = target_paths
        self._exclude_paths = tuple(p.resolve() for p in exclude_paths)
        self._rules = rules
        self._manifest = manifest
        self._boundaries = boundaries
```

Add `BoundaryEntry` to the `TYPE_CHECKING` imports:

```python
    from wardline.manifest.models import BoundaryEntry, WardlineManifest
```

In `_scan_file()`, update the `ScanContext` construction (line 166-168) to pass boundaries:

```python
        ctx = ScanContext(
            file_path=str(file_path),
            function_level_taint_map=taint_map,
            boundaries=self._boundaries,
        )
```

- [ ] **Step 8: Run engine tests**

Run: `uv run pytest tests/unit/scanner/test_engine.py -v`
Expected: All PASS

- [ ] **Step 9: Update CLI call site**

In `src/wardline/cli/scan.py`, around line 275-283, update the engine construction to pass boundaries. Add before the engine construction:

```python
    # --- Resolve overlay boundaries ---
    boundaries: tuple[BoundaryEntry, ...] = ()
    if manifest_model is not None:
        try:
            from wardline.manifest.resolve import resolve_boundaries
            boundaries = resolve_boundaries(
                manifest_path.parent if manifest_path else Path.cwd(),
                manifest_model,
            )
        except Exception as exc:
            logger.warning("Overlay resolution failed: %s", exc)
```

Pass `boundaries=boundaries` to `ScanEngine(...)`.

- [ ] **Step 10: Run full test suite**

Run: `uv run pytest tests/unit/scanner/ -v`
Expected: All PASS

- [ ] **Step 11: Commit**

```bash
git add src/wardline/scanner/context.py src/wardline/scanner/engine.py src/wardline/cli/scan.py tests/unit/scanner/test_engine.py
git commit -m "feat(engine): inject overlay boundaries into ScanContext"
```

---

### Task 5: Add `PY_WL_001_GOVERNED_DEFAULT` to `RuleId`, update SARIF

**Files:**
- Modify: `src/wardline/core/severity.py:42-48`
- Modify: `src/wardline/scanner/sarif.py:31-62`
- Test: `tests/unit/core/test_severity.py`
- Test: `tests/unit/scanner/test_sarif.py`

- [ ] **Step 1: Write the enum test**

In `tests/unit/core/test_severity.py`, update `test_pseudo_rule_round_trip` to include the new member and remove the old:

```python
    def test_pseudo_rule_round_trip(self) -> None:
        """Pseudo-rule-IDs are full members of RuleId."""
        assert str(RuleId.TOOL_ERROR) == "TOOL-ERROR"
        assert str(RuleId.PY_WL_001_GOVERNED_DEFAULT) == "PY-WL-001-GOVERNED-DEFAULT"
        assert str(RuleId.WARDLINE_UNRESOLVED_DECORATOR) == "WARDLINE-UNRESOLVED-DECORATOR"
        assert str(RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED) == "GOVERNANCE-REGISTRY-MISMATCH-ALLOWED"
```

Update `test_canonical_count` — count stays 15 (replaced, not added).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/core/test_severity.py -v`
Expected: FAIL with `AttributeError: PY_WL_001_GOVERNED_DEFAULT`

- [ ] **Step 3: Update `RuleId` enum**

In `src/wardline/core/severity.py`, replace line 43:

```python
    PY_WL_001_UNVERIFIED_DEFAULT = "PY-WL-001-UNVERIFIED-DEFAULT"
```

with:

```python
    PY_WL_001_GOVERNED_DEFAULT = "PY-WL-001-GOVERNED-DEFAULT"
```

- [ ] **Step 4: Update `sarif.py` references**

In `src/wardline/scanner/sarif.py`:

Replace `_RULE_SHORT_DESCRIPTIONS` entry (line 41):
```python
    RuleId.PY_WL_001_GOVERNED_DEFAULT: "Governed default value (diagnostic)",
```

Replace `_PSEUDO_RULE_IDS` entry (line 56):
```python
        RuleId.PY_WL_001_GOVERNED_DEFAULT,
```

- [ ] **Step 5: Write SARIF test for `implementedRules` exclusion**

In `tests/unit/scanner/test_sarif.py`, add:

```python
    def test_governed_default_not_in_implemented_rules(self) -> None:
        """PY_WL_001_GOVERNED_DEFAULT must not appear in implementedRules."""
        report = SarifReport(...)  # minimal report
        output = report.to_dict()
        implemented = output["runs"][0]["properties"]["wardline.implementedRules"]
        assert "PY-WL-001-GOVERNED-DEFAULT" not in implemented

    def test_conformance_gaps_empty(self) -> None:
        """Conformance gaps must remain empty (regression pin)."""
        report = SarifReport(...)  # minimal report
        output = report.to_dict()
        gaps = output["runs"][0]["properties"]["wardline.conformanceGaps"]
        assert gaps == []
```

- [ ] **Step 6: Run all affected tests**

Run: `uv run pytest tests/unit/core/test_severity.py tests/unit/scanner/test_sarif.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/wardline/core/severity.py src/wardline/scanner/sarif.py tests/unit/core/test_severity.py tests/unit/scanner/test_sarif.py
git commit -m "feat(severity): replace UNVERIFIED_DEFAULT with GOVERNED_DEFAULT"
```

---

### Task 6: Boundary-aware `schema_default()` in PY-WL-001

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_001.py:138-164`
- Test: `tests/unit/scanner/test_py_wl_001.py:120-152`

**Context:** `_emit_unverified_default()` currently hardcodes `Severity.WARNING` and `RuleId.PY_WL_001_UNVERIFIED_DEFAULT`. Replace with boundary-aware logic: check `self._context.boundaries` for a matching boundary (qualname + transition type + overlay scope), emit SUPPRESS if governed, ERROR if not.

- [ ] **Step 1: Write governed/ungoverned tests**

Replace the `TestSchemaDefault` class in `tests/unit/scanner/test_py_wl_001.py` with:

```python
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext


def _run_rule_with_context(
    source: str,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    file_path: str = "test.py",
) -> RulePyWl001:
    """Parse source inside a function, set context with boundaries, run rule."""
    tree = parse_function_source(source)
    rule = RulePyWl001(file_path=file_path)
    ctx = ScanContext(
        file_path=file_path,
        function_level_taint_map={},
        boundaries=boundaries,
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return rule


class TestSchemaDefaultGoverned:
    """schema_default() with boundary → SUPPRESS (governed)."""

    def test_get_with_boundary_suppresses(self) -> None:
        boundary = BoundaryEntry(
            function="test_fn",
            transition="construction",
            overlay_scope="",  # empty scope matches any file
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default("fallback"))\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        f = rule.findings[0]
        assert f.rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT
        assert f.severity == Severity.SUPPRESS
        assert f.exceptionability == Exceptionability.TRANSPARENT

    def test_setdefault_with_boundary_suppresses(self) -> None:
        boundary = BoundaryEntry(
            function="test_fn",
            transition="restoration",
            overlay_scope="",
        )
        rule = _run_rule_with_context(
            'd.setdefault("key", schema_default([]))\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT
        assert rule.findings[0].severity == Severity.SUPPRESS

    def test_class_method_with_boundary_suppresses(self) -> None:
        source = '''
class MyClass:
    def handle(self):
        d.get("key", schema_default("x"))
'''
        tree = parse_module_source(source)
        boundary = BoundaryEntry(
            function="MyClass.handle",
            transition="construction",
            overlay_scope="",
        )
        rule = RulePyWl001(file_path="test.py")
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},
            boundaries=(boundary,),
        )
        rule.set_context(ctx)
        rule.visit(tree)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT


class TestSchemaDefaultUngoverned:
    """schema_default() without matching boundary → ERROR."""

    def test_no_boundary_emits_error(self) -> None:
        rule = _run_rule_with_context(
            'd.get("key", schema_default("fallback"))\n',
        )
        assert len(rule.findings) == 1
        f = rule.findings[0]
        assert f.rule_id == RuleId.PY_WL_001
        assert f.severity == Severity.ERROR

    def test_wrong_function_emits_error(self) -> None:
        boundary = BoundaryEntry(
            function="other_fn",
            transition="construction",
            overlay_scope="",
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default(42))\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_wrong_transition_emits_error(self) -> None:
        boundary = BoundaryEntry(
            function="test_fn",
            transition="shape_validation",  # not construction/restoration
            overlay_scope="",
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default(42))\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_wrong_scope_emits_error(self) -> None:
        boundary = BoundaryEntry(
            function="test_fn",
            transition="construction",
            overlay_scope="adapters/",
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default(42))\n',
            boundaries=(boundary,),
            file_path="services/handler.py",
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_no_context_emits_error(self) -> None:
        tree = parse_function_source(
            'd.get("key", schema_default(42))\n'
        )
        rule = RulePyWl001(file_path="test.py")
        # No set_context call — _context is None
        rule.visit(tree)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001
        assert rule.findings[0].severity == Severity.ERROR

    def test_case_sensitive_qualname(self) -> None:
        boundary = BoundaryEntry(
            function="Test_Fn",  # wrong case
            transition="construction",
            overlay_scope="",
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default(42))\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_multiple_boundaries_only_match_suppresses(self) -> None:
        boundaries = (
            BoundaryEntry(function="other", transition="construction", overlay_scope=""),
            BoundaryEntry(function="test_fn", transition="construction", overlay_scope=""),
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default(42))\n',
            boundaries=boundaries,
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT

    def test_non_schema_default_unchanged(self) -> None:
        """Regular default → ERROR regardless of boundaries."""
        boundary = BoundaryEntry(
            function="test_fn",
            transition="construction",
            overlay_scope="",
        )
        rule = _run_rule_with_context(
            'd.get("key", "hardcoded")\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001
        assert rule.findings[0].severity == Severity.ERROR
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_py_wl_001.py::TestSchemaDefaultGoverned tests/unit/scanner/test_py_wl_001.py::TestSchemaDefaultUngoverned -v`
Expected: FAIL — old code emits WARNING with UNVERIFIED_DEFAULT

- [ ] **Step 3: Implement boundary-aware `_emit_unverified_default()`**

In `src/wardline/scanner/rules/py_wl_001.py`, replace `_emit_unverified_default` (lines 138-164):

```python
    _GOVERNED_TRANSITIONS = frozenset({"construction", "restoration"})

    def _emit_unverified_default(
        self,
        call: ast.Call,
        enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Emit governed (SUPPRESS) or ungoverned (ERROR) for schema_default()."""
        taint = self._get_function_taint(self._current_qualname)

        if self._is_governed_by_boundary():
            self.findings.append(
                Finding(
                    rule_id=RuleId.PY_WL_001_GOVERNED_DEFAULT,
                    file_path=self._file_path,
                    line=call.lineno,
                    col=call.col_offset,
                    end_line=call.end_lineno,
                    end_col=call.end_col_offset,
                    message=(
                        "schema_default() governed by overlay boundary — "
                        "suppressed"
                    ),
                    severity=Severity.SUPPRESS,
                    exceptionability=Exceptionability.TRANSPARENT,
                    taint_state=taint,
                    analysis_level=1,
                    source_snippet=None,
                )
            )
        else:
            cell = matrix.lookup(self.RULE_ID, taint)
            self.findings.append(
                Finding(
                    rule_id=RuleId.PY_WL_001,
                    file_path=self._file_path,
                    line=call.lineno,
                    col=call.col_offset,
                    end_line=call.end_lineno,
                    end_col=call.end_col_offset,
                    message=(
                        "schema_default() without overlay boundary — "
                        "ungoverned default value"
                    ),
                    severity=cell.severity,
                    exceptionability=cell.exceptionability,
                    taint_state=taint,
                    analysis_level=1,
                    source_snippet=None,
                )
            )

    def _is_governed_by_boundary(self) -> bool:
        """Check if current function has a matching governance boundary."""
        if self._context is None:
            return False

        for boundary in self._context.boundaries:
            if (
                boundary.function == self._current_qualname
                and boundary.transition in self._GOVERNED_TRANSITIONS
                and self._file_path.startswith(boundary.overlay_scope)
            ):
                return True
        return False
```

Update imports at the top of the file to include `Exceptionability`:

```python
from wardline.core.severity import Exceptionability, RuleId, Severity
```

- [ ] **Step 4: Run all PY-WL-001 tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_001.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_001.py tests/unit/scanner/test_py_wl_001.py
git commit -m "feat(rules): boundary-aware schema_default() governance in PY-WL-001"
```

---

### Task 7: Full integration verification

**Files:**
- Test: `tests/integration/test_scan_engine_integration.py`
- Verify: all test suites

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest -x -v`
Expected: All PASS. Watch for:
- `test_severity.py` — enum count assertion (should be 15)
- `test_sarif.py` — property bag assertions
- `test_scan_engine_integration.py` — fixture project findings

- [ ] **Step 2: Check for any remaining `UNVERIFIED_DEFAULT` references**

Run: `grep -r "UNVERIFIED_DEFAULT" src/ tests/ --include="*.py"`
Expected: No matches (all references replaced in Tasks 5-6)

- [ ] **Step 3: Run self-hosting scan**

Run: `uv run wardline scan src/wardline/ --json 2>/dev/null | python -m json.tool | head -20`
Expected: Clean run, no crashes. Any `schema_default()` calls in the codebase should produce either `PY-WL-001-GOVERNED-DEFAULT` (SUPPRESS) or `PY-WL-001` (ERROR) depending on overlay coverage.

- [ ] **Step 4: Commit any integration test fixes**

If integration tests needed updates (e.g., `test_finding_severity_is_error` filtering for SUPPRESS), commit them:

```bash
git add tests/integration/
git commit -m "test(integration): update for governed schema_default() findings"
```

- [ ] **Step 5: Final commit — all green**

Run: `uv run pytest -v`
Expected: All PASS
