# WP 1.3: Overlay System — Design Spec

**Date:** 2026-03-23
**Status:** Draft
**Work Package:** wardline-afbfce8139
**Blocks:** WP 1.4 (Exception Register), WP 1.7 (Migration Tooling), WP 1.8 (Full Corpus)

## Summary

Wire the overlay merge system to enforce boundary-level narrow-only invariants,
inject resolved boundaries into the scanner's rule context, and upgrade
`schema_default()` handling from unconditional WARNING to evidence-based
severity (INFO when governed by a boundary declaration, ERROR when not).

## Change 1: Boundary-Level Narrow-Only Enforcement in `merge()`

**File:** `src/wardline/manifest/merge.py`

`_check_boundary_tier()` and `_assert_tier_not_widened()` are already
implemented but never called from `merge()`. Activate them.

After resolving boundaries from the overlay (line 124), build a tier map from
`base.tiers` as `{tier.id: tier.tier}` and iterate each boundary entry through
`_check_boundary_tier()`. If a boundary's `from_tier` or `to_tier` would relax
(higher number) the corresponding base tier, `ManifestWidenError` is raised.

Boundaries referencing functions with no base tier entry pass without error
(new boundaries are legitimate).

**Tests (unit):**
- Overlay relaxes `from_tier` beyond base → `ManifestWidenError` with correct
  `overlay_name`, `field_name`, `base_value`, `attempted_value`
- Overlay relaxes `to_tier` beyond base → `ManifestWidenError`
- Overlay tightens tier → passes, boundary in result
- Overlay same tier → passes
- Boundary function not in base tiers → passes

## Change 2: `ScanContext` Boundary Injection

**Files:** `src/wardline/scanner/context.py`, `src/wardline/scanner/engine.py`

Add `boundaries: tuple[BoundaryEntry, ...] = ()` to `ScanContext`. This is
a frozen dataclass field, matching the existing pattern.

In `ScanEngine`:
- At `scan()` time (once per scan run), discover overlays via
  `discover_overlays(root, manifest)`, load each via the manifest loader, and
  merge each with the base manifest via `merge()`. Collect the union of all
  resolved boundaries into a single tuple.
- Store the resolved boundaries on the engine instance.
- In `_scan_file()`, pass them to the `ScanContext` constructor.

The same boundaries tuple is shared across all files (boundaries are a
project-level construct, not per-file).

**Engine constructor change:** The engine needs the project root path to
discover overlays. Add `project_root: Path | None = None` to `__init__()`.
When `project_root` is provided and `manifest` is not None, overlay discovery
and merge happen in `scan()`. When either is None, boundaries default to `()`.

**Tests (unit):**
- `ScanContext` with boundaries accessible from rule via `self._context`
- Engine with overlay files produces findings with boundary context

## Change 3: `schema_default()` Overlay Verification in PY-WL-001

**File:** `src/wardline/scanner/rules/py_wl_001.py`

Change `_emit_unverified_default()` to consult `self._context.boundaries`:

1. Look up the enclosing function's qualname (`self._current_qualname`) in the
   boundaries tuple — match on `boundary.function == qualname`.
2. **Match found (governed):** Emit finding at `Severity.INFO` with rule ID
   `PY_WL_001_UNVERIFIED_DEFAULT`. Message updated to indicate overlay
   verification succeeded.
3. **No match (ungoverned):** Emit finding at `Severity.ERROR` with rule ID
   `PY_WL_001`. This is now a standard PY-WL-001 violation — the
   `schema_default()` wrapper provides no governance without a boundary
   declaration.

**Boundary matching semantics:** Exact match on the function's dotted qualname
(e.g., `"MyClass.handle"` matches boundary `function: "MyClass.handle"`).
This is consistent with how `check_orphaned_annotations` and
`check_undeclared_boundaries` in coherence.py match function names.

**Tests (unit):**
- `schema_default()` with matching boundary → INFO finding
- `schema_default()` without matching boundary → ERROR finding (rule ID PY_WL_001)
- `schema_default()` with boundary for different function → ERROR
- Non-`schema_default()` default → ERROR (unchanged behavior)

## Change 4: Conformance Gap Cleanup

**File:** `src/wardline/scanner/sarif.py` (line 181)

The `wardline.conformanceGaps` array is already empty (`[]`) in the current
code. No code change needed — the behavioral gap is closed by Change 3.

The design doc (`docs/2026-03-21-wardline-python-design.md`, line 463-464)
documents `PY-WL-001-SCHEMA-DEFAULT-UNVERIFIED` as a transitional artefact
that disappears when overlay verification lands. This spec fulfills that
commitment.

**Validation:** The `PY_WL_001_UNVERIFIED_DEFAULT` rule ID continues to
exist in `RuleId` enum for the INFO-level governed finding. It does NOT
appear in `wardline.implementedRules` (per existing convention — it's not
a spec rule).

## Files Changed

| File | Change |
|------|--------|
| `src/wardline/manifest/merge.py` | Activate `_check_boundary_tier` in `merge()` |
| `src/wardline/scanner/context.py` | Add `boundaries` field to `ScanContext` |
| `src/wardline/scanner/engine.py` | Overlay discovery + merge in `scan()`, pass boundaries to context |
| `src/wardline/scanner/rules/py_wl_001.py` | Boundary-aware `schema_default()` handling |
| `tests/unit/manifest/test_merge.py` | Boundary-level narrow-only tests |
| `tests/unit/scanner/test_py_wl_001.py` | Governed vs ungoverned `schema_default()` tests |
| `tests/unit/scanner/test_engine.py` | Engine overlay integration tests |

## Out of Scope

- Multi-overlay merge ordering (only relevant when multiple overlays cover
  the same directory — deferred to WP 1.4)
- Coherence check updates (existing checks already work with boundaries)
- `RuleId` enum changes (existing `PY_WL_001_UNVERIFIED_DEFAULT` is reused)
- SARIF output changes (conformance gap already cleared)
