# WP 1.3: Overlay System — Design Spec

**Date:** 2026-03-23
**Status:** Draft
**Work Package:** wardline-afbfce8139
**Blocks:** WP 1.4 (Exception Register), WP 1.7 (Migration Tooling), WP 1.8 (Full Corpus)

## Summary

Wire the overlay merge system to enforce boundary-level narrow-only invariants,
inject resolved boundaries into the scanner's rule context, and upgrade
`schema_default()` handling from unconditional WARNING to evidence-based
severity (SUPPRESS/note when governed by a boundary declaration, ERROR when not).

## Change 1: Boundary-Level Narrow-Only Enforcement in `merge()`

**File:** `src/wardline/manifest/merge.py`

The existing `_check_boundary_tier()` helper uses `boundary.function` as a
lookup key into a tier map keyed by `TierEntry.id` — these are different
namespaces (function qualnames vs tier identifiers like `"trusted"`), so the
check as written would never fire. **Rewrite the check** to enforce the actual
invariant:

**Invariant:** A boundary's `from_tier` or `to_tier` value must not exceed the
module-level tier for the module containing that function. This requires
resolving the boundary's function to its module tier.

**Implementation:** `merge()` now accepts two additional parameters:
`module_tiers: tuple[ModuleTierEntry, ...] = ()` and
`tiers: tuple[TierEntry, ...] = ()` (both from the base manifest). Resolution
requires a two-step join: first build `{tier_id: tier_number}` from `tiers`,
then build `{module_path: tier_number}` by resolving each `ModuleTierEntry`'s
`default_taint` (which is a tier ID string like `"EXTERNAL_RAW"`) through the
tier map. For each boundary, find the most-specific module path prefix matching
`boundary.function`. If the boundary's `from_tier` or `to_tier` exceeds the
module's resolved tier number, raise `ManifestWidenError`.

Boundaries in modules with no `module_tiers` entry pass without error (no
baseline to enforce against).

**Tests (unit):**
- Boundary `from_tier` exceeds module tier → `ManifestWidenError` with correct
  `overlay_name`, `field_name`, `base_value`, `attempted_value`
- Boundary `to_tier` exceeds module tier → `ManifestWidenError`
- Boundary tightens (lower than module tier) → passes, boundary in result
- Boundary same as module tier → passes
- Boundary function has no matching module tier → passes

## Change 2: `ScanContext` Boundary Injection

**Files:** `src/wardline/scanner/context.py`, `src/wardline/scanner/engine.py`

Add `boundaries: tuple[BoundaryEntry, ...] = ()` to `ScanContext`. This is
a frozen dataclass field, matching the existing pattern. Import
`BoundaryEntry` under `TYPE_CHECKING` guard (same pattern as existing
type-only imports in the scanner package).

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

1. Guard: if `self._context is None`, treat as ungoverned (no boundaries
   available — emit ERROR).
2. Look up the enclosing function's qualname (`self._current_qualname`) in the
   boundaries tuple — match on `boundary.function == qualname`.
3. **Match found (governed):** Emit finding at `Severity.SUPPRESS` with rule ID
   `PY_WL_001_GOVERNED_DEFAULT` (new enum member). Message indicates overlay
   verification succeeded. `Severity.INFO` does not exist in the enum — use
   `SUPPRESS` which is the lowest non-silent severity. The finding still
   appears in SARIF output (SUPPRESS findings are included with
   `exceptionability: TRANSPARENT`) providing the audit trail.
4. **No match (ungoverned):** Emit finding at `Severity.ERROR` with rule ID
   `PY_WL_001`. This is now a standard PY-WL-001 violation — the
   `schema_default()` wrapper provides no governance without a boundary
   declaration.

**New rule ID:** Add `PY_WL_001_GOVERNED_DEFAULT = "PY-WL-001-GOVERNED-DEFAULT"`
to `RuleId` enum. The old `PY_WL_001_UNVERIFIED_DEFAULT` is no longer emitted
by any rule — it can be removed or kept as dead code (prefer removal to avoid
confusion).

**Boundary matching semantics:** Exact match on the function's dotted qualname
(e.g., `"MyClass.handle"` matches boundary `function: "MyClass.handle"`).
This is consistent with how `check_orphaned_annotations` and
`check_undeclared_boundaries` in coherence.py match function names.

**Known limitation:** Qualname matching is file-local (no file path component).
If two files declare functions with identical qualnames, a boundary for one
could match the other. This matches the existing coherence check behavior
and is acceptable for v0.2.0 — cross-file qualname collisions are vanishingly
rare in practice.

**Tests (unit):**
- `schema_default()` with matching boundary → SUPPRESS finding (SARIF "note"), rule ID `PY_WL_001_GOVERNED_DEFAULT`
- `schema_default()` without matching boundary → ERROR finding, rule ID `PY_WL_001`
- `schema_default()` with boundary for different function → ERROR
- `schema_default()` with `self._context is None` → ERROR
- Non-`schema_default()` default → ERROR (unchanged behavior)

## Change 4: Conformance Gap Cleanup

**File:** `src/wardline/scanner/sarif.py` (line 181)

The `wardline.conformanceGaps` array is already empty (`[]`) in the current
code. No code change needed — the behavioral gap is closed by Change 3.

The design doc (`docs/2026-03-21-wardline-python-design.md`, line 463-464)
documents `PY-WL-001-SCHEMA-DEFAULT-UNVERIFIED` as a transitional artefact
that disappears when overlay verification lands. This spec fulfills that
commitment.

**Validation:** `PY_WL_001_GOVERNED_DEFAULT` does NOT appear in
`wardline.implementedRules` (it's not a spec rule, same convention as the
old `UNVERIFIED_DEFAULT`).

## Files Changed

| File | Change |
|------|--------|
| `src/wardline/manifest/merge.py` | Rewrite `_check_boundary_tier` for module-tier lookup, activate in `merge()`, add `ModuleTierEntry` import |
| `src/wardline/scanner/context.py` | Add `boundaries` field to `ScanContext` |
| `src/wardline/scanner/engine.py` | Overlay discovery + merge in `scan()`, pass boundaries to context |
| `src/wardline/scanner/rules/py_wl_001.py` | Boundary-aware `schema_default()` handling |
| `src/wardline/core/severity.py` | Add `PY_WL_001_GOVERNED_DEFAULT` to `RuleId`, remove `PY_WL_001_UNVERIFIED_DEFAULT` |
| `tests/unit/manifest/test_merge.py` | Boundary-level narrow-only tests |
| `tests/unit/scanner/test_py_wl_001.py` | Governed vs ungoverned `schema_default()` tests |
| `tests/unit/scanner/test_engine.py` | Engine overlay integration tests |

## Out of Scope

- Multi-overlay merge ordering (only relevant when multiple overlays cover
  the same directory — deferred to WP 1.4)
- Coherence check updates (existing checks already work with boundaries)
- SARIF output changes (conformance gap already cleared)
- File-path-scoped qualname matching (matches existing coherence check behavior)
