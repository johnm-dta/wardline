# WP 1.3: Overlay System — Design Spec

**Date:** 2026-03-23
**Status:** Draft (post-panel-review)
**Work Package:** wardline-afbfce8139
**Blocks:** WP 1.4 (Exception Register), WP 1.7 (Migration Tooling), WP 1.8 (Full Corpus)

## Summary

Wire the overlay merge system to enforce boundary-level narrow-only invariants,
inject resolved boundaries into the scanner's rule context, and upgrade
`schema_default()` handling from unconditional WARNING to evidence-based
severity (SUPPRESS/note when governed by a scoped boundary declaration, ERROR
when not).

## Change 1: Boundary-Level Narrow-Only Enforcement in `merge()`

**File:** `src/wardline/manifest/merge.py`

The existing `_check_boundary_tier()` helper uses `boundary.function` as a
lookup key into a tier map keyed by `TierEntry.id` — these are different
namespaces (function qualnames vs tier identifiers like `"AUDIT_TRAIL"`), so
the check as written would never fire. **Rewrite the check** to enforce the
actual invariant:

**Invariant:** A boundary's `from_tier` or `to_tier` value must not exceed the
module-level tier for the module containing that function. This requires
resolving the boundary's function to its module tier.

**Implementation:** `merge()` reads `base.tiers` and `base.module_tiers`
directly from the `WardlineManifest` parameter (no additional parameters —
the data is already on `base`). Resolution requires a two-step join:

1. Build `{tier_id: tier_number}` from `base.tiers`
2. Build `{module_path: tier_number}` by resolving each `ModuleTierEntry`'s
   `default_taint` (a tier ID string like `"EXTERNAL_RAW"` that matches
   `TierEntry.id` — verified against `wardline.yaml`) through the tier map
3. For each boundary, find the most-specific (longest) module path prefix
   matching `boundary.function`
4. If the boundary's `from_tier` or `to_tier` exceeds the module's resolved
   tier number, raise `ManifestWidenError`

Extract the prefix-matching logic into a named helper
`_resolve_module_tier(function, module_tiers, tier_number_map) -> int | None`
for independent testability.

Boundaries in modules with no `module_tiers` entry pass without error (no
baseline to enforce against).

**Tests (unit):**
- Boundary `from_tier` exceeds module tier → `ManifestWidenError` with correct
  `overlay_name`, `field_name`, `base_value`, `attempted_value`
- Boundary `to_tier` exceeds module tier → `ManifestWidenError` (assert all
  four error fields)
- Boundary tightens (lower than module tier) → passes, boundary in result
- Boundary same as module tier → passes
- Boundary function has no matching module tier → passes
- **Overlapping module paths**: two `ModuleTierEntry` entries (`"adapters"`
  and `"adapters.partner"`), boundary matches the more specific one
- Boundary with both `from_tier` and `to_tier` set, only one exceeds →
  error names the offending field
- Boundary with `from_tier`/`to_tier` both `None` → passes (no tier claim)
- **Existing `test_boundary_with_tier_accepted`** must be converted to a
  negative test (it currently asserts widening is accepted — under the new
  spec this must raise `ManifestWidenError`)

## Change 2: Boundary Resolution + `ScanContext` Injection

**Files:** `src/wardline/manifest/resolve.py` (new),
`src/wardline/scanner/context.py`, `src/wardline/scanner/engine.py`

### Boundary resolution (new module)

Extract boundary resolution into a standalone function in the manifest package:

```python
# src/wardline/manifest/resolve.py
def resolve_boundaries(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[BoundaryEntry, ...]:
    """Discover overlays, merge each with the manifest, return all boundaries."""
```

This keeps the engine as a consumer of resolved config, not an implementer
of resolution logic. The engine calls `resolve_boundaries()` once and receives
an opaque tuple.

**Error handling:**
- `GovernanceError` (overlay in undeclared directory): **propagate** — this is
  a policy violation, not a recoverable error. Scan should abort.
- `ManifestWidenError` (boundary tier exceeds module tier): **propagate** —
  same rationale. Policy violation = hard failure.
- `ManifestLoadError`, `OSError`, YAML parse errors from overlay loading:
  **log warning + continue with `boundaries=()`** — consistent with the
  engine's fault-tolerant pattern for file-level I/O errors.

### ScanContext change

Add `boundaries: tuple[BoundaryEntry, ...] = ()` to `ScanContext`. Import
`BoundaryEntry` under `TYPE_CHECKING` guard (same pattern as existing
type-only imports; safe because `context.py` has `from __future__ import
annotations`).

### Engine wiring

- Remove `project_root` from engine — instead, the caller (CLI or test)
  calls `resolve_boundaries()` and passes the result to the engine
- `ScanEngine.__init__()` gains `boundaries: tuple[BoundaryEntry, ...] = ()`
- Boundaries are stored as an instance attribute (immutable, set at
  construction time, no stale-state risk)
- `_scan_file()` passes `self._boundaries` to the `ScanContext` constructor

**Tests (unit):**
- `ScanContext` with boundaries accessible from rule via `self._context`
- `ScanContext` without boundaries kwarg → backward-compatible, `boundaries == ()`
- `ScanContext.boundaries` is immutable (frozen dataclass enforcement)
- `resolve_boundaries()` with valid overlay → returns boundaries
- `resolve_boundaries()` with `GovernanceError` → propagates
- `resolve_boundaries()` with bad overlay YAML → returns `()`, logs warning
- Engine with `boundaries=()` → rules see empty boundaries (backward compat)

## Change 3: `schema_default()` Overlay Verification in PY-WL-001

**File:** `src/wardline/scanner/rules/py_wl_001.py`

Change `_emit_unverified_default()` to consult `self._context.boundaries`:

1. Guard: if `self._context is None`, treat as ungoverned (no boundaries
   available — emit ERROR).
2. Look up the enclosing function's qualname (`self._current_qualname`) in
   the boundaries tuple. Match requires **all three conditions**:
   - `boundary.function == qualname` (exact qualname match)
   - `boundary.transition` is in `{"construction", "restoration"}` (the
     transitions where `schema_default()` governance applies — a
     `shape_validation` boundary does not govern defaults)
   - The current file path is under the boundary's overlay scope (see
     **Directory scoping** below)
3. **Match found (governed):** Emit finding at `Severity.SUPPRESS` with rule
   ID `PY_WL_001_GOVERNED_DEFAULT` (new enum member) and
   `exceptionability=Exceptionability.TRANSPARENT`. Message indicates overlay
   verification succeeded.
4. **No match (ungoverned):** Emit finding at `Severity.ERROR` with rule ID
   `PY_WL_001`. This is now a standard PY-WL-001 violation — the
   `schema_default()` wrapper provides no governance without a matching
   boundary declaration.

**Note:** Governed `schema_default()` calls intentionally bypass the
taint-severity matrix. The boundary declaration represents governance review
of the data path, which covers the risk regardless of taint state. The taint
is still recorded on the Finding for audit trail purposes but does not
influence severity.

**Directory scoping:** To prevent a boundary from one overlay suppressing
findings in unrelated files (THREAT-012 from security review), boundary
matching must verify the scanned file is within the boundary's overlay scope.

Implementation: Add `overlay_scope: str = ""` to `BoundaryEntry` — populated
during `resolve_boundaries()` from the overlay's `overlay_for` field. The
PY-WL-001 match checks that `self._file_path` starts with `overlay_scope`
(directory prefix match). This ensures boundaries from `adapters/` only
govern files under `adapters/`.

**New rule ID:** Add `PY_WL_001_GOVERNED_DEFAULT = "PY-WL-001-GOVERNED-DEFAULT"`
to `RuleId` enum. Remove `PY_WL_001_UNVERIFIED_DEFAULT` — update all
reference sites (see Change 4).

**Boundary matching — known limitations:**
- Qualname matching is file-local (no file path in qualname). Within the
  same overlay scope directory, two files with identical qualnames would
  both match a boundary. This matches coherence check behavior and is
  acceptable for v0.2.0. Directory scoping (above) limits the blast radius
  to within-directory collisions only.
- Per-field `optional_fields` matching is deferred (tracked:
  `wardline-d7be55cfd4`).

**Qualname format:** Boundary `function` values use file-local dotted names
(e.g., `"ClassName.method_name"`, not module-qualified). This must match the
scanner's `_scope_stack`-based qualname computation in `RuleBase._dispatch`.

**Tests (unit):**
- `schema_default()` with matching boundary (correct qualname + transition +
  scope) → SUPPRESS finding, rule ID `PY_WL_001_GOVERNED_DEFAULT`,
  `exceptionability == TRANSPARENT`
- `schema_default()` without matching boundary → ERROR finding, rule ID
  `PY_WL_001`
- `schema_default()` with boundary for different function → ERROR
- `schema_default()` with boundary wrong transition type (e.g.,
  `shape_validation`) → ERROR
- `schema_default()` with boundary from different overlay scope → ERROR
- `schema_default()` with `self._context is None` → ERROR
- `schema_default()` inside class method `"MyClass.handle"` with matching
  boundary → SUPPRESS
- Case-sensitivity: near-match boundary `"MyClass.Handle"` vs qualname
  `"MyClass.handle"` → ERROR (exact match only)
- Multiple boundaries in context, only one matches → SUPPRESS
- `setdefault(key, schema_default(...))` with matching boundary → SUPPRESS
- Non-`schema_default()` default → ERROR (unchanged behavior)

## Change 4: SARIF + Enum Cleanup

**Files:** `src/wardline/core/severity.py`, `src/wardline/scanner/sarif.py`

**`severity.py`:** Add `PY_WL_001_GOVERNED_DEFAULT`. Remove
`PY_WL_001_UNVERIFIED_DEFAULT`.

**`sarif.py`:** Update `_RULE_SHORT_DESCRIPTIONS` to include
`PY_WL_001_GOVERNED_DEFAULT`. Update `_PSEUDO_RULE_IDS` frozenset to replace
`UNVERIFIED_DEFAULT` with `GOVERNED_DEFAULT`. This ensures `GOVERNED_DEFAULT`
does NOT appear in `wardline.implementedRules`.

**Removal blast radius** (all sites referencing `UNVERIFIED_DEFAULT`):
- `src/wardline/scanner/rules/py_wl_001.py:147` → replaced by Change 3
- `src/wardline/scanner/sarif.py:41` → `_RULE_SHORT_DESCRIPTIONS`
- `src/wardline/scanner/sarif.py:56` → `_PSEUDO_RULE_IDS`
- `tests/unit/scanner/test_py_wl_001.py:131,141` → replaced by new tests
- `tests/unit/core/test_severity.py:39` → update enum membership assertion

The `wardline.conformanceGaps` array is already empty (`[]`). No code change
needed — the behavioral gap is closed by Change 3.

**Tests:**
- `PY_WL_001_GOVERNED_DEFAULT` not in `wardline.implementedRules`
- `wardline.conformanceGaps == []` regression pin

## Files Changed

| File | Change |
|------|--------|
| `src/wardline/manifest/merge.py` | Rewrite `_check_boundary_tier` for module-tier lookup using `base.tiers`/`base.module_tiers`, activate in `merge()`, add `ModuleTierEntry` import |
| `src/wardline/manifest/resolve.py` | **New** — `resolve_boundaries()` function |
| `src/wardline/manifest/models.py` | Add `overlay_scope: str = ""` to `BoundaryEntry` |
| `src/wardline/scanner/context.py` | Add `boundaries` field to `ScanContext` |
| `src/wardline/scanner/engine.py` | Accept `boundaries` in `__init__()`, pass to context |
| `src/wardline/scanner/rules/py_wl_001.py` | Boundary-aware `schema_default()` handling with scope + transition checks |
| `src/wardline/core/severity.py` | Add `PY_WL_001_GOVERNED_DEFAULT`, remove `PY_WL_001_UNVERIFIED_DEFAULT` |
| `src/wardline/scanner/sarif.py` | Update `_RULE_SHORT_DESCRIPTIONS` and `_PSEUDO_RULE_IDS` |
| `tests/unit/manifest/test_merge.py` | Boundary-level narrow-only tests, convert existing widening test |
| `tests/unit/manifest/test_resolve.py` | **New** — `resolve_boundaries()` tests |
| `tests/unit/scanner/test_py_wl_001.py` | Governed vs ungoverned `schema_default()` tests |
| `tests/unit/scanner/test_engine.py` | Engine boundary injection tests |
| `tests/unit/core/test_severity.py` | Update enum membership assertions |
| `tests/unit/scanner/test_sarif.py` | `implementedRules` + `conformanceGaps` assertions |

## Deferred Issues (tracked in filigree)

| ID | Title | Priority |
|----|-------|----------|
| `wardline-f132f7cc55` | [SEC] `overlay_for` path verification not implemented | P1 |
| `wardline-370a95b5f5` | [SEC] Severity reduction in merge contradicts spec §13.1.2 | P1 |
| `wardline-d7be55cfd4` | `schema_default()` governance should check `optional_fields` | P2 |

## Out of Scope

- Multi-overlay merge ordering (deferred to WP 1.4)
- Coherence check updates (existing checks work with boundaries)
- `overlay_for` path verification (pre-existing gap, tracked above)
- Severity reduction enforcement (pre-existing gap, tracked above)
- Per-field `optional_fields` matching (tracked above)
