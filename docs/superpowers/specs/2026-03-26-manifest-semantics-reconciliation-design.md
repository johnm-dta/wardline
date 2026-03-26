# Manifest Semantics Reconciliation Design

**Date:** 2026-03-26
**Status:** Approved (revised after 5-panel review)
**Spec requirements:** WL-FIT-CORE-006, WL-FIT-MAN-004

## Problem

The manifest layer has three conformance failures against the normative spec (§13.1.2):

1. **Terminology drift.** The implementation uses `bounded_context` where the spec requires `validation_scope`. This affects the overlay JSON Schema, `BoundaryEntry` dataclass, loader, coherence checks, CLI output, and tests.

2. **Missing skip-promotion rejection.** The spec requires that `to_tier: 1` is valid only when `from_tier: 2`. Skip-promotions (`from_tier: 3, to_tier: 1` and `from_tier: 4, to_tier: 1`) must be rejected. Neither the schema nor the loader enforces this.

3. **Missing `validation_scope` presence-check.** Boundaries claiming Tier 2 semantics (`semantic_validation`, `combined_validation`, and `restoration` with `provenance.semantic: true`) must include a `validation_scope` object. No code checks this.

## Decisions

- **No backward compatibility.** Pre-1.0 project with no external adopters. Clean rename, no deprecation shim.
- **Skip-promotion rejection at loader level.** The spec says "schema-invalid" but loader-level validation produces actionable error messages with function name and file context. Hard `ManifestLoadError`.
- **Validation-scope presence-check at coherence level with ERROR severity.** The spec says "is a finding." Registered in `COHERENCE_SEVERITY_MAP` as `"ERROR"` so it gates CI via `--gate`. A boundary claiming Tier 2 semantics without declaring its validation contracts is a structural integrity gap, not a style warning.

## Design

### Change 1: `bounded_context` to `validation_scope` rename

Mechanical rename across all layers. No structural change to the field type (`MappingProxyType[str, object] | None`).

| File | Change |
|------|--------|
| `src/wardline/manifest/schemas/overlay.schema.json` (lines 58-87) | Rename `bounded_context` property to `validation_scope` |
| `src/wardline/manifest/models.py` (line 158) | Rename `BoundaryEntry.bounded_context` to `validation_scope`; update both `isinstance` guard and `object.__setattr__` call in `__post_init__` (lines 167-169) |
| `src/wardline/manifest/loader.py` (line 269) | Change `b.get("bounded_context")` to `b.get("validation_scope")` |
| `src/wardline/manifest/coherence.py` (module docstring at line 8; function `check_unmatched_contracts` at line 452 including docstring at 456-458, attribute access at lines 476/479, and detail string at line 494) | Update all `bounded_context` references to `validation_scope` |
| `src/wardline/cli/resolve_cmd.py` (line 156) | Update CLI JSON output key |
| `src/wardline/cli/scan.py` (line 748) | Update inline overlay builder key |

**Atomic rename constraint:** `resolve_cmd.py` output key and `scan.py` input key must rename in the same commit. If one side renames and the other does not, `validation_scope` silently becomes `None` for all boundaries in the scan pipeline, producing false-positive coherence findings on every Tier 2 boundary.

**Resolved JSON cache:** The `_load_resolved()` path in `scan.py` constructs `BoundaryEntry` objects from cached JSON. After the rename, any stale `wardline.resolved.json` files written with the old `bounded_context` key will produce `validation_scope=None` for all entries. The rename must include the resolved JSON serialization path, and stale caches must be invalidated (e.g., by bumping a format version or deleting the cache on schema version change).

### Change 2: Skip-promotion rejection

Add a dedicated validation loop at the top of `_build_overlay()` in `loader.py` (line 259), before the existing boundary generator expression. This keeps the existing generator intact and separates concerns.

The guard checks transition type to exclude restoration boundaries (which use `restored_tier`, not `to_tier`) rather than relying on `from_tier is not None` — this closes the bypass where omitting `from_tier` on a construction boundary would escape the check.

```python
def _build_overlay(data: dict[str, Any]) -> WardlineOverlay:
    """Construct a WardlineOverlay from validated data."""
    # Reject skip-promotions: to_tier=1 is valid only from from_tier=2 (§13.1.2).
    for b in data.get("boundaries", []):
        to_tier = b.get("to_tier")
        if to_tier == 1 and b.get("transition") != "restoration":
            from_tier = b.get("from_tier")
            if from_tier != 2:
                raise ManifestLoadError(
                    f"Boundary '{b.get('function', '<unknown>')}' declares "
                    f"from_tier={from_tier}, to_tier=1 — skip-promotions to "
                    f"Tier 1 are prohibited. Use composed steps: "
                    f"validation to T2, then T2→T1 construction (§13.1.2)."
                )

    boundaries = tuple(  # existing generator follows unchanged
        ...
    )
```

This is a hard `ManifestLoadError`. An overlay with a skip-promotion does not load.

**Error propagation:** `resolve.py` (line 47) catches `ManifestLoadError` and continues, which would silently swallow skip-promotion rejections. The catch site must distinguish I/O errors (continue) from policy errors (propagate). Either re-raise policy `ManifestLoadError` subclasses or log at ERROR level with a distinct prefix that CI can detect.

**Tests** (in `tests/unit/manifest/test_loader.py`, new `TestSkipPromotionRejection` class):

| Case | Expected |
|------|----------|
| `from_tier=4, to_tier=1` | `ManifestLoadError` |
| `from_tier=3, to_tier=1` | `ManifestLoadError` |
| `from_tier=None, to_tier=1` (no `from_tier` key) | `ManifestLoadError` |
| `from_tier=2, to_tier=1` | Loads (construction boundary) |
| `from_tier=4, to_tier=2` | Loads (combined validation) |
| `transition="restoration", restored_tier=1` (no `to_tier`) | Loads (restoration, not a skip-promotion) |

### Change 3: `validation_scope` presence-check

New function `check_validation_scope_presence()` in `coherence.py`. Returns `CoherenceIssue` entries with `kind="missing_validation_scope"`.

A boundary needs `validation_scope` when:
- `transition` is `"semantic_validation"` or `"combined_validation"`, OR
- `transition` is `"restoration"` AND `provenance.semantic` is `True`

```python
def check_validation_scope_presence(
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    issues = []
    for boundary in boundaries:
        needs_scope = boundary.transition in (
            "semantic_validation", "combined_validation",
        ) or (
            boundary.transition == "restoration"
            and boundary.provenance is not None
            and boundary.provenance.get("semantic") is True
        )
        if needs_scope and boundary.validation_scope is None:
            issues.append(CoherenceIssue(
                kind="missing_validation_scope",
                function=boundary.function,
                file_path=boundary.overlay_path,
                detail=(
                    f"Boundary '{boundary.function}' claims Tier 2 semantics "
                    f"(transition={boundary.transition}) but has no "
                    f"validation_scope declaration (§13.1.2)."
                ),
            ))
    return issues
```

**Wiring:** Add to `src/wardline/cli/coherence_cmd.py` alongside the existing `check_unmatched_contracts` and `check_tier_topology_consistency` calls (lines 173-183). Update the comment at line 137 ("Run all 11 checks" → "Run all 12 checks"). The call signature matches: `check_validation_scope_presence(boundaries)`.

**Severity registration:** Add to `src/wardline/cli/_helpers.py` `COHERENCE_SEVERITY_MAP`:
```python
"missing_validation_scope": "ERROR",
```
Add to `src/wardline/cli/coherence_cmd.py` `CATEGORY_MAP`:
```python
"missing_validation_scope": "enforcement",
```

Without these entries, the finding defaults to `"WARNING"` via `.get()` fallback and the `--gate` flag cannot act on it — making the check structurally unable to block CI.

**Tests** (in `tests/unit/manifest/test_coherence.py`, new `TestValidationScopePresence` class):

| Case | Expected |
|------|----------|
| Empty boundaries tuple | No issues |
| `semantic_validation` without `validation_scope` | Issue |
| `combined_validation` without `validation_scope` | Issue |
| `restoration` + `provenance.semantic=True` without `validation_scope` | Issue |
| `restoration` + `provenance.semantic=False` without `validation_scope` | No issue |
| `restoration` + `provenance=None` without `validation_scope` | No issue |
| `shape_validation` without `validation_scope` | No issue |
| `semantic_validation` with `validation_scope` present | No issue |
| `combined_validation` with `validation_scope` present | No issue |
| Mixed list: one `semantic_validation` missing scope + one `shape_validation` | Issue only for the first |

**Regression test for rename:** Add one test case to existing `TestUnmatchedContracts` that exercises `check_unmatched_contracts` with a non-None `validation_scope` (post-rename), confirming the renamed attribute is read correctly.

## Files touched

**Production code:**
- `src/wardline/manifest/schemas/overlay.schema.json`
- `src/wardline/manifest/models.py`
- `src/wardline/manifest/loader.py`
- `src/wardline/manifest/coherence.py`
- `src/wardline/cli/resolve_cmd.py`
- `src/wardline/cli/scan.py` (both inline builder at line 748 and `_load_resolved()` cache path)
- `src/wardline/cli/coherence_cmd.py` (wiring + `CATEGORY_MAP`)
- `src/wardline/cli/_helpers.py` (`COHERENCE_SEVERITY_MAP`)

**Tests:**
- `tests/unit/manifest/test_loader.py`
- `tests/unit/manifest/test_coherence.py`

**Fixtures:**
- `tests/fixtures/governance/overlays/src/wardline.overlay.yaml` (no change needed — does not use `bounded_context`)

**Fitness spec update:** Update `WL-FIT-MAN-004.verification.target_paths` in `docs/requirements/spec-fitness/02-manifest-governance.yaml` to include `tests/unit/manifest/test_coherence.py`.

## Out of scope

- Cross-validation between `validation_scope.contracts[*].name` and `contract_bindings` entries (minor integrity gap, not yet filed).
- Typed `ContractDeclaration` dataclass replacing raw dicts inside `validation_scope` (improvement, not spec-required, not yet filed).
- JSON Schema `if/then` constraint for skip-promotions (loader enforcement is sufficient; schema constraint can be added later).
- JSON Schema `if/then` requiring `from_tier` for non-restoration transitions (enforced at loader level instead).
- Transition-to-tier semantic consistency checks beyond skip-promotion (e.g., `construction` must be `from_tier: 2, to_tier: 1`) — tracked as future coherence work.
