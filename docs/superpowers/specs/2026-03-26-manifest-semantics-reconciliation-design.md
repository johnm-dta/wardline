# Manifest Semantics Reconciliation Design

**Date:** 2026-03-26
**Status:** Approved
**Spec requirements:** WL-FIT-CORE-006, WL-FIT-MAN-004

## Problem

The manifest layer has three conformance failures against the normative spec (§13.1.2):

1. **Terminology drift.** The implementation uses `bounded_context` where the spec requires `validation_scope`. This affects the overlay JSON Schema, `BoundaryEntry` dataclass, loader, coherence checks, CLI output, and tests.

2. **Missing skip-promotion rejection.** The spec requires that `to_tier: 1` is valid only when `from_tier: 2`. Skip-promotions (`from_tier: 3, to_tier: 1` and `from_tier: 4, to_tier: 1`) must be rejected. Neither the schema nor the loader enforces this.

3. **Missing `validation_scope` presence-check.** Boundaries claiming Tier 2 semantics (`semantic_validation`, `combined_validation`, and `restoration` with `provenance.semantic: true`) must include a `validation_scope` object. No code checks this.

## Decisions

- **No backward compatibility.** Pre-1.0 project with no external adopters. Clean rename, no deprecation shim.
- **Skip-promotion rejection at loader level.** The spec says "schema-invalid" but loader-level validation produces actionable error messages with function name and file context. Hard `ManifestLoadError`.
- **Validation-scope presence-check at coherence level.** The spec says "is a finding," not "is a load error." This matches the existing coherence-check pattern where topology issues are surfaced as `CoherenceIssue` entries.

## Design

### Change 1: `bounded_context` to `validation_scope` rename

Mechanical rename across all layers. No structural change to the field type (`MappingProxyType[str, object] | None`).

| File | Change |
|------|--------|
| `src/wardline/manifest/schemas/overlay.schema.json` (lines 58-87) | Rename `bounded_context` property to `validation_scope` |
| `src/wardline/manifest/models.py` (line 158) | Rename `BoundaryEntry.bounded_context` to `validation_scope`, update `__post_init__` |
| `src/wardline/manifest/loader.py` (line 269) | Change `b.get("bounded_context")` to `b.get("validation_scope")` |
| `src/wardline/manifest/coherence.py` (function `check_unmatched_contracts` at line 452, including docstring at 456-458) | Update all `bounded_context` references |
| `src/wardline/cli/resolve_cmd.py` (line 156) | Update CLI output key |
| `src/wardline/cli/scan.py` (line 748) | Update inline overlay builder |
| `tests/unit/manifest/test_coherence.py` | Update ~8 test references |

### Change 2: Skip-promotion rejection

Add a dedicated validation loop at the top of `_build_overlay()` in `loader.py` (line 259), before the existing boundary generator expression. This keeps the existing generator intact and separates concerns.

Restoration boundaries use `restored_tier` rather than `to_tier`, so the `to_tier == 1` guard naturally excludes them.

```python
def _build_overlay(data: dict[str, Any]) -> WardlineOverlay:
    """Construct a WardlineOverlay from validated data."""
    # Reject skip-promotions to Tier 1 (§13.1.2).
    for b in data.get("boundaries", []):
        to_tier = b.get("to_tier")
        from_tier = b.get("from_tier")
        if to_tier == 1 and from_tier is not None and from_tier != 2:
            raise ManifestLoadError(
                f"Boundary '{b['function']}' declares from_tier={from_tier}, "
                f"to_tier=1 — skip-promotions to Tier 1 are prohibited. "
                f"Use composed steps: T{from_tier}→...→T2 validation, "
                f"then T2→T1 construction (§13.1.2)."
            )

    boundaries = tuple(  # existing generator follows unchanged
        ...
    )
```

This is a hard `ManifestLoadError`. An overlay with a skip-promotion does not load.

**Tests** (in `tests/unit/manifest/test_loader.py`):

| Case | Expected |
|------|----------|
| `from_tier=4, to_tier=1` | `ManifestLoadError` |
| `from_tier=3, to_tier=1` | `ManifestLoadError` |
| `from_tier=2, to_tier=1` | Loads (construction boundary) |
| `from_tier=4, to_tier=2` | Loads (combined validation) |

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

Wire into `src/wardline/cli/coherence_cmd.py` alongside the existing `check_unmatched_contracts` and `check_tier_topology_consistency` calls (lines 173-183). The call signature matches: `check_validation_scope_presence(boundaries)`.

**Tests** (in `tests/unit/manifest/test_coherence.py`):

| Case | Expected |
|------|----------|
| `semantic_validation` without `validation_scope` | Issue |
| `combined_validation` without `validation_scope` | Issue |
| `restoration` + `provenance.semantic=True` without `validation_scope` | Issue |
| `restoration` + `provenance.semantic=False` without `validation_scope` | No issue |
| `restoration` + `provenance=None` without `validation_scope` | No issue |
| `shape_validation` without `validation_scope` | No issue |
| `semantic_validation` with `validation_scope` present | No issue |

## Files touched

**Production code:**
- `src/wardline/manifest/schemas/overlay.schema.json`
- `src/wardline/manifest/models.py`
- `src/wardline/manifest/loader.py`
- `src/wardline/manifest/coherence.py`
- `src/wardline/cli/resolve_cmd.py`
- `src/wardline/cli/scan.py`

**Tests:**
- `tests/unit/manifest/test_loader.py`
- `tests/unit/manifest/test_coherence.py`

**Fixtures (if using `bounded_context`):**
- `tests/fixtures/governance/overlays/src/wardline.overlay.yaml` (no change needed — does not use `bounded_context`)

**Fitness spec update:** Update `WL-FIT-MAN-004.verification.target_paths` in `docs/requirements/spec-fitness/02-manifest-governance.yaml` to include `tests/unit/manifest/test_coherence.py`.

## Out of scope

- Cross-validation between `validation_scope.contracts[*].name` and `contract_bindings` entries (minor integrity gap, not yet filed).
- Typed `ContractDeclaration` dataclass replacing raw dicts inside `validation_scope` (improvement, not spec-required, not yet filed).
- JSON Schema `if/then` constraint for skip-promotions (loader enforcement is sufficient; schema constraint can be added later).
