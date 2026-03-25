# WP 1.3: Overlay System — Plan Errata (Post-Panel Review)

> **For agentic workers:** Read this BEFORE executing the plan. These corrections
> override the corresponding sections in
> `docs/superpowers/plans/2026-03-23-overlay-system.md`.

---

## E1: Task 2 — `_resolve_module_tier` namespace fix (CRITICAL)

**Problem:** The plan's `_resolve_module_tier` uses `function.startswith(mt.path)`
where `function` is a file-local qualname (`"Handler.handle"`) and `mt.path` is
a slash-separated directory path (`"src/adapters"`). These never match.

**Fix:** `_resolve_module_tier` should resolve the boundary's **overlay scope**
to a module tier, not the boundary's function qualname. The overlay scope IS a
directory path that can be prefix-matched against `module_tiers` paths.

Change the signature and implementation:

```python
def _resolve_module_tier(
    overlay_scope: str,
    module_tiers: tuple[ModuleTierEntry, ...],
    tier_number_map: dict[str, int],
) -> int | None:
    """Resolve the module tier for a boundary's overlay scope via longest prefix.

    Returns the tier number, or None if no module tier covers the overlay scope.
    """
    best_match: int | None = None
    best_length = -1

    for mt in module_tiers:
        # Path-segment-safe prefix check (E5)
        if (
            overlay_scope == mt.path
            or overlay_scope.startswith(mt.path + "/")
        ) and len(mt.path) > best_length:
            tier_num = tier_number_map.get(mt.default_taint)
            if tier_num is not None:
                best_match = tier_num
                best_length = len(mt.path)

    return best_match
```

In `merge()`, pass `overlay.overlay_for` (available via the overlay parameter)
instead of `boundary.function`:

```python
    # Resolve module tier from the overlay's governed directory
    tier_number_map: dict[str, int] = {t.id: t.tier for t in base.tiers}
    module_tier = _resolve_module_tier(
        overlay.overlay_for, base.module_tiers, tier_number_map
    )
    if module_tier is not None:
        for boundary in resolved_boundaries:
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

**Update Task 2 tests accordingly** — use `overlay.overlay_for` paths in module
tier entries, not boundary function qualnames.

---

## E2: Task 3 — `resolve_boundaries()` exception handling (CRITICAL)

**Problem:** `except (ManifestLoadError, OSError, Exception)` catches `Exception`,
which subsumes everything including `ManifestWidenError`. Since `merge()` is
called inside the for loop after `load_overlay()`, `ManifestWidenError` from
`merge()` gets swallowed.

**Fix:** Restructure the loop so `merge()` is outside the try/except for load
errors. `ManifestWidenError` and `GovernanceError` must propagate.

```python
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except (ManifestLoadError, OSError) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        # merge() is OUTSIDE the try — ManifestWidenError propagates
        resolved = merge(manifest, overlay)

        for boundary in resolved.boundaries:
            scoped = replace(boundary, overlay_scope=overlay.overlay_for)
            all_boundaries.append(scoped)
```

Remove the bare `Exception` catch entirely. Only catch known recoverable
error types.

---

## E3: Task ordering — Swap Tasks 5 and 6 (HIGH)

**Problem:** Task 5 removes `PY_WL_001_UNVERIFIED_DEFAULT` from `RuleId` before
Task 6 updates `py_wl_001.py` and its tests. Between commits, the codebase has
broken imports.

**Fix:** Execute in this order:
1. Task 6 FIRST (boundary-aware rule + new tests that use `GOVERNED_DEFAULT`)
2. Task 5 SECOND (enum rename + SARIF cleanup)

In Task 6, temporarily add `PY_WL_001_GOVERNED_DEFAULT` to `RuleId` alongside
`UNVERIFIED_DEFAULT`. Task 5 then removes `UNVERIFIED_DEFAULT` and updates the
remaining references (`sarif.py`, `test_severity.py`).

Also in Task 5: update `test_all_pseudo_rules_are_members` (test_severity.py
line 52-62) to replace `UNVERIFIED_DEFAULT` with `GOVERNED_DEFAULT`.

---

## E4: `overlay_scope=""` must NOT match all files (HIGH)

**Problem:** `startswith("")` is always True, so empty scope defeats directory
scoping (THREAT-012 mitigation).

**Fix:** In `_is_governed_by_boundary()`, require non-empty scope:

```python
    def _is_governed_by_boundary(self) -> bool:
        if self._context is None:
            return False

        for boundary in self._context.boundaries:
            if (
                boundary.function == self._current_qualname
                and boundary.transition in self._GOVERNED_TRANSITIONS
                and boundary.overlay_scope  # non-empty required
                and self._file_path.startswith(boundary.overlay_scope + "/")
            ):
                return True
        return False
```

**Update all tests** that use `overlay_scope=""` — replace with the actual
test directory prefix (e.g., `overlay_scope="test.py"` or
`overlay_scope=""` with the file path matching). Use a helper to set both
consistently.

Better approach for tests: use `overlay_scope="test"` and
`file_path="test.py"` so the match works via `"test.py".startswith("test")`.

Actually, since the separator check uses `+ "/"`, test overlays should use
scope paths that end WITHOUT a slash, matching how `overlay_for` values work
in real overlays (e.g., `overlay_scope="adapters"` matches
`"adapters/handler.py"`).

For the test helper `_run_rule_with_context`, default `file_path` and
`overlay_scope` should be set so governed tests pass:

```python
def _run_rule_with_context(
    source: str,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    file_path: str = "src/adapters/handler.py",
) -> RulePyWl001:
```

And governed test boundaries should use `overlay_scope="src/adapters"`.

---

## E5: Path prefix collision fix (HIGH)

**Problem:** `"adapt"` matches `"adapters/"` via `startswith`.

**Fix:** Already incorporated in E1 and E4 above — both `_resolve_module_tier`
and `_is_governed_by_boundary` now use `startswith(scope + "/")` instead of
bare `startswith(scope)`.

---

## E6: CLI exception handling (HIGH)

**Problem:** `except Exception` in Task 4 Step 9 swallows `GovernanceError`
and `ManifestWidenError`.

**Fix:**

```python
    boundaries: tuple[BoundaryEntry, ...] = ()
    if manifest_model is not None:
        from wardline.manifest.resolve import resolve_boundaries
        # GovernanceError and ManifestWidenError propagate —
        # caught by the CLI's top-level error handler
        boundaries = resolve_boundaries(scan_root, manifest_model)
```

Use `scan_root` (the resolved scan path, already available) instead of
`manifest_path.parent` (which is not in scope). Do NOT wrap in try/except —
let policy violations propagate to the CLI's existing error handler.

---

## E7: Ungoverned severity — unconditional ERROR (MEDIUM)

**Problem:** Plan uses `matrix.lookup()` for ungoverned `schema_default()` but
spec says unconditional ERROR.

**Fix:** In `_emit_unverified_default`, ungoverned path:

```python
        else:
            taint = self._get_function_taint(self._current_qualname)
            self.findings.append(
                Finding(
                    rule_id=RuleId.PY_WL_001,
                    ...
                    severity=Severity.ERROR,
                    exceptionability=Exceptionability.STANDARD,
                    taint_state=taint,  # recorded for audit, not used for severity
                    ...
                )
            )
```

---

## E8: Add missing test — positive non-empty scope (MEDIUM)

Add to Task 6 tests:

```python
    def test_matching_scope_suppresses(self) -> None:
        boundary = BoundaryEntry(
            function="test_fn",
            transition="construction",
            overlay_scope="src/adapters",
        )
        rule = _run_rule_with_context(
            'd.get("key", schema_default("x"))\n',
            boundaries=(boundary,),
            file_path="src/adapters/handler.py",
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT
```

---

## E9: Add missing test — `ManifestWidenError` propagation from `resolve_boundaries()` (MEDIUM)

Add to Task 3 tests:

```python
    def test_manifest_widen_error_propagates(self, tmp_path: Path) -> None:
        overlay_dir = tmp_path / "core"
        overlay_dir.mkdir()
        _write_overlay(
            overlay_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/0.1/overlay.schema.json"\n'
                "overlay_for: core\n"
                "boundaries:\n"
                '  - function: "Handler.handle"\n'
                '    transition: "construction"\n'
                "    from_tier: 4\n"  # module is tier 1 — widening
            ),
        )
        manifest = WardlineManifest(
            module_tiers=(ModuleTierEntry(path="core", default_taint="AUDIT_TRAIL"),),
            tiers=(
                TierEntry(id="AUDIT_TRAIL", tier=1),
                TierEntry(id="EXTERNAL_RAW", tier=4),
            ),
        )
        from wardline.manifest.merge import ManifestWidenError
        with pytest.raises(ManifestWidenError):
            resolve_boundaries(tmp_path, manifest)
```
