# SARIF Run-Level Property Bag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the four missing SARIF run-level properties (`inputHash`, `inputFiles`, `overlayHashes`, `coverageRatio`), fix the `manifestHash` spec mismatch, and refactor overlay path handling to use the actual consumed overlay set.

**Architecture:** Pre-computed values flow from CLI helpers into `SarifReport` dataclass fields, maintaining the existing pattern where `SarifReport` is a pure data→dict serializer. `resolve_boundaries()` returns consumed overlay paths alongside boundaries. The scan engine exposes which files it analysed via `scanned_file_paths` on `ScanResult`.

**Tech Stack:** Python 3.12+, pytest, hashlib (SHA-256), frozen dataclasses

**Spec:** `docs/superpowers/specs/2026-03-27-sarif-run-level-properties-design.md`

---

### Task 1: Add `scanned_file_paths` to `ScanResult`

**Files:**
- Modify: `src/wardline/scanner/engine.py:64-72` (ScanResult dataclass)
- Modify: `src/wardline/scanner/engine.py:251` (_scan_file method)
- Test: `tests/unit/scanner/test_engine.py` (existing)

- [ ] **Step 1: Write failing test for scanned_file_paths**

Add to `tests/unit/scanner/test_engine.py`:

```python
class TestScanResultFileTracking:
    def test_scanned_file_paths_populated(self, tmp_path: Path) -> None:
        """Engine records the paths of files it successfully scanned."""
        py_file = tmp_path / "example.py"
        py_file.write_text("x = 1\n", encoding="utf-8")

        from wardline.scanner.engine import ScanEngine, ScanResult
        from wardline.manifest.models import WardlineManifest

        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(),
            rules=(),
            manifest=WardlineManifest(),
            boundaries=(),
            optional_fields=(),
            analysis_level=1,
        )
        result = engine.scan()
        assert len(result.scanned_file_paths) == 1
        assert result.scanned_file_paths[0] == py_file.resolve()

    def test_scanned_file_paths_excludes_skipped(self, tmp_path: Path) -> None:
        """Files that fail to parse are not in scanned_file_paths."""
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def broken(\n", encoding="utf-8")

        from wardline.scanner.engine import ScanEngine, ScanResult
        from wardline.manifest.models import WardlineManifest

        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(),
            rules=(),
            manifest=WardlineManifest(),
            boundaries=(),
            optional_fields=(),
            analysis_level=1,
        )
        result = engine.scan()
        assert result.scanned_file_paths == []
        assert result.files_skipped == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/scanner/test_engine.py::TestScanResultFileTracking -v`
Expected: FAIL — `ScanResult` has no `scanned_file_paths` attribute.

- [ ] **Step 3: Add `scanned_file_paths` field to `ScanResult`**

In `src/wardline/scanner/engine.py`, add the field to the dataclass (after `errors`):

```python
@dataclass
class ScanResult:
    """Aggregated result of a scan run."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    files_with_degraded_taint: int = 0
    errors: list[str] = field(default_factory=list)
    scanned_file_paths: list[Path] = field(default_factory=list)
```

Add the import for `Path` at the top of the file if not already present (check — `Path` is already imported for `_read_python_source`).

In `_scan_file()`, right after `result.files_scanned += 1` (line 251), add:

```python
        result.files_scanned += 1
        result.scanned_file_paths.append(file_path)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/scanner/test_engine.py::TestScanResultFileTracking -v`
Expected: PASS

- [ ] **Step 5: Run full engine test suite to check for regressions**

Run: `pytest tests/unit/scanner/test_engine.py -v`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/engine.py tests/unit/scanner/test_engine.py
git commit -m "feat(engine): add scanned_file_paths to ScanResult for inputHash computation"
```

---

### Task 2: Change `resolve_boundaries()` return signature

**Files:**
- Modify: `src/wardline/manifest/resolve.py:31-85`
- Modify: `src/wardline/cli/scan.py:385`
- Modify: `src/wardline/cli/resolve_cmd.py:62`
- Modify: `src/wardline/cli/coherence_cmd.py:128`
- Modify: `src/wardline/cli/regime_cmd.py:79`
- Modify: `src/wardline/cli/explain_cmd.py:380`
- Modify: `tests/unit/manifest/test_resolve.py`
- Modify: `tests/unit/manifest/test_loader.py:231`
- Test: `tests/unit/manifest/test_resolve.py`

- [ ] **Step 1: Write failing test for tuple return**

Add to `tests/unit/manifest/test_resolve.py` inside `TestResolveBoundaries`:

```python
    def test_returns_boundaries_and_overlay_paths(self, tmp_path: Path) -> None:
        """resolve_boundaries() returns (boundaries, overlay_paths) tuple."""
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

        boundaries, overlay_paths = resolve_boundaries(tmp_path, manifest)

        assert len(boundaries) == 1
        assert len(overlay_paths) == 1
        assert overlay_paths[0] == overlay_dir / "wardline.overlay.yaml"

    def test_no_overlays_returns_empty_tuple_pair(self, tmp_path: Path) -> None:
        """No overlays returns ((), ())."""
        manifest = _minimal_manifest()
        boundaries, overlay_paths = resolve_boundaries(tmp_path, manifest)
        assert boundaries == ()
        assert overlay_paths == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/manifest/test_resolve.py::TestResolveBoundaries::test_returns_boundaries_and_overlay_paths -v`
Expected: FAIL — `resolve_boundaries()` returns a single tuple, not a pair.

- [ ] **Step 3: Update `resolve_boundaries()` to return `(boundaries, overlay_paths)` pair**

In `src/wardline/manifest/resolve.py`, change the function signature and return:

```python
def resolve_boundaries(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[tuple[BoundaryEntry, ...], tuple[Path, ...]]:
    """Discover overlays, merge each with *manifest*, return boundaries and overlay paths.

    Returns:
        (boundaries, discovered_overlay_paths) — the overlay paths are the
        full discovered set from ``discover_overlays()``, including any that
        failed to load (for policy hashing completeness).

    Error handling:
    - ``GovernanceError`` / ``ManifestWidenError``: propagate (policy violation).
    - I/O / parse errors from individual overlay files: log + skip.
    """
    overlay_paths = discover_overlays(root, manifest)

    all_boundaries: list[BoundaryEntry] = []
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except ManifestPolicyError:
            raise  # Policy violations (e.g. skip-promotion) must propagate
        except (ManifestLoadError, OSError) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        # Verify overlay_for matches actual file location
        overlay_dir = str(overlay_path.parent.relative_to(root))
        if not relative_path_within_scope(
            overlay_dir,
            overlay.overlay_for.rstrip("/"),
        ):
            raise GovernanceError(
                f"Overlay at {overlay_path} claims overlay_for='{overlay.overlay_for}' "
                f"but is located in '{overlay_dir}'"
            )

        # merge() is OUTSIDE the try — ManifestWidenError propagates
        resolved = merge(manifest, overlay)

        # Surface governance signals so they appear in verbose output.
        for signal in resolved.governance_signals:
            logger.warning("Governance signal [%s]: %s", overlay_path, signal)

        # Tag each boundary with the overlay's ABSOLUTE scope path
        scope = str((root / overlay.overlay_for).resolve())
        rel_overlay = str(overlay_path.relative_to(root))
        seen_functions: set[str] = set()
        for boundary in resolved.boundaries:
            if boundary.function in seen_functions:
                raise GovernanceError(
                    "Duplicate boundary declaration for function "
                    f"'{boundary.function}' in overlay '{rel_overlay}'"
                )
            seen_functions.add(boundary.function)
            scoped = replace(boundary, overlay_scope=scope, overlay_path=rel_overlay)
            all_boundaries.append(scoped)

    return tuple(all_boundaries), tuple(overlay_paths)
```

- [ ] **Step 4: Fix existing tests in test_resolve.py that unpack the old return**

Update all existing `resolve_boundaries()` call sites in `tests/unit/manifest/test_resolve.py` to unpack the tuple. Each call like:

```python
result = resolve_boundaries(tmp_path, manifest)
```

becomes:

```python
result, _ = resolve_boundaries(tmp_path, manifest)
```

The tests that check `result == ()` or `len(result)` stay the same — they just operate on the first element now. The specific call sites to update (each is a `resolve_boundaries(tmp_path, ...)` call):

- `test_no_overlays_returns_empty` (line 44)
- `test_overlay_boundaries_returned_with_scope` (line 62)
- `test_governance_error_propagates` (line 84) — inside `pytest.raises`, no change needed
- `test_manifest_widen_error_propagates` (line 110) — inside `pytest.raises`, no change needed
- `test_bad_overlay_file_skipped` (line 122)
- `test_overlay_for_path_mismatch_raises` — inside `pytest.raises`, no change needed
- Any others visible in the file — apply the same `result, _ =` pattern

- [ ] **Step 5: Fix test_loader.py call site**

In `tests/unit/manifest/test_loader.py`, the call at line 231 is inside `pytest.raises(GovernanceError)`, so no unpacking change is needed — the function raises before returning.

- [ ] **Step 6: Fix all 5 production callers**

**`src/wardline/cli/scan.py:385`** — this is the primary consumer that needs overlay paths:

```python
        try:
            boundaries, consumed_overlay_paths = resolve_boundaries(
                manifest_path.parent, manifest_model
            )
        except _PolicyError as exc:
```

Also declare `consumed_overlay_paths` with the other defaults near line 357:

```python
    boundaries: tuple[_BoundaryEntry, ...] = ()
    optional_fields: tuple[object, ...] = ()
    consumed_overlay_paths: tuple[Path, ...] = ()
    resolved_rule_overrides: tuple[dict[str, object], ...] | None = None
```

Add `from pathlib import Path` if not already imported (it is — check).

**`src/wardline/cli/resolve_cmd.py:62`** — only needs boundaries. Also collapse the redundant `discover_overlays()` call at line 66:

```python
    boundaries, overlay_file_paths = resolve_boundaries(root, manifest_model)
    optional_fields = resolve_optional_fields(root, manifest_model)

    # overlay_file_paths now comes from resolve_boundaries — no separate discover_overlays() call
```

Remove the line `overlay_file_paths = discover_overlays(root, manifest_model)` at line 66 and its import of `discover_overlays` at line 30 (only if not used elsewhere in this file — check: it is NOT used elsewhere after removing this line).

**`src/wardline/cli/coherence_cmd.py:128`:**

```python
        boundaries, _ = resolve_boundaries(manifest_dir, manifest_model)
```

**`src/wardline/cli/regime_cmd.py:79`:**

```python
        boundaries, _ = resolve_boundaries(manifest_dir, manifest_model)
```

**`src/wardline/cli/explain_cmd.py:380`:**

```python
        boundaries, _ = resolve_boundaries(root, manifest_model)  # type: ignore[arg-type]
```

- [ ] **Step 7: Run the new tests**

Run: `pytest tests/unit/manifest/test_resolve.py -v`
Expected: All pass (including the two new tests).

- [ ] **Step 8: Run full test suite to check for regressions**

Run: `pytest tests/ -x --timeout=60`
Expected: All pass. The signature change touches many callers — any missed unpacking will fail immediately with `ValueError: too many values to unpack`.

- [ ] **Step 9: Commit**

```bash
git add src/wardline/manifest/resolve.py src/wardline/cli/scan.py src/wardline/cli/resolve_cmd.py src/wardline/cli/coherence_cmd.py src/wardline/cli/regime_cmd.py src/wardline/cli/explain_cmd.py tests/unit/manifest/test_resolve.py tests/unit/manifest/test_loader.py
git commit -m "refactor(resolve): return (boundaries, overlay_paths) from resolve_boundaries()

All 5 production callers updated. resolve_cmd.py collapses redundant
discover_overlays() call."
```

---

### Task 3: Fix `_compute_manifest_hash()` to hash root manifest only

**Files:**
- Modify: `src/wardline/cli/scan.py:50-68` (_compute_manifest_hash)
- Test: `tests/unit/cli/test_scan_helpers.py` (new file)

- [ ] **Step 1: Create test file and write failing tests**

Create `tests/unit/cli/test_scan_helpers.py`:

```python
"""Tests for SARIF run-level property computation helpers in cli/scan.py."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


class TestComputeManifestHash:
    def test_manifest_hash_is_root_only(self, tmp_path: Path) -> None:
        """manifestHash is SHA-256 of root manifest raw bytes only (§10.1)."""
        from wardline.cli.scan import _compute_manifest_hash

        manifest = tmp_path / "wardline.yaml"
        content = b"tiers: []\nmodule_tiers: []\n"
        manifest.write_bytes(content)

        result = _compute_manifest_hash(manifest)
        expected = "sha256:" + hashlib.sha256(content).hexdigest()
        assert result == expected

    def test_manifest_hash_unchanged_by_overlay_changes(self, tmp_path: Path) -> None:
        """Adding overlays must not change manifestHash."""
        from wardline.cli.scan import _compute_manifest_hash

        manifest = tmp_path / "wardline.yaml"
        content = b"tiers: []\nmodule_tiers: []\n"
        manifest.write_bytes(content)

        hash_before = _compute_manifest_hash(manifest)

        # Add an overlay file next to the manifest
        overlay_dir = tmp_path / "overlays"
        overlay_dir.mkdir()
        (overlay_dir / "wardline.overlay.yaml").write_text("overlay_for: x\n")

        hash_after = _compute_manifest_hash(manifest)
        assert hash_before == hash_after

    def test_manifest_hash_returns_none_on_missing_file(self, tmp_path: Path) -> None:
        """Missing manifest returns None."""
        from wardline.cli.scan import _compute_manifest_hash

        result = _compute_manifest_hash(tmp_path / "nonexistent.yaml")
        assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/cli/test_scan_helpers.py::TestComputeManifestHash -v`
Expected: FAIL — `test_manifest_hash_unchanged_by_overlay_changes` fails because the current implementation includes overlays.

- [ ] **Step 3: Replace `_compute_manifest_hash()` with root-only implementation**

In `src/wardline/cli/scan.py`, replace lines 50-68:

```python
def _compute_manifest_hash(manifest_path: Path) -> str | None:
    """SHA-256 of root manifest raw bytes only (§10.1).

    The spec defines wardline.manifestHash as the hash of the root manifest
    file content — not a combined hash with overlays. Overlay hashes are
    reported separately via wardline.overlayHashes.
    """
    import hashlib

    try:
        raw = manifest_path.read_bytes()
        return "sha256:" + hashlib.sha256(raw).hexdigest()
    except OSError:
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/cli/test_scan_helpers.py::TestComputeManifestHash -v`
Expected: All 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/scan.py tests/unit/cli/test_scan_helpers.py
git commit -m "fix(sarif): manifestHash hashes root manifest only, not combined with overlays

Fixes spec mismatch: §10.1 defines wardline.manifestHash as SHA-256 of
the root manifest file's raw bytes. Overlays are covered separately by
wardline.overlayHashes (added in next commit). Breaking change to
existing manifestHash values — propertyBagVersion bump to follow."
```

---

### Task 4: Add `_compute_input_hash()` helper

**Files:**
- Modify: `src/wardline/cli/scan.py` (add new function after `_compute_manifest_hash`)
- Test: `tests/unit/cli/test_scan_helpers.py`

- [ ] **Step 1: Write failing tests for input hash computation**

Add to `tests/unit/cli/test_scan_helpers.py`:

```python
class TestComputeInputHash:
    def test_deterministic(self, tmp_path: Path) -> None:
        """Same files produce same hash."""
        from wardline.cli.scan import _compute_input_hash

        f1 = tmp_path / "a.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2 = tmp_path / "b.py"
        f2.write_text("y = 2\n", encoding="utf-8")

        hash1, count1 = _compute_input_hash([f1, f2], tmp_path)
        hash2, count2 = _compute_input_hash([f1, f2], tmp_path)
        assert hash1 == hash2
        assert count1 == count2 == 2
        assert hash1.startswith("sha256:")

    def test_order_independent(self, tmp_path: Path) -> None:
        """Different enumeration order produces same hash."""
        from wardline.cli.scan import _compute_input_hash

        f1 = tmp_path / "a.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2 = tmp_path / "b.py"
        f2.write_text("y = 2\n", encoding="utf-8")

        hash_ab, _ = _compute_input_hash([f1, f2], tmp_path)
        hash_ba, _ = _compute_input_hash([f2, f1], tmp_path)
        assert hash_ab == hash_ba

    def test_empty_file_set(self, tmp_path: Path) -> None:
        """Empty file set produces valid hash with count 0."""
        from wardline.cli.scan import _compute_input_hash

        h, count = _compute_input_hash([], tmp_path)
        assert h.startswith("sha256:")
        assert count == 0
        # Hash of empty string is deterministic
        assert len(h) == len("sha256:") + 64

    def test_symlink_dedup(self, tmp_path: Path) -> None:
        """Symlink to same file is counted once."""
        from wardline.cli.scan import _compute_input_hash

        real = tmp_path / "real.py"
        real.write_text("x = 1\n", encoding="utf-8")
        link = tmp_path / "link.py"
        link.symlink_to(real)

        h_both, count_both = _compute_input_hash([real, link], tmp_path)
        h_real, count_real = _compute_input_hash([real], tmp_path)
        assert h_both == h_real
        assert count_both == count_real == 1

    def test_uses_project_root_not_scan_path(self, tmp_path: Path) -> None:
        """Paths are relative to project_root, not to wherever the scan started."""
        from wardline.cli.scan import _compute_input_hash

        sub = tmp_path / "src"
        sub.mkdir()
        f = sub / "mod.py"
        f.write_text("x = 1\n", encoding="utf-8")

        # Hash with project root = tmp_path
        h_root, _ = _compute_input_hash([f], tmp_path)
        # Hash with project root = sub (wrong — would produce different relative path)
        h_sub, _ = _compute_input_hash([f], sub)
        # These MUST differ — the relative paths are different
        assert h_root != h_sub

    def test_hard_failure_on_unreadable(self, tmp_path: Path) -> None:
        """OSError on read_bytes raises, does not silently skip."""
        from wardline.cli.scan import _compute_input_hash

        missing = tmp_path / "gone.py"
        # File doesn't exist — read_bytes will raise OSError
        with pytest.raises(OSError):
            _compute_input_hash([missing], tmp_path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cli/test_scan_helpers.py::TestComputeInputHash -v`
Expected: FAIL — `_compute_input_hash` does not exist.

- [ ] **Step 3: Implement `_compute_input_hash()`**

Add to `src/wardline/cli/scan.py`, after `_compute_manifest_hash()`:

```python
def _compute_input_hash(
    file_paths: Sequence[Path], project_root: Path
) -> tuple[str, int]:
    """Hash-of-hashes over analysed files (§10.1 algorithm).

    Args:
        file_paths: Files the engine analysed (from ScanResult.scanned_file_paths).
        project_root: The project root (manifest_path.parent), NOT the scan
            target path. The spec requires paths relative to project root so
            that scanning a subdirectory produces the same inputHash as scanning
            the full project (for the same file set).

    Returns:
        (hash_string, deduplicated_file_count). The hash is always valid
        (including for empty file sets). OSError on any file is re-raised —
        silently skipping would make the hash describe a different set than
        the scan consumed.
    """
    import hashlib

    resolved_root = project_root.resolve()

    # Deduplicate after symlink resolution (§10.1 step 2)
    seen: dict[Path, None] = {}
    for fp in file_paths:
        resolved = fp.resolve()
        if resolved not in seen:
            seen[resolved] = None

    records: list[str] = []
    for resolved in seen:
        # Step 3: normalize to forward-slash path relative to project root
        try:
            rel = resolved.relative_to(resolved_root)
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        # Step 4: SHA-256 of raw bytes (OSError re-raises — hard failure)
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        # Step 5: form record
        records.append(f"{normalized}\x00{digest}")

    # Step 6: sort, concatenate with \n terminators, hash
    records.sort()
    combined = "".join(r + "\n" for r in records)
    return (
        "sha256:" + hashlib.sha256(combined.encode("utf-8")).hexdigest(),
        len(records),
    )
```

Add the `Sequence` import at the top of the file. Find the existing typing imports (line 13):

```python
from typing import TYPE_CHECKING
```

Change to:

```python
from typing import TYPE_CHECKING, Sequence
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/cli/test_scan_helpers.py::TestComputeInputHash -v`
Expected: All 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/scan.py tests/unit/cli/test_scan_helpers.py
git commit -m "feat(sarif): add _compute_input_hash() implementing §10.1 hash-of-hashes"
```

---

### Task 5: Add `_compute_overlay_hashes()` and `_read_coverage_ratio()` helpers

**Files:**
- Modify: `src/wardline/cli/scan.py` (add two new functions)
- Test: `tests/unit/cli/test_scan_helpers.py`

- [ ] **Step 1: Write failing tests for overlay hash computation**

Add to `tests/unit/cli/test_scan_helpers.py`:

```python
class TestComputeOverlayHashes:
    def test_sorted_by_normalized_path(self, tmp_path: Path) -> None:
        """Overlay hashes are sorted by forward-slash path relative to project root."""
        from wardline.cli.scan import _compute_overlay_hashes

        d1 = tmp_path / "z_dir"
        d1.mkdir()
        d2 = tmp_path / "a_dir"
        d2.mkdir()
        o1 = d1 / "wardline.overlay.yaml"
        o1.write_bytes(b"overlay_for: z_dir\n")
        o2 = d2 / "wardline.overlay.yaml"
        o2.write_bytes(b"overlay_for: a_dir\n")

        result = _compute_overlay_hashes([o1, o2], tmp_path)
        assert len(result) == 2
        assert all(h.startswith("sha256:") for h in result)
        # a_dir sorts before z_dir
        h_a = _compute_overlay_hashes([o2], tmp_path)
        h_z = _compute_overlay_hashes([o1], tmp_path)
        assert result == (h_a[0], h_z[0])

    def test_empty_returns_empty_tuple(self, tmp_path: Path) -> None:
        """No overlays returns empty tuple."""
        from wardline.cli.scan import _compute_overlay_hashes

        result = _compute_overlay_hashes([], tmp_path)
        assert result == ()

    def test_skips_symlinks(self, tmp_path: Path) -> None:
        """Symlinked overlay files are excluded."""
        from wardline.cli.scan import _compute_overlay_hashes

        real = tmp_path / "real.yaml"
        real.write_bytes(b"overlay_for: x\n")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)

        result = _compute_overlay_hashes([real, link], tmp_path)
        assert len(result) == 1  # symlink excluded


class TestReadCoverageRatio:
    def test_no_baseline_returns_none(self, tmp_path: Path) -> None:
        """No fingerprint baseline file returns None."""
        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        result = _read_coverage_ratio(manifest)
        assert result is None

    def test_baseline_with_ratio(self, tmp_path: Path) -> None:
        """Fingerprint baseline with coverage.ratio returns float."""
        import json

        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        baseline = tmp_path / "wardline.fingerprint.json"
        baseline.write_text(
            json.dumps({"coverage": {"ratio": 0.73, "annotated": 30, "total": 41}})
        )
        result = _read_coverage_ratio(manifest)
        assert result == 0.73

    def test_baseline_with_zero_ratio(self, tmp_path: Path) -> None:
        """Baseline exists but ratio is 0.0 — returns 0.0, not None."""
        import json

        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        baseline = tmp_path / "wardline.fingerprint.json"
        baseline.write_text(json.dumps({"coverage": {"ratio": 0.0}}))
        result = _read_coverage_ratio(manifest)
        assert result == 0.0

    def test_corrupt_baseline_returns_none(self, tmp_path: Path) -> None:
        """Corrupt JSON baseline returns None (not crash)."""
        from wardline.cli.scan import _read_coverage_ratio

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("tiers: []\n")
        baseline = tmp_path / "wardline.fingerprint.json"
        baseline.write_text("NOT JSON")
        result = _read_coverage_ratio(manifest)
        assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cli/test_scan_helpers.py::TestComputeOverlayHashes tests/unit/cli/test_scan_helpers.py::TestReadCoverageRatio -v`
Expected: FAIL — functions do not exist.

- [ ] **Step 3: Implement `_compute_overlay_hashes()` and `_read_coverage_ratio()`**

Add to `src/wardline/cli/scan.py`, after `_compute_input_hash()`:

```python
def _compute_overlay_hashes(
    consumed_overlay_paths: Sequence[Path],
    project_root: Path,
) -> tuple[str, ...]:
    """SHA-256 of each consumed overlay, sorted by normalized path (§10.1).

    Symlinked overlay files are excluded (consistent with overlay discovery).
    """
    import hashlib

    entries: list[tuple[str, str]] = []
    resolved_root = project_root.resolve()
    for overlay_path in consumed_overlay_paths:
        if overlay_path.is_symlink():
            continue
        resolved = overlay_path.resolve()
        try:
            rel = resolved.relative_to(resolved_root)
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        entries.append((normalized, f"sha256:{digest}"))

    entries.sort(key=lambda e: e[0])
    return tuple(h for _, h in entries)


def _read_coverage_ratio(manifest_path: Path) -> float | None:
    """Read annotation coverage ratio from fingerprint baseline.

    Returns None when no baseline exists (property omitted from SARIF).
    Returns 0.0 when baseline exists but shows zero coverage.
    """
    import json

    baseline = manifest_path.parent / "wardline.fingerprint.json"
    if not baseline.exists():
        return None
    try:
        data = json.loads(baseline.read_text(encoding="utf-8"))
        ratio = data.get("coverage", {}).get("ratio")
        return float(ratio) if ratio is not None else None
    except (json.JSONDecodeError, OSError, ValueError):
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/cli/test_scan_helpers.py::TestComputeOverlayHashes tests/unit/cli/test_scan_helpers.py::TestReadCoverageRatio -v`
Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/scan.py tests/unit/cli/test_scan_helpers.py
git commit -m "feat(sarif): add _compute_overlay_hashes() and _read_coverage_ratio() helpers"
```

---

### Task 6: Add four new fields to `SarifReport` and update `to_dict()`

**Files:**
- Modify: `src/wardline/scanner/sarif.py:206-314`
- Test: `tests/unit/scanner/test_sarif.py`

- [ ] **Step 1: Write failing tests for new run-level properties**

Add to `tests/unit/scanner/test_sarif.py` inside `TestSarifPropertyBags`:

```python
    def test_input_hash_always_emitted(self) -> None:
        """wardline.inputHash is always present in run properties."""
        report = SarifReport(findings=[], input_hash="sha256:abc123")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputHash"] == "sha256:abc123"

    def test_input_hash_empty_string_default(self) -> None:
        """Default empty input_hash emits empty string (not absent)."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.inputHash" in props
        assert props["wardline.inputHash"] == ""

    def test_input_files_always_emitted(self) -> None:
        """wardline.inputFiles is always present, defaults to 0."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputFiles"] == 0

    def test_input_files_wired(self) -> None:
        report = SarifReport(findings=[], input_files=42)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputFiles"] == 42

    def test_overlay_hashes_always_emitted(self) -> None:
        """wardline.overlayHashes is always present (empty list when no overlays)."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.overlayHashes"] == []

    def test_overlay_hashes_with_entries(self) -> None:
        report = SarifReport(
            findings=[],
            overlay_hashes=("sha256:aaa", "sha256:bbb"),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.overlayHashes"] == ["sha256:aaa", "sha256:bbb"]

    def test_coverage_ratio_omitted_when_none(self) -> None:
        """wardline.coverageRatio is absent when coverage_ratio is None."""
        report = SarifReport(findings=[], coverage_ratio=None)
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.coverageRatio" not in props

    def test_coverage_ratio_present_when_set(self) -> None:
        report = SarifReport(findings=[], coverage_ratio=0.73456789)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.coverageRatio"] == 0.7346  # rounded to 4 dp

    def test_coverage_ratio_zero_is_emitted(self) -> None:
        """coverageRatio 0.0 is emitted (distinct from None/absent)."""
        report = SarifReport(findings=[], coverage_ratio=0.0)
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.coverageRatio" in props
        assert props["wardline.coverageRatio"] == 0.0

    def test_input_hash_not_suppressed_in_verification_mode(self) -> None:
        """inputHash is deterministic — present even in verification mode."""
        report = SarifReport(
            findings=[],
            verification_mode=True,
            input_hash="sha256:abc",
            input_files=5,
            overlay_hashes=("sha256:def",),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputHash"] == "sha256:abc"
        assert props["wardline.inputFiles"] == 5
        assert props["wardline.overlayHashes"] == ["sha256:def"]
```

- [ ] **Step 2: Update the property bag version test**

In `tests/unit/scanner/test_sarif.py`, update `test_property_bag_version` (line 327-330):

```python
    def test_property_bag_version(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.propertyBagVersion"] == "0.3"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/unit/scanner/test_sarif.py::TestSarifPropertyBags -v`
Expected: FAIL — new fields don't exist on `SarifReport`.

- [ ] **Step 4: Add four new fields to `SarifReport` dataclass**

In `src/wardline/scanner/sarif.py`, after the `commit_ref` field (line 227), add:

```python
    commit_ref: str | None = None
    # Gap 3: Run-level identity properties (§10.1)
    input_hash: str = ""
    input_files: int = 0
    overlay_hashes: tuple[str, ...] = ()
    coverage_ratio: float | None = None
```

- [ ] **Step 5: Update `to_dict()` to emit the four new properties and bump version**

In `src/wardline/scanner/sarif.py`, in the `to_dict()` method, update the `properties` dict. The new properties go after the existing ones, before the closing `}`. Also bump `propertyBagVersion`:

Replace the entire `"properties"` dict (lines 273-298) with:

```python
            "properties": {
                "wardline.analysisLevel": self.analysis_level,
                **({"wardline.commitRef": self.commit_ref}
                   if not self.verification_mode and self.commit_ref
                   else {}),
                "wardline.conformanceGaps": [],
                "wardline.controlLaw": self.control_law,
                **({"wardline.coverageRatio": round(self.coverage_ratio, 4)}
                   if self.coverage_ratio is not None else {}),
                "wardline.governanceProfile": self.governance_profile,
                "wardline.implementedRules": self._implemented_rules(),
                "wardline.inputFiles": self.input_files,
                "wardline.inputHash": self.input_hash,
                **({"wardline.manifestHash": self.manifest_hash}
                   if self.manifest_hash is not None
                   else {}),
                "wardline.overlayHashes": list(self.overlay_hashes),
                "wardline.propertyBagVersion": "0.3",
                **({"wardline.scanTimestamp": self.scan_timestamp}
                   if not self.verification_mode and self.scan_timestamp
                   else {}),
                "wardline.suppressedFindingCount": sum(
                    1 for f in self.findings if f.exception_id is not None
                ),
                "wardline.unknownRawFunctionCount": self.unknown_raw_count,
                "wardline.unresolvedDecoratorCount": self.unresolved_decorator_count,
                "wardline.filesWithDegradedTaint": self.files_with_degraded_taint,
                "wardline.activeExceptionCount": self.active_exception_count,
                "wardline.staleExceptionCount": self.stale_exception_count,
                "wardline.expeditedExceptionRatio": round(self.expedited_exception_ratio, 3),
            },
```

Note: properties are alphabetically ordered by key for deterministic JSON output (the dict is built in order, and `sort_keys=True` in `to_json_string()` handles final ordering, but keeping source order alphabetical is good practice).

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/unit/scanner/test_sarif.py -v`
Expected: All tests pass (including existing tests — no regressions).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py
git commit -m "feat(sarif): add inputHash, inputFiles, overlayHashes, coverageRatio run properties

Adds 4 new fields to SarifReport dataclass. Bumps propertyBagVersion
from 0.2 to 0.3. inputHash/inputFiles/overlayHashes always emitted;
coverageRatio conditional on fingerprint baseline existence."
```

---

### Task 7: Wire everything together in `cli/scan.py`

**Files:**
- Modify: `src/wardline/cli/scan.py:537-561` (SARIF construction block)
- Test: `tests/integration/test_scan_cmd.py`

- [ ] **Step 1: Write integration tests**

Add to `tests/integration/test_scan_cmd.py`:

```python
@pytest.mark.integration
class TestSarifRunLevelProperties:
    """Gap 3: SARIF run-level identity properties (§10.1)."""

    def test_sarif_output_contains_input_hash(self, tmp_path: Path) -> None:
        """wardline.inputHash present and starts with sha256:."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert "wardline.inputHash" in props
        assert props["wardline.inputHash"].startswith("sha256:")

    def test_sarif_output_contains_input_files(self, tmp_path: Path) -> None:
        """wardline.inputFiles matches scanned file count."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert "wardline.inputFiles" in props
        # _minimal_manifest creates clean.py → 1 file
        assert props["wardline.inputFiles"] == 1

    def test_sarif_output_overlay_hashes_present(self, tmp_path: Path) -> None:
        """wardline.overlayHashes is a list (empty when no overlays)."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert "wardline.overlayHashes" in props
        assert isinstance(props["wardline.overlayHashes"], list)

    def test_sarif_input_hash_deterministic(self, tmp_path: Path) -> None:
        """Two identical runs produce same inputHash."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        args = [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--verification-mode",
        ]
        r1 = runner.invoke(cli, args)
        r2 = runner.invoke(cli, args)
        sarif1 = json.loads(r1.stdout)
        sarif2 = json.loads(r2.stdout)
        assert (
            sarif1["runs"][0]["properties"]["wardline.inputHash"]
            == sarif2["runs"][0]["properties"]["wardline.inputHash"]
        )

    def test_sarif_property_bag_version_is_0_3(self, tmp_path: Path) -> None:
        """Property bag version is 0.3 after Gap 3."""
        manifest = _minimal_manifest(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        sarif = json.loads(result.stdout)
        props = sarif["runs"][0]["properties"]
        assert props["wardline.propertyBagVersion"] == "0.3"
```

- [ ] **Step 2: Run integration tests to verify they fail**

Run: `pytest tests/integration/test_scan_cmd.py::TestSarifRunLevelProperties -v`
Expected: FAIL — inputHash/inputFiles not in SARIF output yet (not wired).

- [ ] **Step 3: Wire the helpers into the SARIF construction block**

In `src/wardline/cli/scan.py`, update the SARIF construction section.

First, where `resolve_boundaries` is called (around line 385), update to capture overlay paths. The code currently reads:

```python
        try:
            boundaries = resolve_boundaries(manifest_path.parent, manifest_model)
        except _PolicyError as exc:
```

The Task 2 commit already changed this to:

```python
        try:
            boundaries, consumed_overlay_paths = resolve_boundaries(
                manifest_path.parent, manifest_model
            )
        except _PolicyError as exc:
```

Now update the SARIF construction block (around line 537-561). Replace:

```python
    manifest_hash = _compute_manifest_hash(manifest_path)
```

with the full set of computations (remove the old `_compute_manifest_hash` call that was on its own):

```python
    # --- Compute run identity properties (§10.1) ---
    manifest_hash = _compute_manifest_hash(manifest_path)
    overlay_hashes = _compute_overlay_hashes(
        consumed_overlay_paths, manifest_path.parent
    )
    coverage_ratio = _read_coverage_ratio(manifest_path)

    # inputHash — hard failure if a scanned file becomes unreadable
    project_root = manifest_path.parent
    try:
        input_hash, input_files = _compute_input_hash(
            result.scanned_file_paths, project_root
        )
    except OSError as exc:
        logger.error("inputHash computation failed: %s", exc)
        all_findings.append(
            _make_governance_finding(
                RuleId.TOOL_ERROR,
                f"inputHash computation failed — scanned file unreadable: {exc}",
                Severity.ERROR,
            )
        )
        input_hash = ""
        input_files = result.files_scanned
```

Then update the `SarifReport` constructor to include the new fields:

```python
    sarif_report = SarifReport(
        findings=all_findings,
        tool_version=_wardline_pkg.__version__,
        verification_mode=verification_mode,
        implemented_rule_ids=loaded_rule_ids,
        base_path=str(scan_path),
        unknown_raw_count=unknown_raw_count,
        unresolved_decorator_count=unresolved_decorator_count,
        files_with_degraded_taint=result.files_with_degraded_taint,
        active_exception_count=active_exception_count,
        stale_exception_count=stale_exception_count,
        expedited_exception_ratio=expedited_exception_ratio,
        governance_profile=manifest_model.governance_profile,
        analysis_level=analysis_level,
        manifest_hash=manifest_hash,
        scan_timestamp=_utc_timestamp(),
        commit_ref=_git_head_ref(),
        input_hash=input_hash,
        input_files=input_files,
        overlay_hashes=overlay_hashes,
        coverage_ratio=coverage_ratio,
    )
```

- [ ] **Step 4: Run integration tests to verify they pass**

Run: `pytest tests/integration/test_scan_cmd.py::TestSarifRunLevelProperties -v`
Expected: All 5 tests pass.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -x --timeout=120`
Expected: All tests pass. This is the critical regression gate — the wiring touches the main scan pipeline.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/scan.py tests/integration/test_scan_cmd.py
git commit -m "feat(sarif): wire inputHash, inputFiles, overlayHashes, coverageRatio into scan pipeline

Completes Gap 3 (WL-FIT-SCAN-004, WL-FIT-PY-008). All four run-level
identity properties now flow from CLI helpers through SarifReport to
SARIF JSON output. Hard failure path for unreadable files emits
TOOL_ERROR finding."
```

---

### Task 8: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ --timeout=120`
Expected: All tests pass. Note the count — should be ~1830+ (1808 baseline + ~23 new tests).

- [ ] **Step 2: Verify SARIF output manually**

Run a scan on the wardline project itself and inspect the output:

```bash
cd /home/john/wardline
python -m wardline scan src/wardline --manifest wardline.yaml --allow-registry-mismatch -o /tmp/wardline-sarif.json 2>/dev/null
python -c "
import json
d = json.load(open('/tmp/wardline-sarif.json'))
props = d['runs'][0]['properties']
print('propertyBagVersion:', props.get('wardline.propertyBagVersion'))
print('inputHash:', props.get('wardline.inputHash', 'MISSING')[:30] + '...')
print('inputFiles:', props.get('wardline.inputFiles', 'MISSING'))
print('overlayHashes:', props.get('wardline.overlayHashes', 'MISSING'))
print('coverageRatio:', props.get('wardline.coverageRatio', 'MISSING'))
print('manifestHash:', props.get('wardline.manifestHash', 'MISSING')[:30] + '...')
"
```

Expected output:
- `propertyBagVersion: 0.3`
- `inputHash: sha256:...` (64 hex chars after prefix)
- `inputFiles:` a positive integer
- `overlayHashes:` a list (may be empty or populated depending on project overlays)
- `coverageRatio:` a float or `MISSING` (depends on fingerprint baseline)
- `manifestHash: sha256:...` (now root-only hash)

- [ ] **Step 3: Verify determinism**

Run the same scan twice in verification mode:

```bash
python -m wardline scan src/wardline --manifest wardline.yaml --allow-registry-mismatch --verification-mode -o /tmp/v1.json 2>/dev/null
python -m wardline scan src/wardline --manifest wardline.yaml --allow-registry-mismatch --verification-mode -o /tmp/v2.json 2>/dev/null
diff /tmp/v1.json /tmp/v2.json
```

Expected: No diff — byte-identical output.
