# SARIF Run-Level Property Bag Completion

**Date:** 2026-03-27
**Status:** Draft
**Spec requirements:** WL-FIT-SCAN-004, WL-FIT-PY-008
**Normative sources:** Part I §10.1, Part II §A.3.9

## Problem

The SARIF run-level `properties` bag is missing four required fields for Wardline-Core tool output:

| Property | Type | Purpose |
|----------|------|---------|
| `wardline.inputHash` | `"sha256:<hex>"` | Cryptographic hash of analysed file set — determinism verification |
| `wardline.inputFiles` | `int` | Count of files in analysed set — file-set divergence detection |
| `wardline.overlayHashes` | `list[str]` | Per-overlay SHA-256 hashes, sorted by normalized path |
| `wardline.coverageRatio` | `float` | Annotation coverage from fingerprint baseline (0.0–1.0) |

Without `inputHash` + `inputFiles`, an assessor cannot distinguish "different output because different input" from "non-deterministic tool." Without `overlayHashes`, individual overlay policy versions are opaque. Without `coverageRatio`, annotation progress is invisible in SARIF output.

Additionally, `_compute_manifest_hash()` in `cli/scan.py` hardcodes an `overlays/` directory for overlay discovery, which is wrong — this project uses dispersed `wardline.overlay.yaml` files discovered via `discover_overlays()`. The `manifestHash` computation must be refactored to use the same consumed overlay path list as `overlayHashes`.

## Architecture Decision

**Compute in `cli/scan.py`, pass pre-computed values to `SarifReport`.**

Same pattern as `manifest_hash`, `scan_timestamp`, `commit_ref`. The CLI command has access to the scan engine result, manifest path, and fingerprint baseline. `SarifReport` stays a pure data→dict serializer. No computation logic in the dataclass.

## Design

### 1. `ScanResult` — expose scanned file paths

Add a `scanned_file_paths` field to `ScanResult` in `scanner/engine.py`:

```python
@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    files_with_degraded_taint: int = 0
    errors: list[str] = field(default_factory=list)
    scanned_file_paths: list[Path] = field(default_factory=list)  # NEW
```

In `_scan_file()`, append the file path after successful parse (at the same point `files_scanned` is incremented):

```python
result.files_scanned += 1
result.scanned_file_paths.append(file_path)  # NEW
```

The engine is the authority on which files were analysed. The CLI hashes this authoritative list rather than re-enumerating.

**Deduplication after symlink resolution.** If the engine could surface the same resolved file twice through aliases or symlinks, dedup after resolution before hashing and counting. This keeps `inputFiles` and `inputHash` stable regardless of how the file set was enumerated. The dedup happens in the `_compute_input_hash()` helper (see §3), not in the engine — the engine's `files_scanned` count reflects enumeration reality; the hash reflects content identity.

### 2. `SarifReport` — four new fields

```python
@dataclass
class SarifReport:
    # ... existing fields ...

    # Gap 3: Run-level identity properties (§10.1)
    input_hash: str = ""                   # "sha256:<hex>" — always emitted
    input_files: int = 0                   # count of analysed files — always emitted
    overlay_hashes: tuple[str, ...] = ()   # per-overlay SHA-256, sorted by path
    coverage_ratio: float | None = None    # from fingerprint baseline (0.0–1.0)
```

Field design choices:

- **`input_hash: str = ""`** — not `str | None`. The spec treats this as a required run-level identity property. An empty string is the sentinel for "computation failed" and should be a governance/tool-error signal, not silent omission. For an empty file set (zero files scanned), hash the empty concatenation and emit `inputFiles: 0`.
- **`overlay_hashes: tuple[str, ...]`** — immutable. Always emitted (as `[]` when no overlays consumed). An empty list means "no overlays"; absence would mean "tool forgot to compute it" — the distinction matters for assessors.
- **`coverage_ratio: float | None`** — `None` means "no fingerprint baseline exists." This is a repo-level interpretation: the spec says the property comes "from the fingerprint baseline (§9.2)" but does not explicitly address what to emit when no baseline exists. Our policy: omit the property when no baseline exists; emit `0.0` when the baseline exists but shows zero coverage. This interpretation is documented here for assessor clarity.

### 3. `_compute_input_hash()` — new helper in `cli/scan.py`

Implements the §10.1 hash-of-hashes algorithm exactly:

```python
def _compute_input_hash(
    file_paths: Sequence[Path], base_path: Path
) -> tuple[str, int]:
    """Hash-of-hashes over analysed files (§10.1 algorithm).

    Returns (hash_string, deduplicated_file_count).
    """
    import hashlib

    # Deduplicate after symlink resolution (§10.1 step 2)
    seen: dict[Path, None] = {}
    for fp in file_paths:
        resolved = fp.resolve()
        if resolved not in seen:
            seen[resolved] = None

    records: list[str] = []
    for resolved in seen:
        # Step 3: normalize to forward-slash relative path
        try:
            rel = resolved.relative_to(base_path.resolve())
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        # Step 4: SHA-256 of raw bytes
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

Key spec constraints honoured:
- Symlinks resolved before hashing (step 2)
- Paths normalized to forward-slash relative, no leading `./` (step 3)
- Per-file SHA-256 of raw bytes (step 4)
- Records: `<path>\x00<hex-digest>` (step 5)
- Sorted lexicographically, `\n`-terminated, then SHA-256 the concatenation (step 6)
- Deduplication after resolution prevents aliases/symlinks from producing different hashes
- Empty file set: zero records → hash of empty string → valid `sha256:<hex>` with `inputFiles: 0`

**Error handling:** If `read_bytes()` raises `OSError` on a file that the engine successfully scanned (should not happen — the engine already read the file), the helper logs a warning and skips that file's record. The caller in `scan.py` is responsible for emitting a TOOL_ERROR finding if the hash computation raises. The `input_hash` field defaults to `""` which signals computation failure to SARIF consumers.

### 4. Overlay hash refactoring — consumed overlay paths

**Problem:** `_compute_manifest_hash()` currently hardcodes `manifest_path.parent / "overlays"` for overlay discovery. This project uses dispersed `wardline.overlay.yaml` files found by `discover_overlays()`. The hardcoded path will miss overlays outside `overlays/` and may include non-consumed files inside it.

**Fix:** Thread the actual consumed overlay file paths from manifest resolution to the SARIF construction block. Both `manifestHash` and `overlayHashes` derive from this single authoritative list.

#### 4a. Surface consumed overlay paths from `resolve_boundaries()`

`resolve_boundaries()` in `manifest/resolve.py` already calls `discover_overlays()` and iterates the result. Add the consumed paths to the return signature:

```python
def resolve_boundaries(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[tuple[BoundaryEntry, ...], tuple[Path, ...]]:
    """Return (boundaries, consumed_overlay_paths)."""
    overlay_paths = discover_overlays(root, manifest)
    # ... existing logic ...
    return tuple(all_boundaries), tuple(overlay_paths)
```

The second element is the list of overlay files that `discover_overlays()` returned — the full discovered set. This is the correct input for both `manifestHash` (which hashes all policy-relevant overlays) and `overlayHashes` (which reports what the tool consumed). Overlay files that failed to load during `resolve_boundaries()` are still included in this list because they were discovered and attempted — the policy surface includes them even if their boundaries could not be resolved. A failed overlay is a governance concern (already logged as a warning), not a reason to exclude it from the hash.

**Callers to update:** `cli/scan.py` (primary consumer), `cli/resolve_cmd.py` (already has `overlay_file_paths` from its own `discover_overlays()` call — can switch to the returned tuple for consistency).

#### 4b. Refactored `_compute_manifest_hash()`

Replace the hardcoded overlay directory with the consumed overlay path list:

```python
def _compute_manifest_hash(
    manifest_path: Path,
    consumed_overlay_paths: Sequence[Path],
) -> str | None:
    """SHA-256 of manifest + consumed overlay contents."""
    import hashlib

    try:
        parts: list[str] = [manifest_path.read_text(encoding="utf-8")]
        for overlay_path in sorted(consumed_overlay_paths):
            if overlay_path.is_symlink():
                continue
            parts.append(overlay_path.read_text(encoding="utf-8"))
        combined = "\n---\n".join(parts)
        return "sha256:" + hashlib.sha256(combined.encode("utf-8")).hexdigest()
    except OSError:
        return None
```

#### 4c. `_compute_overlay_hashes()` — new helper

```python
def _compute_overlay_hashes(
    consumed_overlay_paths: Sequence[Path],
    project_root: Path,
) -> tuple[str, ...]:
    """SHA-256 of each consumed overlay, sorted by normalized path (§10.1)."""
    import hashlib

    entries: list[tuple[str, str]] = []
    for overlay_path in consumed_overlay_paths:
        if overlay_path.is_symlink():
            continue
        resolved = overlay_path.resolve()
        try:
            rel = resolved.relative_to(project_root.resolve())
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        entries.append((normalized, f"sha256:{digest}"))

    entries.sort(key=lambda e: e[0])
    return tuple(h for _, h in entries)
```

Both `_compute_manifest_hash()` and `_compute_overlay_hashes()` now consume the same `consumed_overlay_paths` list — they cannot drift.

### 5. Coverage ratio — read from fingerprint baseline

```python
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

**Repo-level interpretation:** The spec (§10.1) defines `wardline.coverageRatio` as "annotation coverage from the fingerprint baseline (§9.2)." It does not explicitly address absent baselines. Our policy: omit the property when no baseline exists. This is a pragmatic choice — a project that has never run `wardline fingerprint update` should not be forced to emit `coverageRatio: 0.0` (which would be misleading — it implies a baseline exists and shows zero coverage). Assessors can distinguish "property absent" (no baseline) from `coverageRatio: 0.0` (baseline exists, no annotations).

### 6. `SarifReport.to_dict()` — four new run properties

```python
"properties": {
    # ... existing properties ...

    # Gap 3: Run identity properties (§10.1)
    "wardline.inputHash": self.input_hash,
    "wardline.inputFiles": self.input_files,
    "wardline.overlayHashes": list(self.overlay_hashes),
    **({"wardline.coverageRatio": round(self.coverage_ratio, 4)}
       if self.coverage_ratio is not None else {}),

    # ... existing properties ...
}
```

Emission rules:
- **`inputHash`** — always emitted (required identity). Empty string only on hard failure.
- **`inputFiles`** — always emitted (required identity). Zero for empty file set.
- **`overlayHashes`** — always emitted. Empty list `[]` when no overlays consumed.
- **`coverageRatio`** — conditional on baseline existence. Rounded to 4 decimal places for determinism.

**Verification mode:** `inputHash`, `inputFiles`, and `overlayHashes` are NOT suppressed in verification mode — they are deterministic by construction (same input = same values). This differs from `scanTimestamp` and `commitRef` which are volatile.

### 7. Wiring in `cli/scan.py`

In the scan command's SARIF construction block:

```python
# Unpack boundaries + consumed overlay paths
boundaries, consumed_overlay_paths = resolve_boundaries(
    manifest_path.parent, manifest_model
)

# ... existing scan execution ...

# Compute run identity properties
input_hash, input_files = _compute_input_hash(
    result.scanned_file_paths, scan_path
)
manifest_hash = _compute_manifest_hash(manifest_path, consumed_overlay_paths)
overlay_hashes = _compute_overlay_hashes(consumed_overlay_paths, manifest_path.parent)
coverage_ratio = _read_coverage_ratio(manifest_path)

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
    # Gap 3
    input_hash=input_hash,
    input_files=input_files,
    overlay_hashes=overlay_hashes,
    coverage_ratio=coverage_ratio,
)
```

### 8. `propertyBagVersion` bump

Bump from `"0.2"` to `"0.3"`. Four new properties constitutes a schema change for SARIF consumers that validate the property bag structure.

## Properties Not Addressed by This Gap

The following run-level properties are defined in §10.1 but are not cited by WL-FIT-SCAN-004 or WL-FIT-PY-008 and are tracked separately:

- **`wardline.deterministic`** — self-report boolean. Already tracked as a separate conformance item; not part of the Gap 3 requirement scope.
- **`wardline.deferredFixRatio`** — requires exception register classification not yet implemented.
- **`wardline.controlLawDegradations`** — requires alternate control-law conditions not yet implemented.
- **`wardline.retroactiveScan`** — requires retrospective scan capability not yet implemented.

These are not deferred as optional — they are required by the spec at different conformance levels and will be addressed through their own requirement IDs.

## Testing

### Unit tests — `tests/unit/scanner/test_sarif.py`

New run-level property tests:

| Test | Assertion |
|------|-----------|
| `test_run_properties_include_input_hash` | `wardline.inputHash` present, starts with `sha256:` |
| `test_run_properties_input_hash_empty_string_on_failure` | Empty string emitted (not absent) on hard failure |
| `test_run_properties_include_input_files` | `wardline.inputFiles` always present, default 0 |
| `test_run_properties_include_overlay_hashes_with_entries` | List of `sha256:` strings |
| `test_run_properties_overlay_hashes_empty_list_when_none` | `wardline.overlayHashes` is `[]`, not absent |
| `test_run_properties_include_coverage_ratio` | Rounded to 4 decimal places |
| `test_run_properties_omit_coverage_ratio_when_none` | Property absent when `coverage_ratio=None` |
| `test_property_bag_version_is_0_3` | Version bump verified |
| `test_input_hash_not_suppressed_in_verification_mode` | Present even with `verification_mode=True` |

### Unit tests — computation helpers (new file or inline in `tests/unit/cli/`)

| Test | Assertion |
|------|-----------|
| `test_compute_input_hash_deterministic` | Same files → same hash |
| `test_compute_input_hash_order_independent` | Different enumeration order → same hash |
| `test_compute_input_hash_symlink_dedup` | Symlink + target → counted once, same hash |
| `test_compute_input_hash_empty_set` | Zero files → valid sha256 hash, count 0 |
| `test_compute_input_hash_relative_paths` | Paths normalized to forward-slash relative |
| `test_compute_overlay_hashes_sorted_by_path` | Output sorted by normalized path |
| `test_compute_overlay_hashes_skips_symlinks` | Symlink exclusion |
| `test_compute_overlay_hashes_empty_returns_empty_tuple` | No overlays → `()` |
| `test_compute_manifest_hash_uses_consumed_overlays` | Hash changes when overlay list changes |
| `test_read_coverage_ratio_no_baseline` | Returns `None` |
| `test_read_coverage_ratio_with_baseline` | Returns float from JSON |

### Integration tests — `tests/integration/test_scan_cmd.py`

| Test | Assertion |
|------|-----------|
| `test_sarif_output_contains_input_hash` | End-to-end `wardline.inputHash` presence |
| `test_sarif_output_contains_input_files` | Matches file count from scan summary |
| `test_sarif_output_overlay_hashes_present` | `wardline.overlayHashes` is a list |
| `test_sarif_input_hash_deterministic` | Two identical runs → same `inputHash` |

## Files Changed

| File | Nature | Change |
|------|--------|--------|
| `src/wardline/scanner/engine.py` | Modify | Add `scanned_file_paths: list[Path]` to `ScanResult`, populate in `_scan_file()` |
| `src/wardline/scanner/sarif.py` | Modify | 4 new dataclass fields, 4 new run properties, version bump to 0.3 |
| `src/wardline/manifest/resolve.py` | Modify | `resolve_boundaries()` returns consumed overlay paths |
| `src/wardline/cli/scan.py` | Modify | 3 new helpers, refactored `_compute_manifest_hash()`, wiring |
| `src/wardline/cli/resolve_cmd.py` | Modify | Update call site for new `resolve_boundaries()` signature |
| `tests/unit/scanner/test_sarif.py` | Modify | ~9 new test cases |
| `tests/unit/cli/test_scan_helpers.py` | New | ~10 computation tests |
| `tests/integration/test_scan_cmd.py` | Modify | ~4 new integration tests |
