# Lite Governance Assessability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the self-hosting repo's Lite governance posture assessable by filling in ratification metadata, temporal-separation declaration, CODEOWNERS gaps, and regime verify checks (WL-FIT-MAN-007/009/010/011).

**Architecture:** Mostly configuration and schema changes. One new dataclass (`TemporalSeparation`), loader conditional validation, two new `ManifestMetrics` fields, and three new regime verify checks. No new modules.

**Tech Stack:** Python 3.12+, pytest, JSON Schema draft-07, frozen dataclasses

**Spec:** `docs/superpowers/specs/2026-03-27-lite-governance-assessability-design.md`

---

### Task 1: Add `TemporalSeparation` dataclass and update `ManifestMetadata`

**Files:**
- Modify: `src/wardline/manifest/models.py:132-145`
- Test: `tests/unit/manifest/test_models.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/manifest/test_models.py`. First add the import — find the existing import block and add `TemporalSeparation`:

```python
from wardline.manifest.models import (
    BoundaryEntry,
    ContractBinding,
    DelegationConfig,
    DelegationGrant,
    ExceptionEntry,
    FingerprintEntry,
    ManifestMetadata,
    ModuleTierEntry,
    RulesConfig,
    ScannerConfig,
    ScannerConfigError,
    TemporalSeparation,  # NEW
    TierEntry,
    WardlineManifest,
    WardlineOverlay,
)
```

Then add the test class:

```python
class TestTemporalSeparation:
    def test_defaults(self) -> None:
        ts = TemporalSeparation()
        assert ts.alternative == "same-actor-with-retrospective"
        assert ts.retrospective_window_days == 10
        assert ts.rationale == ""

    def test_enforced(self) -> None:
        ts = TemporalSeparation(alternative="enforced")
        assert ts.alternative == "enforced"

    def test_frozen(self) -> None:
        ts = TemporalSeparation()
        with pytest.raises(FrozenInstanceError):
            ts.alternative = "enforced"  # type: ignore[misc]

    def test_manifest_metadata_temporal_separation_none_means_undeclared(self) -> None:
        meta = ManifestMetadata(organisation="test")
        assert meta.temporal_separation is None

    def test_manifest_metadata_temporal_separation_round_trip(self) -> None:
        ts = TemporalSeparation(
            alternative="same-actor-with-retrospective",
            retrospective_window_days=15,
            rationale="small team",
        )
        meta = ManifestMetadata(organisation="test", temporal_separation=ts)
        assert meta.temporal_separation is not None
        assert meta.temporal_separation.alternative == "same-actor-with-retrospective"
        assert meta.temporal_separation.retrospective_window_days == 15
        assert meta.temporal_separation.rationale == "small team"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/manifest/test_models.py::TestTemporalSeparation -v`
Expected: FAIL — `TemporalSeparation` does not exist.

- [ ] **Step 3: Implement `TemporalSeparation` and update `ManifestMetadata`**

In `src/wardline/manifest/models.py`, add the new dataclass **before** `ManifestMetadata` (around line 131):

```python
@dataclass(frozen=True)
class TemporalSeparation:
    """Temporal separation alternative declaration (§14.3.2)."""

    alternative: str = "same-actor-with-retrospective"
    retrospective_window_days: int = 10
    rationale: str = ""
```

Then add the field to `ManifestMetadata` — insert after `review_interval_days`:

```python
@dataclass(frozen=True)
class ManifestMetadata:
    """Manifest metadata — organisational and governance fields."""

    organisation: str = ""
    ratified_by: MappingProxyType[str, str] | None = None
    ratification_date: str | None = None
    review_interval_days: int | None = None
    temporal_separation: TemporalSeparation | None = None

    def __post_init__(self) -> None:
        if isinstance(self.ratified_by, dict):
            object.__setattr__(
                self, "ratified_by", MappingProxyType(self.ratified_by)
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/manifest/test_models.py::TestTemporalSeparation -v`
Expected: PASS

- [ ] **Step 5: Run full model test suite**

Run: `pytest tests/unit/manifest/test_models.py -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/manifest/models.py tests/unit/manifest/test_models.py
git commit -m "feat(manifest): add TemporalSeparation dataclass and field on ManifestMetadata"
```

---

### Task 2: Update JSON schema and loader for `temporal_separation`

**Files:**
- Modify: `src/wardline/manifest/schemas/wardline.schema.json:17-42`
- Modify: `src/wardline/manifest/loader.py:231-237`
- Test: `tests/unit/manifest/test_loader.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/manifest/test_loader.py`. These tests need a helper to write a manifest with temporal_separation. Add inside the existing test class or as standalone functions depending on the file structure:

```python
class TestTemporalSeparationLoading:
    def test_load_manifest_with_temporal_separation(self, tmp_path: Path) -> None:
        """Manifest with temporal_separation loads correctly."""
        from wardline.manifest.loader import load_manifest

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "same-actor-with-retrospective"\n'
            "    retrospective_window_days: 10\n"
            "    rationale: small team\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = load_manifest(manifest)
        assert result.metadata.temporal_separation is not None
        assert result.metadata.temporal_separation.alternative == "same-actor-with-retrospective"
        assert result.metadata.temporal_separation.retrospective_window_days == 10
        assert result.metadata.temporal_separation.rationale == "small team"

    def test_load_manifest_with_enforced_temporal_separation(self, tmp_path: Path) -> None:
        """Manifest with enforced temporal_separation loads correctly."""
        from wardline.manifest.loader import load_manifest

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "enforced"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = load_manifest(manifest)
        assert result.metadata.temporal_separation is not None
        assert result.metadata.temporal_separation.alternative == "enforced"

    def test_load_manifest_without_temporal_separation(self, tmp_path: Path) -> None:
        """Absent temporal_separation loads as None (undeclared)."""
        from wardline.manifest.loader import load_manifest

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = load_manifest(manifest)
        assert result.metadata.temporal_separation is None

    def test_schema_rejects_unknown_alternative(self, tmp_path: Path) -> None:
        """Invalid temporal_separation.alternative fails schema validation."""
        from wardline.manifest.loader import ManifestLoadError, load_manifest

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "bogus"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        with pytest.raises(ManifestLoadError):
            load_manifest(manifest)

    def test_same_actor_requires_window_and_rationale(self, tmp_path: Path) -> None:
        """same-actor-with-retrospective without window/rationale fails."""
        from wardline.manifest.loader import ManifestLoadError, load_manifest

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "same-actor-with-retrospective"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        with pytest.raises(ManifestLoadError, match="retrospective_window_days"):
            load_manifest(manifest)

    def test_enforced_rejects_extra_fields(self, tmp_path: Path) -> None:
        """enforced with retrospective fields is rejected."""
        from wardline.manifest.loader import ManifestLoadError, load_manifest

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "enforced"\n'
            "    retrospective_window_days: 10\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        with pytest.raises(ManifestLoadError, match="must not be present"):
            load_manifest(manifest)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/manifest/test_loader.py::TestTemporalSeparationLoading -v`
Expected: FAIL — schema validation rejects unknown `temporal_separation` property.

- [ ] **Step 3: Update JSON schema**

In `src/wardline/manifest/schemas/wardline.schema.json`, add `temporal_separation` inside the `metadata.properties` object (after `review_interval_days`, before the closing `}`). The metadata block currently ends at line 41 with `"additionalProperties": false`. Insert before line 40:

```json
        "temporal_separation": {
          "type": "object",
          "description": "Temporal separation posture declaration (§14.3.2).",
          "properties": {
            "alternative": {
              "type": "string",
              "enum": ["enforced", "same-actor-with-retrospective"],
              "description": "The declared posture: enforced or a named alternative."
            },
            "retrospective_window_days": {
              "type": "integer",
              "minimum": 1,
              "description": "Maximum days before retrospective review must occur."
            },
            "rationale": {
              "type": "string",
              "description": "Free-text justification for the alternative."
            }
          },
          "required": ["alternative"],
          "additionalProperties": false
        }
```

- [ ] **Step 4: Update loader**

In `src/wardline/manifest/loader.py`, in `_build_manifest()`, update the `ManifestMetadata` construction (around line 231-237). Replace:

```python
    raw_meta = data.get("metadata", {})
    metadata = ManifestMetadata(
        organisation=raw_meta.get("organisation", ""),
        ratified_by=raw_meta.get("ratified_by"),
        ratification_date=raw_meta.get("ratification_date"),
        review_interval_days=raw_meta.get("review_interval_days"),
    )
```

with:

```python
    raw_meta = data.get("metadata", {})

    # Build TemporalSeparation with conditional validation
    ts_data = raw_meta.get("temporal_separation")
    temporal_separation = None
    if ts_data is not None:
        alt = ts_data["alternative"]
        if alt == "same-actor-with-retrospective":
            if "retrospective_window_days" not in ts_data:
                raise ManifestLoadError(
                    "temporal_separation: retrospective_window_days required "
                    "when alternative is same-actor-with-retrospective"
                )
            if not ts_data.get("rationale"):
                raise ManifestLoadError(
                    "temporal_separation: rationale required "
                    "when alternative is same-actor-with-retrospective"
                )
            temporal_separation = TemporalSeparation(
                alternative=alt,
                retrospective_window_days=ts_data["retrospective_window_days"],
                rationale=ts_data["rationale"],
            )
        elif alt == "enforced":
            if "retrospective_window_days" in ts_data or "rationale" in ts_data:
                raise ManifestLoadError(
                    "temporal_separation: retrospective_window_days and rationale "
                    "must not be present when alternative is enforced"
                )
            temporal_separation = TemporalSeparation(alternative="enforced")

    metadata = ManifestMetadata(
        organisation=raw_meta.get("organisation", ""),
        ratified_by=raw_meta.get("ratified_by"),
        ratification_date=raw_meta.get("ratification_date"),
        review_interval_days=raw_meta.get("review_interval_days"),
        temporal_separation=temporal_separation,
    )
```

Add the `TemporalSeparation` import at the top of the file. Find the existing import from `models.py`:

```python
from wardline.manifest.models import (
    ...
    TemporalSeparation,
    ...
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/manifest/test_loader.py::TestTemporalSeparationLoading -v`
Expected: All 6 tests pass.

- [ ] **Step 6: Run full loader test suite**

Run: `pytest tests/unit/manifest/test_loader.py -v`
Expected: All pass (no regressions from existing tests).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/manifest/schemas/wardline.schema.json src/wardline/manifest/loader.py tests/unit/manifest/test_loader.py
git commit -m "feat(manifest): add temporal_separation to schema and loader with conditional validation"
```

---

### Task 3: Update `ManifestMetrics` and `collect_manifest_metrics()`

**Files:**
- Modify: `src/wardline/manifest/regime.py:54-64` (ManifestMetrics)
- Modify: `src/wardline/manifest/regime.py:183-215` (collect_manifest_metrics)
- Test: `tests/unit/cli/test_regime_cmd.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/cli/test_regime_cmd.py`. First, we need tests that check the new metrics fields. Add a new test class:

```python
class TestManifestMetricsFields:
    def test_ratified_by_present_when_set(self, tmp_path: Path) -> None:
        """ManifestMetrics.ratified_by_present is True when ratified_by exists."""
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = _write_minimal_manifest(tmp_path)
        m = collect_manifest_metrics(manifest)
        assert m.ratified_by_present is True

    def test_ratified_by_present_when_missing(self, tmp_path: Path) -> None:
        """ManifestMetrics.ratified_by_present is False when ratified_by absent."""
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.ratified_by_present is False

    def test_temporal_separation_posture_with_alternative(self, tmp_path: Path) -> None:
        """Documented alternative produces 'alternative:...' posture."""
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "same-actor-with-retrospective"\n'
            "    retrospective_window_days: 10\n"
            "    rationale: small team\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.temporal_separation_posture == "alternative:same-actor-with-retrospective"

    def test_temporal_separation_posture_enforced(self, tmp_path: Path) -> None:
        """Explicitly enforced produces 'enforced' posture."""
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "enforced"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.temporal_separation_posture == "enforced"

    def test_temporal_separation_posture_undeclared(self, tmp_path: Path) -> None:
        """Absent temporal_separation produces None posture (undeclared)."""
        from wardline.manifest.regime import collect_manifest_metrics

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        m = collect_manifest_metrics(manifest)
        assert m.temporal_separation_posture is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cli/test_regime_cmd.py::TestManifestMetricsFields -v`
Expected: FAIL — `ManifestMetrics` has no `ratified_by_present` or `temporal_separation_posture`.

- [ ] **Step 3: Add fields to `ManifestMetrics`**

In `src/wardline/manifest/regime.py`, update the `ManifestMetrics` dataclass (around line 54-64):

```python
@dataclass(frozen=True)
class ManifestMetrics:
    """Manifest-level governance metadata."""

    governance_profile: str = "lite"
    schema_version: str = ""
    analysis_level: int = 1
    ratification_date: str | None = None
    ratification_age_days: int | None = None
    review_interval_days: int | None = None
    ratification_overdue: bool = False
    ratified_by_present: bool = False
    temporal_separation_posture: str | None = None
```

- [ ] **Step 4: Populate new fields in `collect_manifest_metrics()`**

In `src/wardline/manifest/regime.py`, in `collect_manifest_metrics()` (around line 183-215), add the new field computations before the return. After the existing ratification computation, add:

```python
    ratified_by_present = meta.ratified_by is not None

    temporal_separation_posture: str | None = None
    if meta.temporal_separation is not None:
        alt = meta.temporal_separation.alternative
        if alt == "enforced":
            temporal_separation_posture = "enforced"
        else:
            temporal_separation_posture = f"alternative:{alt}"
```

And update the return statement to include the new fields:

```python
    return ManifestMetrics(
        governance_profile=manifest.governance_profile,
        schema_version="0.1",
        analysis_level=1,
        ratification_date=ratification_date,
        ratification_age_days=ratification_age_days,
        review_interval_days=meta.review_interval_days,
        ratification_overdue=ratification_overdue,
        ratified_by_present=ratified_by_present,
        temporal_separation_posture=temporal_separation_posture,
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/cli/test_regime_cmd.py::TestManifestMetricsFields -v`
Expected: All 5 tests pass.

- [ ] **Step 6: Run full regime test suite**

Run: `pytest tests/unit/cli/test_regime_cmd.py -v`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/manifest/regime.py tests/unit/cli/test_regime_cmd.py
git commit -m "feat(regime): add ratified_by_present and temporal_separation_posture to ManifestMetrics"
```

---

### Task 4: Add three new regime verify checks

**Files:**
- Modify: `src/wardline/cli/regime_cmd.py:582-600` (after check 9)
- Test: `tests/unit/cli/test_regime_cmd.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/cli/test_regime_cmd.py`:

```python
class TestVerifyLiteGovernanceChecks:
    """Tests for Gap 5 regime verify checks (MAN-007/009/010/011)."""

    def test_ratification_metadata_present_passes(self, runner: CliRunner, tmp_path: Path) -> None:
        manifest = _write_minimal_manifest(tmp_path)
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "ratification_metadata_present")
        assert check["passed"] is True

    def test_ratification_metadata_present_fails_missing_ratified_by(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            '  ratification_date: "2026-03-01"\n'
            "  review_interval_days: 180\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "ratification_metadata_present")
        assert check["passed"] is False
        assert "ratified_by" in check["evidence"]

    def test_ratification_metadata_present_fails_missing_date(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  ratified_by:\n"
            '    name: "lead"\n'
            '    role: "tech"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "ratification_metadata_present")
        assert check["passed"] is False
        assert "ratification_date" in check["evidence"]

    def test_temporal_separation_declared_lite_with_alternative(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "same-actor-with-retrospective"\n'
            "    retrospective_window_days: 10\n"
            "    rationale: small team\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "temporal_separation_declared")
        assert check["passed"] is True

    def test_temporal_separation_declared_lite_enforced(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "  temporal_separation:\n"
            '    alternative: "enforced"\n'
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "temporal_separation_declared")
        assert check["passed"] is True

    def test_temporal_separation_declared_lite_undeclared(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            '$id: "https://wardline.dev/schemas/0.1/wardline.schema.json"\n'
            "metadata:\n"
            "  organisation: test\n"
            "tiers:\n"
            '  - id: "T1"\n'
            "    tier: 1\n"
            "module_tiers: []\n"
        )
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "temporal_separation_declared")
        assert check["passed"] is False
        assert "not declared" in check["evidence"]

    def test_annotation_change_tracking_with_baseline(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = _write_minimal_manifest(tmp_path)
        # Create a fingerprint baseline
        (tmp_path / "wardline.fingerprint.json").write_text('{"coverage": {}}')
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "annotation_change_tracking")
        assert check["passed"] is True

    def test_annotation_change_tracking_no_baseline(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        manifest = _write_minimal_manifest(tmp_path)
        result = _invoke_verify(runner, "--json", manifest=str(manifest), path=str(tmp_path))
        data = json.loads(result.output)
        check = next(c for c in data["checks"] if c["check"] == "annotation_change_tracking")
        assert check["passed"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cli/test_regime_cmd.py::TestVerifyLiteGovernanceChecks -v`
Expected: FAIL — checks don't exist in regime verify output.

- [ ] **Step 3: Add the three new checks to regime verify**

In `src/wardline/cli/regime_cmd.py`, after the existing check 9 (`ratification_current`, around line 599), add the three new checks:

```python
    # Check 10: Ratification metadata present (MAN-007)
    has_ratification = (
        manifest_m.ratified_by_present
        and manifest_m.ratification_date is not None
        and manifest_m.review_interval_days is not None
    )
    if has_ratification:
        checks.append({
            "check": "ratification_metadata_present",
            "passed": True,
            "severity": "ERROR",
            "evidence": "Ratification authority, date, and review interval declared.",
        })
    else:
        missing = []
        if not manifest_m.ratified_by_present:
            missing.append("ratified_by")
        if manifest_m.ratification_date is None:
            missing.append("ratification_date")
        if manifest_m.review_interval_days is None:
            missing.append("review_interval_days")
        checks.append({
            "check": "ratification_metadata_present",
            "passed": False,
            "severity": "ERROR",
            "evidence": f"Missing ratification metadata: {', '.join(missing)}.",
        })

    # Check 11: Temporal separation declared (MAN-011)
    ts = manifest_m.temporal_separation_posture
    governance_profile = manifest_m.governance_profile
    if governance_profile == "lite":
        if ts is not None:
            checks.append({
                "check": "temporal_separation_declared",
                "passed": True,
                "severity": "WARNING",
                "evidence": f"Temporal separation posture declared: {ts}.",
            })
        else:
            checks.append({
                "check": "temporal_separation_declared",
                "passed": False,
                "severity": "WARNING",
                "evidence": (
                    "Temporal separation posture not declared. "
                    "Assessor cannot determine whether enforced or "
                    "alternative applies. Add temporal_separation to "
                    "manifest metadata."
                ),
            })
    else:
        if ts is not None and ts.startswith("alternative:"):
            checks.append({
                "check": "temporal_separation_declared",
                "passed": False,
                "severity": "ERROR",
                "evidence": (
                    "Assurance profile does not permit temporal "
                    "separation alternatives."
                ),
            })
        else:
            checks.append({
                "check": "temporal_separation_declared",
                "passed": ts == "enforced",
                "severity": "ERROR",
                "evidence": (
                    "Temporal separation enforced."
                    if ts == "enforced"
                    else "Temporal separation posture not declared."
                ),
            })

    # Check 12: Annotation change tracking (MAN-010)
    # This repo's chosen Lite evidence: fingerprint baseline exists + CODEOWNERS.
    fingerprint_path = manifest_dir / "wardline.fingerprint.json"
    if fingerprint_path.exists():
        checks.append({
            "check": "annotation_change_tracking",
            "passed": True,
            "severity": "WARNING",
            "evidence": "Fingerprint baseline present — annotation changes visible in diffs.",
        })
    else:
        checks.append({
            "check": "annotation_change_tracking",
            "passed": False,
            "severity": "WARNING",
            "evidence": (
                "No fingerprint baseline found. Run 'wardline fingerprint update' "
                "to establish annotation change tracking."
            ),
        })
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/cli/test_regime_cmd.py::TestVerifyLiteGovernanceChecks -v`
Expected: All 9 tests pass.

- [ ] **Step 5: Run full regime test suite**

Run: `pytest tests/unit/cli/test_regime_cmd.py -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/regime_cmd.py tests/unit/cli/test_regime_cmd.py
git commit -m "feat(regime): add ratification-presence, temporal-separation, and annotation-tracking checks"
```

---

### Task 5: Update `wardline.yaml` and `.github/CODEOWNERS`

**Files:**
- Modify: `wardline.yaml:8-9`
- Modify: `.github/CODEOWNERS`

- [ ] **Step 1: Update `wardline.yaml` metadata section**

Replace the existing metadata block (lines 8-9):

```yaml
metadata:
  organisation: "wardline"
```

with:

```yaml
metadata:
  organisation: "wardline"
  ratified_by:
    name: "John"
    role: "Project Lead"
  ratification_date: "2026-03-27"
  review_interval_days: 180
  temporal_separation:
    alternative: "same-actor-with-retrospective"
    retrospective_window_days: 10
    rationale: >
      Single-developer project. Same-actor approval permitted for
      enforcement artefact changes with mandatory retrospective review
      within 10 business days. Policy artefact changes (tier definitions,
      boundary declarations, restoration provenance) require different-actor
      review per §9.3.1.
```

- [ ] **Step 2: Update `.github/CODEOWNERS`**

Add after the existing baselines block:

```
# Exception register
wardline.exceptions.json           @wardline/maintainers

# Fingerprint baseline
wardline.fingerprint.json          @wardline/maintainers
```

- [ ] **Step 3: Validate the manifest loads**

Run: `python -c "from wardline.manifest.loader import load_manifest; from pathlib import Path; m = load_manifest(Path('wardline.yaml')); print(f'TS: {m.metadata.temporal_separation}'); print(f'Ratified: {m.metadata.ratified_by}')""`
Expected: Shows TemporalSeparation and ratified_by values.

- [ ] **Step 4: Run full test suite**

Run: `python -m pytest tests/ -x -q`
Expected: All pass (the self-hosting manifest is used by some integration tests).

- [ ] **Step 5: Commit**

```bash
git add wardline.yaml .github/CODEOWNERS
git commit -m "feat(governance): add ratification metadata, temporal-separation declaration, CODEOWNERS

Closes WL-FIT-MAN-007 (ratification metadata present),
WL-FIT-MAN-009 (exception register + fingerprint CODEOWNERS),
WL-FIT-MAN-011 (temporal separation posture declared)."
```

---

### Task 6: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `python -m pytest tests/ -x -q`
Expected: All pass.

- [ ] **Step 2: Run regime verify on self-hosting manifest**

Run: `wardline regime verify --manifest wardline.yaml --path src/wardline --json 2>/dev/null | python -m json.tool | grep -A2 '"check"'`
Expected: All checks pass including the three new ones (`ratification_metadata_present`, `temporal_separation_declared`, `annotation_change_tracking`).

- [ ] **Step 3: Verify manifest validates**

Run: `wardline manifest validate --manifest wardline.yaml`
Expected: No errors.
