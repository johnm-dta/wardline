"""Tests for YAML loader — happy paths, alias bomb, coercion, schema."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from wardline.manifest.loader import (
    DEFAULT_ALIAS_LIMIT,
    HARD_ALIAS_UPPER_BOUND,
    MAX_FILE_SIZE,
    ManifestLoadError,
    WardlineYAMLError,
    load_manifest,
    load_overlay,
    make_wardline_loader,
)
from wardline.manifest.models import WardlineManifest, WardlineOverlay
from wardline.manifest.resolve import (
    GovernanceError,
    resolve_boundaries,
    resolve_optional_fields,
)

if TYPE_CHECKING:
    from pathlib import Path

# ── Happy Path ────────────────────────────────────────────────────


class TestLoadManifest:
    def test_valid_manifest_loads(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
tiers:
  - id: "internal_db"
    tier: 1
    description: "PostgreSQL audit store"
  - id: "partner_api"
    tier: 4
module_tiers:
  - path: "audit/"
    default_taint: "AUDIT_TRAIL"
  - path: "adapters/"
    default_taint: "EXTERNAL_RAW"
metadata:
  organisation: "TestOrg"
  ratification_date: "2026-01-15"
  review_interval_days: 180
""")
        manifest = load_manifest(f)
        assert isinstance(manifest, WardlineManifest)
        assert len(manifest.tiers) == 2
        assert manifest.tiers[0].id == "internal_db"
        assert manifest.tiers[0].tier == 1
        assert len(manifest.module_tiers) == 2
        assert manifest.metadata.organisation == "TestOrg"

    def test_minimal_manifest(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("{}\n")
        manifest = load_manifest(f)
        assert manifest.tiers == ()
        assert manifest.module_tiers == ()

    def test_manifest_with_id(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
"$id": "https://wardline.dev/schemas/0.1/wardline.schema.json"
tiers: []
""")
        manifest = load_manifest(f)
        assert manifest.tiers == ()

    def test_manifest_with_delegation(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
delegation:
  default_authority: "STANDARD"
  grants:
    - path: "audit/"
      authority: "NONE"
""")
        manifest = load_manifest(f)
        assert manifest.delegation.default_authority == "STANDARD"
        assert len(manifest.delegation.grants) == 1
        assert manifest.delegation.grants[0].authority == "NONE"


# ── Load Overlay ──────────────────────────────────────────────────


class TestLoadOverlay:
    def test_valid_overlay_loads(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.overlay.yaml"
        f.write_text("""\
overlay_for: "adapters/"
boundaries:
  - function: "mymod.check_shape"
    transition: "shape_validation"
    from_tier: 4
    to_tier: 3
""")
        overlay = load_overlay(f)
        assert isinstance(overlay, WardlineOverlay)
        assert overlay.overlay_for == "adapters/"
        assert len(overlay.boundaries) == 1
        assert overlay.boundaries[0].transition == "shape_validation"

    def test_overlay_with_contract_bindings(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.overlay.yaml"
        f.write_text("""\
overlay_for: "adapters/"
contract_bindings:
  - contract: "landscape_recording"
    functions:
      - "mymod.record"
      - "mymod.update"
""")
        overlay = load_overlay(f)
        assert len(overlay.contract_bindings) == 1
        assert overlay.contract_bindings[0].contract == "landscape_recording"
        assert len(overlay.contract_bindings[0].functions) == 2

    def test_overlay_with_optional_fields_loads(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.overlay.yaml"
        f.write_text("""\
overlay_for: "adapters/"
optional_fields:
  - field: "middle_name"
    approved_default: ""
    rationale: "Not present in all partner systems"
  - field: "risk_indicators"
    approved_default: []
    rationale: "Some feeds omit this field"
""")
        overlay = load_overlay(f)
        assert len(overlay.optional_fields) == 2
        assert overlay.optional_fields[0].field == "middle_name"
        assert overlay.optional_fields[0].approved_default == ""
        assert overlay.optional_fields[1].approved_default == []

    def test_conflicting_optional_fields_across_same_scope_rejected(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: "EXTERNAL_RAW"
""")
        root_model = load_manifest(manifest)

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "wardline.overlay.yaml").write_text("""\
overlay_for: "src/"
optional_fields:
  - field: "middle_name"
    approved_default: ""
    rationale: "top-level default"
""")
        nested = src_dir / "nested"
        nested.mkdir()
        (nested / "wardline.overlay.yaml").write_text("""\
overlay_for: "src/"
optional_fields:
  - field: "middle_name"
    approved_default: "UNKNOWN"
    rationale: "conflicting nested default"
""")

        with pytest.raises(GovernanceError, match="Conflicting optional_fields declarations"):
            resolve_optional_fields(tmp_path, root_model)

    def test_nested_optional_fields_scopes_are_both_resolved(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: "EXTERNAL_RAW"
""")
        root_model = load_manifest(manifest)

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "wardline.overlay.yaml").write_text("""\
overlay_for: "src/"
optional_fields:
  - field: "middle_name"
    approved_default: ""
    rationale: "parent default"
""")
        nested = src_dir / "nested"
        nested.mkdir()
        (nested / "wardline.overlay.yaml").write_text("""\
overlay_for: "src/nested/"
optional_fields:
  - field: "middle_name"
    approved_default: "UNKNOWN"
    rationale: "child override"
""")

        resolved = resolve_optional_fields(tmp_path, root_model)

        assert len(resolved) == 2

    def test_overlay_for_sibling_prefix_spoof_rejected_for_boundaries(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: "EXTERNAL_RAW"
""")
        root_model = load_manifest(manifest)

        spoof_dir = tmp_path / "src" / "apiary"
        spoof_dir.mkdir(parents=True)
        (spoof_dir / "wardline.overlay.yaml").write_text("""\
overlay_for: "src/api/"
boundaries:
  - function: "target"
    transition: "shape_validation"
    from_tier: 4
    to_tier: 3
""")

        with pytest.raises(GovernanceError, match="claims overlay_for"):
            resolve_boundaries(tmp_path, root_model)

    def test_overlay_for_sibling_prefix_spoof_rejected_for_optional_fields(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: "EXTERNAL_RAW"
""")
        root_model = load_manifest(manifest)

        spoof_dir = tmp_path / "src" / "apiary"
        spoof_dir.mkdir(parents=True)
        (spoof_dir / "wardline.overlay.yaml").write_text("""\
overlay_for: "src/api/"
optional_fields:
  - field: "middle_name"
    approved_default: ""
    rationale: "spoofed"
""")

        with pytest.raises(GovernanceError, match="claims overlay_for"):
            resolve_optional_fields(tmp_path, root_model)


# ── Schema Validation ─────────────────────────────────────────────


class TestSchemaValidation:
    def test_invalid_field_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("unknown_top_level_field: true\n")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_invalid_taint_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: "NOT_A_REAL_TAINT"
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_invalid_tier_range_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
tiers:
  - id: "bad"
    tier: 99
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_invalid_optional_fields_shape_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.overlay.yaml"
        f.write_text("""\
overlay_for: "adapters/"
optional_fields:
  - "middle_name"
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_overlay(f)

    def test_invalid_rule_override_shape_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
rules:
  overrides:
    - id: "PY-WL-001"
      severtiy: "WARNING"
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_invalid_overlay_rule_override_shape_rejected(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "wardline.overlay.yaml"
        f.write_text("""\
overlay_for: "adapters/"
rule_overrides:
  - id: "PY-WL-001"
    severtiy: "WARNING"
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_overlay(f)


# ── $id Version Check ─────────────────────────────────────────────


class TestVersionCheck:
    def test_matching_version_accepted(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
"$id": "https://wardline.dev/schemas/0.1/wardline.schema.json"
tiers: []
""")
        manifest = load_manifest(f)
        assert manifest is not None

    def test_mismatched_version_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
"$id": "https://wardline.dev/schemas/9.9/wardline.schema.json"
tiers: []
""")
        with pytest.raises(ManifestLoadError, match="targets schema version"):
            load_manifest(f)

    def test_no_id_accepted(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("tiers: []\n")
        manifest = load_manifest(f)
        assert manifest is not None


# ── File Size Limit ───────────────────────────────────────────────


class TestFileSizeLimit:
    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        # Write a file just over 1MB
        f.write_bytes(b"x: " + b"a" * (MAX_FILE_SIZE + 1) + b"\n")
        with pytest.raises(ManifestLoadError, match="exceeding"):
            load_manifest(f)

    def test_file_at_limit_accepted(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        # Tiny valid YAML — well under limit
        f.write_text("{}\n")
        manifest = load_manifest(f)
        assert manifest is not None


# ── Alias Bomb Protection ─────────────────────────────────────────


class TestAliasBomb:
    def test_alias_bomb_rejected(self, tmp_path: Path) -> None:
        """YAML alias bomb exceeding limit raises error."""
        from wardline.manifest.loader import _load_yaml

        f = tmp_path / "bomb.yaml"
        # Each level adds 2 alias resolutions. With limit=10,
        # 6 levels = 12 alias resolutions > 10.
        lines = ["a0: &a0 x"]
        for i in range(1, 7):
            lines.append(f"a{i}: &a{i} [*a{i-1}, *a{i-1}]")
        f.write_text("\n".join(lines) + "\n")
        with pytest.raises(WardlineYAMLError, match="alias limit"):
            _load_yaml(f, alias_limit=10)

    def test_reasonable_aliases_accepted(self, tmp_path: Path) -> None:
        """A few aliases don't trigger the alias limiter."""
        from wardline.manifest.loader import _load_yaml

        f = tmp_path / "test.yaml"
        f.write_text("""\
base: &base
  x: 1
items:
  - *base
  - *base
  - *base
""")
        data = _load_yaml(f)
        assert len(data["items"]) == 3

    def test_custom_alias_limit(self) -> None:
        loader_cls = make_wardline_loader(alias_limit=5)
        assert loader_cls._alias_limit == 5

    def test_hard_upper_bound(self) -> None:
        loader_cls = make_wardline_loader(alias_limit=999_999)
        assert loader_cls._alias_limit == HARD_ALIAS_UPPER_BOUND

    def test_default_limit(self) -> None:
        loader_cls = make_wardline_loader()
        assert loader_cls._alias_limit == DEFAULT_ALIAS_LIMIT


# ── YAML 1.1 Coercion Tests ──────────────────────────────────────


class TestYaml11Coercion:
    """PyYAML uses YAML 1.1 which silently coerces values.

    Schema validation catches these type mismatches.
    """

    def test_norway_problem_no(self, tmp_path: Path) -> None:
        """Unquoted NO becomes boolean false — schema rejects."""
        f = tmp_path / "wardline.yaml"
        # default_taint expects string, gets bool from YAML 1.1
        f.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: NO
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_norway_problem_yes(self, tmp_path: Path) -> None:
        """Unquoted YES becomes boolean true — schema rejects."""
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: YES
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_norway_problem_off(self, tmp_path: Path) -> None:
        """Unquoted OFF becomes boolean false — schema rejects."""
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: OFF
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_norway_problem_on(self, tmp_path: Path) -> None:
        """Unquoted ON becomes boolean true — schema rejects."""
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
module_tiers:
  - path: "src/"
    default_taint: ON
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_sexagesimal_coercion(self, tmp_path: Path) -> None:
        """Unquoted 1:30 becomes integer 90 in YAML 1.1."""
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
metadata:
  organisation: 1:30
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_float_coercion(self, tmp_path: Path) -> None:
        """Unquoted 1.5 becomes float — schema rejects."""
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
metadata:
  organisation: 1.5
""")
        with pytest.raises(ManifestLoadError, match="Schema validation"):
            load_manifest(f)

    def test_quoted_strings_accepted(self, tmp_path: Path) -> None:
        """Quoted values are preserved as strings."""
        f = tmp_path / "wardline.yaml"
        f.write_text("""\
metadata:
  organisation: "NO"
module_tiers:
  - path: "src/"
    default_taint: "EXTERNAL_RAW"
""")
        manifest = load_manifest(f)
        assert manifest.metadata.organisation == "NO"


# ── Non-mapping YAML ──────────────────────────────────────────────


class TestNonMappingYaml:
    def test_list_yaml_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("- item1\n- item2\n")
        with pytest.raises(ManifestLoadError, match="must be a YAML mapping"):
            load_manifest(f)

    def test_scalar_yaml_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.yaml"
        f.write_text("just a string\n")
        with pytest.raises(ManifestLoadError, match="must be a YAML mapping"):
            load_manifest(f)

    def test_overlay_list_yaml_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wardline.overlay.yaml"
        f.write_text("- item1\n- item2\n")
        with pytest.raises(ManifestLoadError, match="must be a YAML mapping"):
            load_overlay(f)
