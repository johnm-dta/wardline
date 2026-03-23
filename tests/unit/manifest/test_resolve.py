"""Tests for wardline.manifest.resolve — boundary resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.manifest.discovery import GovernanceError
from wardline.manifest.merge import ManifestWidenError
from wardline.manifest.models import (
    BoundaryEntry,
    ModuleTierEntry,
    TierEntry,
    WardlineManifest,
)
from wardline.manifest.resolve import resolve_boundaries


def _write_overlay(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _minimal_manifest(
    module_paths: tuple[str, ...] = (),
    tiers: tuple[TierEntry, ...] = (),
) -> WardlineManifest:
    return WardlineManifest(
        module_tiers=tuple(
            ModuleTierEntry(path=p, default_taint="EXTERNAL_RAW")
            for p in module_paths
        ),
        tiers=tiers if tiers else (TierEntry(id="EXTERNAL_RAW", tier=4),),
    )


class TestResolveBoundaries:
    def test_no_overlays_returns_empty(self, tmp_path: Path) -> None:
        manifest = _minimal_manifest()
        result = resolve_boundaries(tmp_path, manifest)
        assert result == ()

    def test_overlay_boundaries_returned_with_scope(self, tmp_path: Path) -> None:
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

        result = resolve_boundaries(tmp_path, manifest)

        assert len(result) == 1
        assert result[0].function == "Handler.handle"
        assert result[0].overlay_scope == "adapters"

    def test_governance_error_propagates(self, tmp_path: Path) -> None:
        """Overlay in undeclared directory raises GovernanceError."""
        rogue_dir = tmp_path / "rogue"
        rogue_dir.mkdir()
        _write_overlay(
            rogue_dir / "wardline.overlay.yaml",
            (
                '$id: "https://wardline.dev/schemas/0.1/overlay.schema.json"\n'
                "overlay_for: rogue\n"
                "boundaries: []\n"
            ),
        )
        manifest = _minimal_manifest()  # no module_tiers covering "rogue"

        with pytest.raises(GovernanceError):
            resolve_boundaries(tmp_path, manifest)

    def test_manifest_widen_error_propagates(self, tmp_path: Path) -> None:
        """ManifestWidenError from merge() propagates (not caught)."""
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
                "    from_tier: 4\n"
            ),
        )
        manifest = WardlineManifest(
            module_tiers=(ModuleTierEntry(path="core", default_taint="AUDIT_TRAIL"),),
            tiers=(
                TierEntry(id="AUDIT_TRAIL", tier=1),
                TierEntry(id="EXTERNAL_RAW", tier=4),
            ),
        )

        with pytest.raises(ManifestWidenError):
            resolve_boundaries(tmp_path, manifest)

    def test_bad_overlay_file_skipped(self, tmp_path: Path) -> None:
        """Overlay that fails to load is skipped, not crash."""
        overlay_dir = tmp_path / "adapters"
        overlay_dir.mkdir()
        # Write a file that will fail schema validation
        (overlay_dir / "wardline.overlay.yaml").write_text(
            "this_is_not_valid_overlay: true\n", encoding="utf-8"
        )
        manifest = _minimal_manifest(module_paths=("adapters",))

        result = resolve_boundaries(tmp_path, manifest)
        assert result == ()
