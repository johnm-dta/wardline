"""Tests for manifest and overlay discovery."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from wardline.manifest.discovery import (
    GovernanceError,
    _find_all_overlays,
    discover_manifest,
    discover_overlays,
)
from wardline.manifest.models import ModuleTierEntry, WardlineManifest

if TYPE_CHECKING:
    from pathlib import Path


# ── discover_manifest ─────────────────────────────────────────────


class TestDiscoverManifest:
    def test_finds_manifest_in_current_dir(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("{}\n")
        result = discover_manifest(tmp_path)
        assert result is not None
        assert result.name == "wardline.yaml"

    def test_finds_manifest_in_parent(self, tmp_path: Path) -> None:
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text("{}\n")
        child = tmp_path / "src" / "module"
        child.mkdir(parents=True)
        result = discover_manifest(child)
        assert result is not None
        assert result == manifest

    def test_stops_at_git_directory(self, tmp_path: Path) -> None:
        # Create .git at tmp_path level — manifest is above it
        (tmp_path / ".git").mkdir()
        child = tmp_path / "src"
        child.mkdir()
        # No manifest anywhere
        result = discover_manifest(child)
        assert result is None

    def test_stops_at_git_even_with_manifest_above(
        self, tmp_path: Path
    ) -> None:
        # Manifest above .git — should NOT be found
        parent = tmp_path / "workspace"
        parent.mkdir()
        (parent / "wardline.yaml").write_text("{}\n")
        repo = parent / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        child = repo / "src"
        child.mkdir()
        result = discover_manifest(child)
        assert result is None

    def test_finds_manifest_at_git_level(self, tmp_path: Path) -> None:
        # Manifest at same level as .git — should be found
        (tmp_path / ".git").mkdir()
        (tmp_path / "wardline.yaml").write_text("{}\n")
        child = tmp_path / "src"
        child.mkdir()
        result = discover_manifest(child)
        assert result is not None
        assert result == tmp_path / "wardline.yaml"

    def test_returns_none_when_not_found(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        result = discover_manifest(tmp_path)
        assert result is None

    def test_symlink_cycle_detection(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wardline.manifest import discovery as discovery_module

        start = tmp_path / "src"
        start.mkdir()
        real_stat = discovery_module.os.stat
        call_count = 0

        def fake_stat(path: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return SimpleNamespace(st_ino=4242)
            return real_stat(path)

        monkeypatch.setattr(
            discovery_module,
            "os",
            SimpleNamespace(stat=fake_stat),
        )

        with caplog.at_level(logging.WARNING):
            result = discover_manifest(start)

        assert result is None
        assert "Symlink cycle detected" in caplog.text


# ── discover_overlays ─────────────────────────────────────────────


class TestDiscoverOverlays:
    @pytest.fixture()
    def project(self, tmp_path: Path) -> Path:
        """Create a project structure with overlays."""
        root = tmp_path / "project"
        root.mkdir()
        # module_tiers directories
        (root / "audit").mkdir()
        (root / "adapters").mkdir()
        (root / "vendor").mkdir()
        # Overlays in allowed dirs
        (root / "audit" / "wardline.overlay.yaml").write_text(
            'overlay_for: "audit/"\n'
        )
        (root / "adapters" / "wardline.overlay.yaml").write_text(
            'overlay_for: "adapters/"\n'
        )
        return root

    @pytest.fixture()
    def manifest(self) -> WardlineManifest:
        return WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path="audit/", default_taint="INTEGRAL"),
                ModuleTierEntry(
                    path="adapters/", default_taint="EXTERNAL_RAW"
                ),
            ),
        )

    def test_module_tiers_default(
        self, project: Path, manifest: WardlineManifest
    ) -> None:
        """Secure default: only module_tiers directories searched."""
        overlays = discover_overlays(project, manifest)
        assert len(overlays) == 2
        names = {o.parent.name for o in overlays}
        assert names == {"audit", "adapters"}

    def test_undeclared_overlay_raises(
        self, project: Path, manifest: WardlineManifest
    ) -> None:
        """Overlay in undeclared directory raises GovernanceError."""
        (project / "vendor" / "wardline.overlay.yaml").write_text(
            'overlay_for: "vendor/"\n'
        )
        with pytest.raises(GovernanceError, match="undeclared directory"):
            discover_overlays(project, manifest)

    def test_governance_error_has_guidance(
        self, project: Path, manifest: WardlineManifest
    ) -> None:
        """GovernanceError includes corrective guidance."""
        (project / "vendor" / "wardline.overlay.yaml").write_text(
            'overlay_for: "vendor/"\n'
        )
        with pytest.raises(GovernanceError, match="module_tiers"):
            discover_overlays(project, manifest)

    def test_star_sentinel_unrestricted(
        self, project: Path, manifest: WardlineManifest
    ) -> None:
        """'*' sentinel enables unrestricted overlay discovery."""
        (project / "vendor" / "wardline.overlay.yaml").write_text(
            'overlay_for: "vendor/"\n'
        )
        overlays = discover_overlays(
            project, manifest, overlay_paths=["*"]
        )
        assert len(overlays) == 3

    def test_explicit_overlay_paths(
        self, tmp_path: Path, manifest: WardlineManifest
    ) -> None:
        """Explicit overlay_paths overrides module_tiers default."""
        root = tmp_path / "explicit"
        root.mkdir()
        (root / "custom").mkdir()
        (root / "custom" / "wardline.overlay.yaml").write_text(
            'overlay_for: "custom/"\n'
        )
        overlays = discover_overlays(
            root, manifest, overlay_paths=["custom/"]
        )
        assert len(overlays) == 1
        assert overlays[0].parent.name == "custom"

    def test_no_overlays_found(
        self, tmp_path: Path, manifest: WardlineManifest
    ) -> None:
        root = tmp_path / "empty"
        root.mkdir()
        (root / "audit").mkdir()
        overlays = discover_overlays(root, manifest)
        assert overlays == []

    def test_nested_overlay(
        self, project: Path, manifest: WardlineManifest
    ) -> None:
        """Overlay in subdirectory of allowed dir is accepted."""
        sub = project / "audit" / "submodule"
        sub.mkdir()
        (sub / "wardline.overlay.yaml").write_text(
            'overlay_for: "audit/submodule/"\n'
        )
        overlays = discover_overlays(project, manifest)
        assert len(overlays) == 3  # audit, adapters, audit/submodule

    def test_explicit_overlay_paths_undeclared_raises(
        self, project: Path, manifest: WardlineManifest
    ) -> None:
        """With explicit overlay_paths, unlisted dirs still raise."""
        with pytest.raises(GovernanceError):
            discover_overlays(
                project, manifest, overlay_paths=["nonexistent/"]
            )


class TestFindAllOverlays:
    def test_returns_resolved_paths_for_dotdot_root(
        self, tmp_path: Path
    ) -> None:
        project = tmp_path / "project"
        nested = project / "src"
        nested.mkdir(parents=True)
        overlay = nested / "wardline.overlay.yaml"
        overlay.write_text('overlay_for: "src/"\n')

        inner = project / "nested"
        inner.mkdir()
        root_with_dotdot = inner / ".."
        overlays = _find_all_overlays(root_with_dotdot)

        assert overlays == [overlay.resolve()]

    def test_returns_resolved_paths_for_symlink_root(
        self, tmp_path: Path
    ) -> None:
        project = tmp_path / "project"
        nested = project / "src"
        nested.mkdir(parents=True)
        overlay = nested / "wardline.overlay.yaml"
        overlay.write_text('overlay_for: "src/"\n')

        symlink_root = tmp_path / "linked-project"
        symlink_root.symlink_to(project, target_is_directory=True)

        overlays = _find_all_overlays(symlink_root)

        assert overlays == [overlay.resolve()]
