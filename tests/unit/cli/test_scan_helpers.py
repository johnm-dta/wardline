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
