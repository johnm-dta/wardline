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

        h_root, _ = _compute_input_hash([f], tmp_path)
        h_sub, _ = _compute_input_hash([f], sub)
        assert h_root != h_sub

    def test_hard_failure_on_unreadable(self, tmp_path: Path) -> None:
        """OSError on read_bytes raises, does not silently skip."""
        from wardline.cli.scan import _compute_input_hash

        missing = tmp_path / "gone.py"
        with pytest.raises(OSError):
            _compute_input_hash([missing], tmp_path)
