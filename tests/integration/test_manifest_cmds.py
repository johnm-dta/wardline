"""Integration tests for wardline manifest validate / baseline commands."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from click.testing import CliRunner

from wardline.cli.main import cli

VALID_MANIFEST_YAML = (
    "tiers:\n"
    '  - id: "core"\n'
    "    tier: 1\n"
    '    description: "core tier"\n'
    "module_tiers:\n"
    '  - path: "src/app"\n'
    '    default_taint: "PIPELINE"\n'
    "metadata:\n"
    '  organisation: "TestOrg"\n'
)

INVALID_MANIFEST_YAML = (
    "tiers:\n"
    '  - id: "bad"\n'
    "    tier: 99\n"  # tier max is 4 per schema
)


@pytest.mark.integration
class TestManifestValidate:
    """Tests for ``wardline manifest validate``."""

    def test_validate_valid_manifest(self, tmp_path: Path) -> None:
        """Valid manifest exits 0."""
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(VALID_MANIFEST_YAML)

        runner = CliRunner()
        result = runner.invoke(cli, ["manifest", "validate", str(manifest)])
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )
        assert "manifest valid" in result.output

    def test_validate_invalid_manifest(self, tmp_path: Path) -> None:
        """Invalid manifest exits 1."""
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(INVALID_MANIFEST_YAML)

        runner = CliRunner()
        result = runner.invoke(cli, ["manifest", "validate", str(manifest)])
        assert result.exit_code == 1, (
            f"Expected exit 1, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )
        assert "error:" in result.output

    def test_validate_file_not_found(self) -> None:
        """Non-existent file exits 2."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["manifest", "validate", "/nonexistent/wardline.yaml"]
        )
        assert result.exit_code == 2, (
            f"Expected exit 2, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )
        assert "not found" in result.output


@pytest.mark.integration
class TestManifestBaseline:
    """Tests for ``wardline manifest baseline update``."""

    def test_baseline_update_without_approve(self, tmp_path: Path) -> None:
        """Baseline update without --approve exits non-zero."""
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(VALID_MANIFEST_YAML)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["manifest", "baseline", "update", "--manifest", str(manifest)],
        )
        assert result.exit_code != 0, (
            f"Expected non-zero exit, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )
        assert "--approve" in result.output

    def test_baseline_update_with_approve(self, tmp_path: Path) -> None:
        """Baseline update with --approve exits 0 and writes files."""
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(VALID_MANIFEST_YAML)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "manifest",
                "baseline",
                "update",
                "--approve",
                "--manifest",
                str(manifest),
            ],
        )
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )

        manifest_baseline = tmp_path / "wardline.manifest.baseline.json"
        perimeter_baseline = tmp_path / "wardline.perimeter.baseline.json"
        assert manifest_baseline.exists(), "manifest baseline not written"
        assert perimeter_baseline.exists(), "perimeter baseline not written"

    def test_baseline_files_valid_json(self, tmp_path: Path) -> None:
        """Written baseline files are valid JSON with correct structure."""
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(VALID_MANIFEST_YAML)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "manifest",
                "baseline",
                "update",
                "--approve",
                "--manifest",
                str(manifest),
            ],
        )
        assert result.exit_code == 0, result.output

        manifest_baseline = json.loads(
            (tmp_path / "wardline.manifest.baseline.json").read_text()
        )
        assert "tiers" in manifest_baseline
        assert "module_tiers" in manifest_baseline
        assert len(manifest_baseline["tiers"]) == 1
        assert manifest_baseline["tiers"][0]["id"] == "core"
        assert manifest_baseline["tiers"][0]["tier"] == 1
        assert len(manifest_baseline["module_tiers"]) == 1
        assert manifest_baseline["module_tiers"][0]["path"] == "src/app"

        perimeter_baseline = json.loads(
            (tmp_path / "wardline.perimeter.baseline.json").read_text()
        )
        assert "module_paths" in perimeter_baseline
        assert perimeter_baseline["module_paths"] == ["src/app"]

    def test_baseline_update_manifest_not_found(
        self, tmp_path: Path
    ) -> None:
        """Baseline update with nonexistent manifest exits 2."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "manifest",
                "baseline",
                "update",
                "--approve",
                "--manifest",
                str(tmp_path / "nonexistent.yaml"),
            ],
        )
        assert result.exit_code == 2, result.output
