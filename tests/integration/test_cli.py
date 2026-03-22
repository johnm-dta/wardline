"""Integration tests for the wardline CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE_PROJECT = (
    Path(__file__).parent.parent / "fixtures" / "integration" / "sample_project"
)


@pytest.mark.integration
class TestCliExitCodes:
    """Verify CLI exit codes match the specification."""

    def test_exit_0_clean_scan(self, tmp_path: Path) -> None:
        """Scan a directory with no wardline patterns exits 0."""
        # Create a minimal valid manifest
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            "tiers:\n"
            '  - id: "test"\n'
            "    tier: 1\n"
            '    description: "test tier"\n'
            "module_tiers: []\n"
            "metadata:\n"
            '  organisation: "TestOrg"\n'
        )
        # Create a clean Python file with no patterns
        py_file = tmp_path / "clean.py"
        py_file.write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--manifest", str(manifest)])
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
        )

    def test_exit_1_findings_present(self) -> None:
        """Scan fixture project with wardline patterns exits 1."""
        manifest = FIXTURE_PROJECT / "wardline.yaml"
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--manifest", str(manifest)])
        assert result.exit_code == 1, (
            f"Expected exit 1, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
        )

    def test_exit_2_missing_manifest(self) -> None:
        """Missing manifest file exits 2."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "--manifest", "/nonexistent/wardline.yaml"]
        )
        assert result.exit_code == 2, (
            f"Expected exit 2, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
        )

    def test_exit_2_invalid_yaml(self, tmp_path: Path) -> None:
        """Manifest with invalid YAML exits 2, no traceback."""
        bad_manifest = tmp_path / "wardline.yaml"
        bad_manifest.write_text(":\n  - :\n    bad: [unbalanced\n")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--manifest", str(bad_manifest)])
        assert result.exit_code == 2, (
            f"Expected exit 2, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
        )
        assert "Traceback" not in result.output

    def test_exit_2_schema_invalid(self, tmp_path: Path) -> None:
        """Manifest that fails schema validation exits 2."""
        bad_manifest = tmp_path / "wardline.yaml"
        # Valid YAML but invalid schema — missing required fields
        bad_manifest.write_text("not_a_valid_key: true\n")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--manifest", str(bad_manifest)])
        assert result.exit_code == 2, (
            f"Expected exit 2, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
        )


@pytest.mark.integration
class TestCliStructuredErrors:
    """Verify error output formatting."""

    def test_error_no_traceback(self) -> None:
        """Error output does NOT contain Python tracebacks."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "--manifest", "/nonexistent/wardline.yaml"]
        )
        assert "Traceback" not in result.output
        assert "Traceback" not in (result.output or "")

    def test_error_to_stderr(self) -> None:
        """Error messages go to stderr, not stdout.

        Click 8.2+ always separates stderr. result.stderr has stderr,
        result.stdout has stdout only.
        """
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "--manifest", "/nonexistent/wardline.yaml"]
        )
        # The error message should be on stderr
        assert "error:" in result.stderr
        # stdout should NOT contain the error prefix
        assert "error:" not in result.stdout


@pytest.mark.integration
class TestCliOptions:
    """Verify CLI option handling."""

    def test_verbose_flag(self, tmp_path: Path) -> None:
        """--verbose produces logging output on stderr."""
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            "tiers:\n"
            '  - id: "test"\n'
            "    tier: 1\n"
            '    description: "test tier"\n'
            "module_tiers: []\n"
            "metadata:\n"
            '  organisation: "TestOrg"\n'
        )
        py_file = tmp_path / "clean.py"
        py_file.write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "--manifest", str(manifest), "--verbose"]
        )
        # Verbose should produce INFO-level log messages on stderr
        assert "INFO" in result.stderr

    def test_help_flag(self) -> None:
        """--help shows usage information."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Wardline" in result.output

    def test_scan_help_flag(self) -> None:
        """scan --help shows scan-specific usage."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--manifest" in result.output
