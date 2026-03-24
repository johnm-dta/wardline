"""Integration tests for governance CLI subsystems.

End-to-end tests against the frozen governance fixture at
``tests/fixtures/governance/``, plus negative tests for malformed inputs.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli

if TYPE_CHECKING:
    pass

GOVERNANCE_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "governance"
)


# ---------------------------------------------------------------------------
# Positive integration tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCoherenceIntegration:
    """Full ``wardline manifest coherence`` against governance fixture."""

    def test_coherence_integration(self) -> None:
        """Coherence runs against governance fixture without crashing."""
        manifest = GOVERNANCE_FIXTURE / "wardline.yaml"
        src_path = GOVERNANCE_FIXTURE / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "manifest",
                "coherence",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )

        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
            f"stderr: {getattr(result, 'stderr', '')}"
        )
        # Should produce some output (either issues or "0 issues found")
        assert "issues found" in result.output.lower() or "issue" in result.output.lower()


@pytest.mark.integration
class TestFingerprintUpdateDiffRoundtrip:
    """``wardline fingerprint update`` then ``diff`` shows 0 changes."""

    def test_fingerprint_update_diff_roundtrip(self, tmp_path: Path) -> None:
        """Update creates baseline, diff against same code shows 0 changes."""
        # Copy fixture to tmp so we can write the baseline
        fixture_copy = tmp_path / "governance"
        shutil.copytree(GOVERNANCE_FIXTURE, fixture_copy)

        manifest = fixture_copy / "wardline.yaml"
        src_path = fixture_copy / "src"

        # Remove any pre-existing fingerprint baseline so update writes fresh
        baseline = fixture_copy / "wardline.fingerprint.json"
        if baseline.exists():
            baseline.unlink()

        runner = CliRunner()

        # Step 1: update
        update_result = runner.invoke(
            cli,
            [
                "fingerprint",
                "update",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )
        assert update_result.exit_code == 0, (
            f"update failed: {update_result.output}"
        )
        assert baseline.exists(), "Baseline file was not created"

        # Step 2: diff — should show 0 changes
        diff_result = runner.invoke(
            cli,
            [
                "fingerprint",
                "diff",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )
        assert diff_result.exit_code == 0, (
            f"diff failed: {diff_result.output}"
        )
        assert "0 changes" in diff_result.output


@pytest.mark.integration
class TestRegimeStatusIntegration:
    """Full ``wardline regime status`` from governance fixture."""

    def test_regime_status_integration(self) -> None:
        """Regime status runs against governance fixture without crashing."""
        manifest = GOVERNANCE_FIXTURE / "wardline.yaml"
        src_path = GOVERNANCE_FIXTURE / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "regime",
                "status",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )

        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )
        assert "Wardline Regime Status" in result.output
        assert "Governance profile:" in result.output
        assert "Exceptions:" in result.output
        assert "wardline regime verify --gate" in result.output


@pytest.mark.integration
class TestRegimeVerifyIntegration:
    """Full ``wardline regime verify`` from governance fixture."""

    def test_regime_verify_integration(self) -> None:
        """Regime verify runs against governance fixture without crashing."""
        manifest = GOVERNANCE_FIXTURE / "wardline.yaml"
        src_path = GOVERNANCE_FIXTURE / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "regime",
                "verify",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )

        # verify may exit 0 or report warnings — just should not crash
        assert result.exit_code in (0, 1), (
            f"Expected exit 0 or 1, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )
        assert "Wardline Regime Verify" in result.output
        assert "checks:" in result.output.lower()


@pytest.mark.integration
class TestExplainIntegration:
    """Full ``wardline explain`` against governance fixture."""

    def test_explain_integration(self) -> None:
        """Explain fetch_data from fixture shows taint, exceptions, overlay."""
        manifest = GOVERNANCE_FIXTURE / "wardline.yaml"
        # --path must be the fixture root (parent of src/) so overlays resolve
        fixture_root = GOVERNANCE_FIXTURE

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "fetch_data",
                "--path",
                str(fixture_root),
                "--manifest",
                str(manifest),
            ],
        )

        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )
        # Should show taint state
        assert "Taint state:" in result.output
        assert "EXTERNAL_RAW" in result.output

        # Should show exception section
        assert "Exceptions:" in result.output
        assert "EXC-001" in result.output

        # Should show overlay section
        assert "Overlay:" in result.output

        # Should show fingerprint section
        assert "Fingerprint:" in result.output


# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCoherenceMalformedManifest:
    """Corrupt YAML manifest -> exit 2."""

    def test_coherence_malformed_manifest(self, tmp_path: Path) -> None:
        """Malformed YAML manifest produces exit code 2."""
        bad_manifest = tmp_path / "wardline.yaml"
        bad_manifest.write_text(":\n  - :\n    bad: [unbalanced\n")

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "example.py").write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "manifest",
                "coherence",
                "--manifest",
                str(bad_manifest),
                "--path",
                str(src_dir),
            ],
        )

        assert result.exit_code == 2, (
            f"Expected exit 2, got {result.exit_code}.\n"
            f"stdout: {result.output}\n"
            f"stderr: {getattr(result, 'stderr', '')}"
        )


@pytest.mark.integration
class TestFingerprintDiffNoBaseline:
    """Diff without baseline -> warning, not error."""

    def test_fingerprint_diff_no_baseline(self, tmp_path: Path) -> None:
        """Missing baseline produces warning and exit 0, not a crash."""
        # Copy fixture but ensure no fingerprint baseline
        fixture_copy = tmp_path / "governance"
        shutil.copytree(GOVERNANCE_FIXTURE, fixture_copy)

        baseline = fixture_copy / "wardline.fingerprint.json"
        if baseline.exists():
            baseline.unlink()

        manifest = fixture_copy / "wardline.yaml"
        src_path = fixture_copy / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "fingerprint",
                "diff",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )

        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )
        # Should warn about missing baseline
        combined = result.output + getattr(result, "stderr", "")
        assert "no" in combined.lower() and "baseline" in combined.lower()


@pytest.mark.integration
class TestFingerprintDiffMalformedBaseline:
    """Corrupt JSON baseline -> exit 2."""

    def test_fingerprint_diff_malformed_baseline(self, tmp_path: Path) -> None:
        """Malformed JSON baseline produces exit code 2."""
        fixture_copy = tmp_path / "governance"
        shutil.copytree(GOVERNANCE_FIXTURE, fixture_copy)

        # Write corrupt JSON as the fingerprint baseline
        baseline = fixture_copy / "wardline.fingerprint.json"
        baseline.write_text("{this is not valid json!!!")

        manifest = fixture_copy / "wardline.yaml"
        src_path = fixture_copy / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "fingerprint",
                "diff",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )

        assert result.exit_code == 2, (
            f"Expected exit 2, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )


@pytest.mark.integration
class TestRegimeVerifyGateExitCode:
    """Verify with error conditions -> exit 1 with --gate."""

    def test_regime_verify_gate_exit_code(self, tmp_path: Path) -> None:
        """Verify --gate exits 1 when ERROR-level checks fail."""
        # Create a fixture with a malformed manifest that will fail loading
        # in the coherence check, producing an ERROR
        fixture_copy = tmp_path / "governance"
        shutil.copytree(GOVERNANCE_FIXTURE, fixture_copy)

        # Sabotage the exceptions file so exception_register_valid fails
        exceptions_file = fixture_copy / "wardline.exceptions.json"
        exceptions_file.write_text("{this is invalid json!!!")

        manifest = fixture_copy / "wardline.yaml"
        src_path = fixture_copy / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "regime",
                "verify",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
                "--gate",
            ],
        )

        assert result.exit_code == 1, (
            f"Expected exit 1, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )


@pytest.mark.integration
class TestRegimeVerifyMalformedExceptions:
    """Corrupt exceptions -> appropriate handling."""

    def test_regime_verify_malformed_exceptions(self, tmp_path: Path) -> None:
        """Corrupt exceptions file is handled gracefully in verify."""
        fixture_copy = tmp_path / "governance"
        shutil.copytree(GOVERNANCE_FIXTURE, fixture_copy)

        # Write corrupt exceptions
        exceptions_file = fixture_copy / "wardline.exceptions.json"
        exceptions_file.write_text("{not valid json!!!")

        manifest = fixture_copy / "wardline.yaml"
        src_path = fixture_copy / "src"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "regime",
                "verify",
                "--manifest",
                str(manifest),
                "--path",
                str(src_path),
            ],
        )

        # Should not crash — either exit 0 (warnings only) or report failures
        assert result.exit_code in (0, 1), (
            f"Expected exit 0 or 1, got {result.exit_code}.\n"
            f"stdout: {result.output}"
        )
        # The verify output should indicate something about the exception register
        assert "exception" in result.output.lower() or "FAIL" in result.output
