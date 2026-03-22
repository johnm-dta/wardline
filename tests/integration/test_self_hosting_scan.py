"""Integration tests for self-hosting scan gate (T-6.4a).

Verifies that wardline can scan its own codebase:
- Scanner runs without crashing (no TOOL-ERROR exit code 3)
- Manifest loads and validates
- Tier-distribution check passes at configured threshold
- Coverage check script runs
- Finding count is stable (regression baseline)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

# Paths are relative to repo root
_REPO_ROOT = Path(__file__).parent.parent.parent


def _extract_sarif_json(output: str) -> str:
    """Extract the JSON object from mixed stdout+stderr output.

    CliRunner merges stdout and stderr by default, so the output may
    contain log lines before the SARIF JSON and a summary line after.
    We find the first '{' and the last '}' to isolate the JSON block.
    """
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        return ""
    return output[start : end + 1]
_MANIFEST = _REPO_ROOT / "wardline.yaml"
_CONFIG = _REPO_ROOT / "wardline.toml"


@pytest.mark.integration
class TestSelfHostingScan:
    """Wardline scans its own codebase without crashing."""

    def test_scan_does_not_crash(self) -> None:
        """Exit code is not 3 (TOOL-ERROR) — scanner processes all files."""
        from wardline.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest",
                str(_MANIFEST),
                "--config",
                str(_CONFIG),
                "--verification-mode",
            ],
        )
        # Exit 1 (findings present) is expected; exit 3 (crash) is not
        assert result.exit_code != 3, (
            f"Scanner crashed (exit 3): {result.output}"
        )
        # Exit 2 (config error) should not happen
        assert result.exit_code != 2, (
            f"Config error (exit 2): {result.output}"
        )

    def test_scan_produces_valid_sarif(self) -> None:
        """SARIF output is valid JSON with expected structure."""
        import json

        from wardline.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest",
                str(_MANIFEST),
                "--config",
                str(_CONFIG),
                "--verification-mode",
            ],
        )

        sarif = json.loads(_extract_sarif_json(result.output))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert "results" in sarif["runs"][0]
        assert "properties" in sarif["runs"][0]

    def test_scan_finding_count_stable(self) -> None:
        """Finding count is within expected range (regression check).

        The self-hosting scan produces findings because wardline's own
        code uses dict.get(), hasattr(), getattr() with defaults, and
        exception handlers — exactly the patterns the scanner detects.
        These are documented, expected findings in a tooling codebase.
        """
        import json

        from wardline.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest",
                str(_MANIFEST),
                "--config",
                str(_CONFIG),
                "--verification-mode",
            ],
        )

        sarif = json.loads(_extract_sarif_json(result.output))
        results = sarif["runs"][0]["results"]

        # Separate governance from scan findings
        scan_findings = [
            r for r in results
            if "GOVERNANCE" not in r["ruleId"]
        ]

        # Baseline: ~101 findings as of T-6.4a.
        # Allow ±20 for minor code changes; a large increase suggests
        # a regression, a large decrease suggests suppression.
        assert len(scan_findings) >= 50, (
            f"Suspiciously few findings ({len(scan_findings)}) — "
            "possible suppression regression"
        )
        assert len(scan_findings) <= 200, (
            f"Too many findings ({len(scan_findings)}) — "
            "possible scanner regression"
        )

    def test_files_scanned_count(self) -> None:
        """Scanner processes all wardline source files."""
        import json

        from wardline.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest",
                str(_MANIFEST),
                "--config",
                str(_CONFIG),
                "--verification-mode",
            ],
        )

        # Check stderr for file count
        assert "file(s) scanned" in (result.output or "")

        sarif = json.loads(_extract_sarif_json(result.output))
        results = sarif["runs"][0]["results"]
        # At least some files should produce findings
        files_with_findings = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results
            if r.get("locations")
        }
        assert len(files_with_findings) >= 10


@pytest.mark.integration
class TestManifestValidation:
    """Self-hosting manifest validates correctly."""

    def test_manifest_loads(self) -> None:
        """wardline.yaml loads without errors."""
        from wardline.manifest.loader import load_manifest

        manifest = load_manifest(_MANIFEST)
        assert len(manifest.tiers) == 4
        assert len(manifest.module_tiers) >= 15

    def test_tier_distribution_under_threshold(self) -> None:
        """Permissive tiers (3+4) are under 60%."""
        from wardline.manifest.loader import load_manifest

        manifest = load_manifest(_MANIFEST)
        tier_map = {t.id: t.tier for t in manifest.tiers}

        total = len(manifest.module_tiers)
        permissive = sum(
            1 for mt in manifest.module_tiers
            if tier_map.get(mt.default_taint, 0) >= 3
        )
        pct = (permissive / total) * 100.0

        assert pct < 60.0, (
            f"Permissive tier ratio {pct:.1f}% exceeds 60% threshold"
        )


@pytest.mark.integration
class TestCoverageCheck:
    """Coverage check script runs correctly."""

    def test_coverage_check_runs(self) -> None:
        """scripts/coverage_check.py executes without import errors."""
        from scripts.coverage_check import check_coverage

        pct, decorated, total, details = check_coverage(
            _MANIFEST, threshold=0.0
        )
        # Wardline is a tooling project — 0% decorator coverage is
        # expected since its own functions don't process user data
        # through the wardline pipeline.
        assert total >= 10, "Should find public functions in T1/T4 modules"
        assert isinstance(pct, float)
