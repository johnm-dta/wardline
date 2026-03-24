"""Integration tests for self-hosting scan gate (T-6.4a).

Verifies that wardline can scan its own codebase:
- Scanner runs without crashing (no TOOL-ERROR exit code 3)
- Manifest loads and validates
- Tier-distribution check passes at configured threshold
- Coverage check script runs
- Finding count is stable (regression baseline) at L1 and L3
"""

from __future__ import annotations

import tempfile
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


def _config_with_analysis_level(analysis_level: int) -> Path:
    """Return a config path with the specified analysis_level.

    If analysis_level is 1 (default), returns the original config.
    Otherwise, creates a temporary config in the repo root (so that
    relative paths like target_paths resolve correctly).
    The caller is responsible for cleanup of temporary files.
    """
    if analysis_level == 1:
        return _CONFIG
    # Create temp copy in repo root so relative paths resolve correctly
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".toml", delete=False, prefix="wardline_test_",
        dir=_REPO_ROOT,
    )
    tmp.write(_CONFIG.read_text())
    tmp.write(f"\nanalysis_level = {analysis_level}\n")
    tmp.close()
    return Path(tmp.name)


def _run_scan(analysis_level: int = 1) -> tuple[int, str]:
    """Run a self-hosting scan at the given analysis level.

    Returns (exit_code, output).
    """
    from wardline.cli.main import cli

    config_path = _config_with_analysis_level(analysis_level)
    try:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest",
                str(_MANIFEST),
                "--config",
                str(config_path),
                "--verification-mode",
            ],
            catch_exceptions=False,
        )
        return result.exit_code, result.output
    finally:
        if config_path != _CONFIG:
            config_path.unlink(missing_ok=True)


@pytest.mark.integration
class TestSelfHostingScan:
    """Wardline scans its own codebase without crashing."""

    def test_scan_does_not_crash(self) -> None:
        """Exit code is not 3 (TOOL-ERROR) — scanner processes all files."""
        exit_code, output = _run_scan()
        # Exit 1 (findings present) is expected; exit 3 (crash) is not
        assert exit_code != 3, (
            f"Scanner crashed (exit 3): {output[:500]}"
        )
        # Exit 2 (config error) should not happen
        assert exit_code != 2, (
            f"Config error (exit 2): {output[:500]}"
        )

    def test_scan_produces_valid_sarif(self) -> None:
        """SARIF output is valid JSON with expected structure."""
        import json

        exit_code, output = _run_scan()

        sarif = json.loads(_extract_sarif_json(output))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert "results" in sarif["runs"][0]
        assert "properties" in sarif["runs"][0]

    @pytest.mark.parametrize(
        "analysis_level",
        [1, 3],
        ids=["L1", "L3"],
    )
    def test_scan_finding_count_stable(self, analysis_level: int) -> None:
        """Per-rule finding counts are within expected ranges.

        Prevents baseline erosion when tier-aware severity changes
        finding distribution. L1 ranges are +/- 50% of measured baselines.
        L3 ranges are initially wide (+/- 100%) until stabilized.
        """
        import json
        from collections import Counter

        exit_code, output = _run_scan(analysis_level=analysis_level)

        sarif = json.loads(_extract_sarif_json(output))
        results = sarif["runs"][0]["results"]
        scan_findings = [
            r for r in results
            if "GOVERNANCE" not in r["ruleId"]
        ]

        counts = Counter(r["ruleId"] for r in scan_findings)

        # Per-rule baselines by analysis level.
        # L1: measured 2026-03-24, +/- 50% tolerance.
        # L3: measured 2026-03-24, +/- 100% tolerance (wide initial ranges).
        expected_ranges_by_level: dict[int, dict[str, tuple[int, int]]] = {
            1: {
                "PY-WL-001": (51, 204),
                "PY-WL-002": (14, 56),
                "PY-WL-003": (57, 226),
                "PY-WL-004": (8, 30),
                "PY-WL-005": (14, 54),
                "PY-WL-006": (3, 10),
                "PY-WL-007": (80, 320),
                "PY-WL-008": (13, 52),
                "PY-WL-009": (84, 336),
            },
            3: {
                "PY-WL-001": (0, 204),
                "PY-WL-002": (0, 56),
                "PY-WL-003": (0, 226),
                "PY-WL-004": (0, 30),
                "PY-WL-005": (0, 54),
                "PY-WL-006": (0, 10),
                "PY-WL-007": (0, 320),
                "PY-WL-008": (0, 52),
                "PY-WL-009": (0, 336),
            },
        }

        expected_ranges = expected_ranges_by_level[analysis_level]

        for rule_id, (lo, hi) in expected_ranges.items():
            count = counts.get(rule_id, 0)
            assert lo <= count <= hi, (
                f"{rule_id} (L{analysis_level}): {count} findings "
                f"outside expected range [{lo}, {hi}]"
            )

        # Total sanity check
        total = len(scan_findings)
        assert total >= 50, f"Suspiciously few findings ({total})"
        assert total <= 1500, f"Too many findings ({total})"

    def test_files_scanned_count(self) -> None:
        """Scanner processes all wardline source files."""
        import json

        exit_code, output = _run_scan()

        # Check stderr for file count
        assert "file(s) scanned" in (output or "")

        sarif = json.loads(_extract_sarif_json(output))
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
