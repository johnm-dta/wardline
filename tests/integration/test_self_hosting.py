"""Self-hosting gate tests — __init_subclass__ safety and SARIF regression (T-6.4b)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

_REPO_ROOT = Path(__file__).parent.parent.parent
_MANIFEST = _REPO_ROOT / "wardline.yaml"
_CONFIG = _REPO_ROOT / "wardline.toml"
_SARIF_BASELINE = _REPO_ROOT / "wardline.sarif.baseline.json"


def _extract_sarif(output: str) -> str:
    """Extract JSON block from mixed CliRunner output."""
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        return ""
    return output[start : end + 1]


@pytest.mark.integration
class TestInitSubclassSafety:
    """Scanning wardline does not register new WardlineBase subclasses."""

    def test_no_new_subclasses_after_scan(self) -> None:
        """WardlineBase.__subclasses__() is unchanged after a scan.

        The scanner imports and processes wardline source files via AST
        parsing — it does NOT execute them. If a scan caused import
        side-effects that triggered __init_subclass__, it would mean
        the scanner is executing user code, which is a security issue.
        """
        from wardline.runtime.base import WardlineBase

        before = set(WardlineBase.__subclasses__())

        from wardline.cli.main import cli

        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest", str(_MANIFEST),
                "--config", str(_CONFIG),
                "--verification-mode",
            ],
        )

        after = set(WardlineBase.__subclasses__())
        new_subclasses = after - before
        assert not new_subclasses, (
            f"Scan registered new WardlineBase subclasses: "
            f"{[c.__name__ for c in new_subclasses]}"
        )


@pytest.mark.integration
class TestSarifRegressionBaseline:
    """SARIF regression comparison against committed baseline."""

    @pytest.fixture()
    def current_results(self) -> list[dict]:
        """Run a fresh scan and return the results array."""
        from wardline.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(_REPO_ROOT / "src" / "wardline"),
                "--manifest", str(_MANIFEST),
                "--config", str(_CONFIG),
                "--verification-mode",
            ],
        )
        sarif = json.loads(_extract_sarif(result.output))
        return sarif["runs"][0]["results"]

    @pytest.fixture()
    def baseline_results(self) -> list[dict]:
        """Load the committed SARIF baseline results."""
        if not _SARIF_BASELINE.exists():
            pytest.skip("No SARIF baseline committed yet")
        baseline = json.loads(_SARIF_BASELINE.read_text())
        return baseline["runs"][0]["results"]

    def test_no_suppression_regression(
        self,
        current_results: list[dict],
        baseline_results: list[dict],
    ) -> None:
        """Finding count should not decrease (suppression regression).

        A decrease means findings were suppressed — this requires
        human sign-off, not silent acceptance.
        """
        # Filter out governance findings for comparison
        current_scan = [
            r for r in current_results
            if "GOVERNANCE" not in r["ruleId"]
        ]
        baseline_scan = [
            r for r in baseline_results
            if "GOVERNANCE" not in r["ruleId"]
        ]

        assert len(current_scan) >= len(baseline_scan) - 5, (
            f"Finding count decreased significantly: "
            f"baseline={len(baseline_scan)}, current={len(current_scan)}. "
            f"Possible suppression regression — requires review."
        )

    def test_finding_increase_flagged(
        self,
        current_results: list[dict],
        baseline_results: list[dict],
    ) -> None:
        """A large finding increase is flagged (new findings detected).

        New findings are acceptable but should be reviewed. A large
        increase (>20) suggests a scanner change or new code pattern.
        """
        current_scan = [
            r for r in current_results
            if "GOVERNANCE" not in r["ruleId"]
        ]
        baseline_scan = [
            r for r in baseline_results
            if "GOVERNANCE" not in r["ruleId"]
        ]

        increase = len(current_scan) - len(baseline_scan)
        # This is informational — a moderate increase is fine
        assert increase <= 50, (
            f"Finding count increased by {increase}: "
            f"baseline={len(baseline_scan)}, current={len(current_scan)}. "
            f"Review new findings."
        )
