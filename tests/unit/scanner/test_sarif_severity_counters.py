"""Tests for SARIF run-level severity counters.

Verifies that the run properties include the four severity breakdown
counters (errorFindingCount, warningFindingCount, suppressedCellFindingCount,
gateBlockingCount) plus the renamed exceptedFindingCount.
"""
from __future__ import annotations

import json

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.sarif import SarifReport


def _make_finding(
    *,
    severity: Severity = Severity.ERROR,
    rule_id: RuleId = RuleId.PY_WL_001,
    exception_id: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path="test.py",
        line=1,
        col=1,
        end_line=None,
        end_col=None,
        message="test",
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        source_snippet=None,
        exception_id=exception_id,
    )


class TestSarifSeverityCounters:
    """Run-level properties include severity breakdown."""

    def test_counters_present(self) -> None:
        report = SarifReport(
            findings=[
                _make_finding(severity=Severity.SUPPRESS),
                _make_finding(severity=Severity.WARNING),
                _make_finding(severity=Severity.ERROR),
                _make_finding(severity=Severity.ERROR, exception_id="EXC-1"),
            ],
            analysis_level=1,
        )
        sarif = json.loads(report.to_json_string())
        props = sarif["runs"][0]["properties"]
        assert props["wardline.errorFindingCount"] == 2
        assert props["wardline.warningFindingCount"] == 1
        assert props["wardline.suppressedCellFindingCount"] == 1
        assert props["wardline.gateBlockingCount"] == 1

    def test_excepted_finding_count(self) -> None:
        """The renamed exceptedFindingCount replaces suppressedFindingCount."""
        report = SarifReport(
            findings=[
                _make_finding(severity=Severity.ERROR, exception_id="EXC-1"),
                _make_finding(severity=Severity.ERROR, exception_id="EXC-2"),
                _make_finding(severity=Severity.ERROR),
            ],
            analysis_level=1,
        )
        sarif = json.loads(report.to_json_string())
        props = sarif["runs"][0]["properties"]
        assert props["wardline.exceptedFindingCount"] == 2
        assert "wardline.suppressedFindingCount" not in props

    def test_counters_zero_when_no_findings(self) -> None:
        report = SarifReport(findings=[], analysis_level=1)
        sarif = json.loads(report.to_json_string())
        props = sarif["runs"][0]["properties"]
        assert props["wardline.errorFindingCount"] == 0
        assert props["wardline.warningFindingCount"] == 0
        assert props["wardline.suppressedCellFindingCount"] == 0
        assert props["wardline.gateBlockingCount"] == 0
        assert props["wardline.exceptedFindingCount"] == 0

    def test_all_suppress_means_zero_gate_blocking(self) -> None:
        report = SarifReport(
            findings=[
                _make_finding(severity=Severity.SUPPRESS),
                _make_finding(severity=Severity.SUPPRESS),
            ],
            analysis_level=1,
        )
        sarif = json.loads(report.to_json_string())
        props = sarif["runs"][0]["properties"]
        assert props["wardline.gateBlockingCount"] == 0
        assert props["wardline.suppressedCellFindingCount"] == 2
