"""Unit tests for scan gate severity filtering.

The three-tier signal model (spec §7.3–§7.5, corpus_cmds.py:755–787):
- SUPPRESS (SARIF "note"): expected pattern at this taint state — excluded from gate
- WARNING (SARIF "warning"): suspicious, worth reviewing — excluded from gate
- ERROR (SARIF "error"): violates tier integrity contract — blocks gate unless excepted
"""
from __future__ import annotations

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding


def _make_finding(
    *,
    severity: Severity = Severity.ERROR,
    rule_id: RuleId = RuleId.PY_WL_001,
    exception_id: str | None = None,
) -> Finding:
    """Create a minimal Finding for gate logic tests."""
    return Finding(
        file_path="test.py",
        line=1,
        col=1,
        end_line=None,
        end_col=None,
        message="test finding",
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        rule_id=rule_id,
        qualname="mod.func",
        source_snippet=None,
        exception_id=exception_id,
        exception_expires=None,
    )


class TestGateBlockingFindings:
    """Gate should only count unexcepted ERROR findings."""

    def test_suppress_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.SUPPRESS)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_warning_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.WARNING)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_error_findings_block(self) -> None:
        findings = [_make_finding(severity=Severity.ERROR)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 1

    def test_excepted_error_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.ERROR, exception_id="EXC-001")]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_mixed_severities(self) -> None:
        findings = [
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.WARNING),
            _make_finding(severity=Severity.ERROR),
            _make_finding(severity=Severity.ERROR, exception_id="EXC-002"),
        ]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 1

    def test_empty_findings(self) -> None:
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking([]) == 0


class TestSeverityBreakdown:
    """Severity breakdown for stderr summary and SARIF counters."""

    def test_breakdown_counts(self) -> None:
        findings = [
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.WARNING),
            _make_finding(severity=Severity.ERROR),
            _make_finding(severity=Severity.ERROR, exception_id="EXC-001"),
        ]
        from wardline.cli._gate import severity_breakdown
        bd = severity_breakdown(findings)
        assert bd.error_count == 2
        assert bd.warning_count == 1
        assert bd.suppress_count == 2
        assert bd.excepted_count == 1
        assert bd.gate_blocking == 1  # 2 errors - 1 excepted

    def test_breakdown_empty(self) -> None:
        from wardline.cli._gate import severity_breakdown
        bd = severity_breakdown([])
        assert bd.error_count == 0
        assert bd.warning_count == 0
        assert bd.suppress_count == 0
        assert bd.excepted_count == 0
        assert bd.gate_blocking == 0
