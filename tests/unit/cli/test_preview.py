"""Tests for build_preview_report."""

from __future__ import annotations

from wardline.cli.preview import build_preview_report
from wardline.core.severity import (
    Exceptionability,
    RuleId,
    Severity,
)
from wardline.scanner.context import Finding


def _finding(
    rule_id: RuleId = RuleId.PY_WL_001,
    *,
    file_path: str = "src/app.py",
    line: int = 10,
    severity: Severity = Severity.ERROR,
    qualname: str | None = "App.handle",
    message: str = "test finding",
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=0,
        end_line=None,
        end_col=None,
        message=message,
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        source_snippet=None,
        qualname=qualname,
        exception_id=exception_id,
        original_rule=original_rule,
    )


class TestBuildPreviewReport:
    def test_empty(self) -> None:
        report = build_preview_report([], [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 0
        assert report["exception_rereview_count"] == 0
        assert report["total_phase2_impact"] == 0
        assert report["details"]["unverified_defaults"] == []
        assert report["details"]["exceptions_needing_rereview"] == []
        assert report["scan_metadata"]["scanned_path"] == "/tmp"
        assert report["scan_metadata"]["wardline_version"] == "0.2.0"
        assert "timestamp" in report["scan_metadata"]
        assert report["version"] == "1.0"

    def test_unverified_defaults(self) -> None:
        findings = [
            _finding(
                rule_id=RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
                file_path="src/a.py",
                line=42,
                qualname="Foo.bar",
                message="schema_default() without overlay boundary",
            ),
        ]
        report = build_preview_report(findings, [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 1
        assert report["total_phase2_impact"] == 1
        detail = report["details"]["unverified_defaults"][0]
        assert detail["file"] == "src/a.py"
        assert detail["line"] == 42
        assert detail["qualname"] == "Foo.bar"

    def test_governance_findings(self) -> None:
        gov = [
            _finding(
                rule_id=RuleId.GOVERNANCE_STALE_EXCEPTION,
                exception_id="EXC-aaa",
                original_rule="PY-WL-001",
                message="stale",
            ),
        ]
        report = build_preview_report([], gov, scanned_path="/tmp", wardline_version="0.2.0")
        assert report["exception_rereview_count"] == 1
        entry = report["details"]["exceptions_needing_rereview"][0]
        assert entry["exception_id"] == "EXC-aaa"
        assert entry["rule"] == "PY-WL-001"
        assert entry["reasons"] == ["stale_fingerprint"]

    def test_mixed(self) -> None:
        findings = [
            _finding(rule_id=RuleId.PY_WL_001_UNGOVERNED_DEFAULT),
        ]
        gov = [
            _finding(
                rule_id=RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
                exception_id="EXC-bbb",
                original_rule="PY-WL-002",
            ),
        ]
        report = build_preview_report(findings, gov, scanned_path="/tmp", wardline_version="0.2.0")
        assert report["total_phase2_impact"] == 2

    def test_ignores_governed_defaults(self) -> None:
        findings = [
            _finding(rule_id=RuleId.PY_WL_001_GOVERNED_DEFAULT, severity=Severity.SUPPRESS),
        ]
        report = build_preview_report(findings, [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 0

    def test_ignores_regular_py_wl_001(self) -> None:
        findings = [
            _finding(rule_id=RuleId.PY_WL_001, severity=Severity.ERROR),
        ]
        report = build_preview_report(findings, [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 0

    def test_deduplicates_exceptions(self) -> None:
        gov = [
            _finding(
                rule_id=RuleId.GOVERNANCE_STALE_EXCEPTION,
                exception_id="EXC-ccc",
                original_rule="PY-WL-001",
            ),
            _finding(
                rule_id=RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
                exception_id="EXC-ccc",
                original_rule="PY-WL-001",
            ),
            _finding(
                rule_id=RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
                exception_id="EXC-ccc",
                original_rule="PY-WL-001",
            ),
        ]
        report = build_preview_report([], gov, scanned_path="/tmp", wardline_version="0.2.0")
        assert report["exception_rereview_count"] == 1
        entry = report["details"]["exceptions_needing_rereview"][0]
        assert sorted(entry["reasons"]) == ["no_expiry", "stale_fingerprint", "unknown_provenance"]
