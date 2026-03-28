"""Tests for exception register governance — taint drift and level stale detection.

Task 8 of WP 2.1: L3 call-graph taint implementation.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import ExceptionEntry
from wardline.scanner.context import Finding
from wardline.scanner.exceptions import apply_exceptions


def _make_exception(
    *,
    id: str = "EXC-001",
    rule: str = "PY-WL-001",
    taint_state: str = "ASSURED",
    location: str = "src/app.py::my_func",
    exceptionability: str = "STANDARD",
    severity_at_grant: str = "ERROR",
    rationale: str = "Test exception",
    reviewer: str = "test-reviewer",
    expires: str | None = "2027-01-01",
    ast_fingerprint: str = "abcdef1234567890",
    analysis_level: int = 1,
    **kwargs: object,
) -> ExceptionEntry:
    return ExceptionEntry(
        id=id,
        rule=rule,
        taint_state=taint_state,
        location=location,
        exceptionability=exceptionability,
        severity_at_grant=severity_at_grant,
        rationale=rationale,
        reviewer=reviewer,
        expires=expires,
        ast_fingerprint=ast_fingerprint,
        analysis_level=analysis_level,
        agent_originated=True,
        recurrence_count=0,
    )


def _make_finding(
    *,
    rule_id: RuleId = RuleId.PY_WL_001,
    file_path: str = "/project/src/app.py",
    qualname: str = "my_func",
    taint_state: TaintState = TaintState.ASSURED,
    severity: Severity = Severity.ERROR,
    exceptionability: Exceptionability = Exceptionability.STANDARD,
    analysis_level: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=10,
        col=0,
        end_line=None,
        end_col=None,
        message="Test finding",
        severity=severity,
        exceptionability=exceptionability,
        taint_state=taint_state,
        analysis_level=analysis_level,
        source_snippet=None,
        qualname=qualname,
    )


PROJECT_ROOT = Path("/project")
FIXED_NOW = datetime.date(2026, 6, 1)


class TestTaintDriftDetected:
    """Exception taint_state doesn't match function's current effective taint."""

    def test_taint_drift_detected(self) -> None:
        """Exception at ASSURED, function now EXTERNAL_RAW -> drift finding."""
        exc = _make_exception(
            taint_state="ASSURED",
            location="src/app.py::my_func",
        )
        # taint_map says my_func is now EXTERNAL_RAW
        taint_map = {"my_func": TaintState.EXTERNAL_RAW}

        _, governance = apply_exceptions(
            [],
            (exc,),
            PROJECT_ROOT,
            now=FIXED_NOW,
            taint_map=taint_map,
        )

        drift_findings = [
            g for g in governance
            if g.rule_id == RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT
        ]
        assert len(drift_findings) == 1
        assert "ASSURED" in drift_findings[0].message
        assert "EXTERNAL_RAW" in drift_findings[0].message
        assert drift_findings[0].exception_id == "EXC-001"


class TestLevelStaleDetected:
    """Exception analysis_level < active scan level."""

    def test_level_stale_detected(self) -> None:
        """Exception at level 1, scan at level 3 -> stale finding."""
        exc = _make_exception(analysis_level=1)

        _, governance = apply_exceptions(
            [],
            (exc,),
            PROJECT_ROOT,
            now=FIXED_NOW,
            analysis_level=3,
        )

        stale_findings = [
            g for g in governance
            if g.rule_id == RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE
        ]
        assert len(stale_findings) == 1
        assert "level 1" in stale_findings[0].message
        assert "level 3" in stale_findings[0].message
        assert stale_findings[0].exception_id == "EXC-001"


class TestLevelStaleDoesNotSuppress:
    """Stale exception does not suppress findings."""

    def test_level_stale_does_not_suppress(self, tmp_path: Path) -> None:
        """Stale exception must not suppress the finding it would match."""
        # Create a real Python file so AST fingerprint can be computed
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        py_file = src_dir / "app.py"
        py_file.write_text("def my_func():\n    pass\n")

        # Compute the real fingerprint for this function
        from wardline.scanner.fingerprint import compute_ast_fingerprint

        fp = compute_ast_fingerprint(py_file, "my_func", project_root=tmp_path)

        exc = _make_exception(
            taint_state="ASSURED",
            location="src/app.py::my_func",
            analysis_level=1,
            ast_fingerprint=fp or "abcdef1234567890",
        )

        finding = _make_finding(
            file_path=str(py_file),
            taint_state=TaintState.ASSURED,
        )

        processed, governance = apply_exceptions(
            [finding],
            (exc,),
            tmp_path,
            now=FIXED_NOW,
            analysis_level=3,  # Exception is level 1, scan is level 3
        )

        # Finding should NOT be suppressed (stale exception is inactive)
        assert len(processed) == 1
        assert processed[0].severity == Severity.ERROR  # Not SUPPRESS

        # Level-stale governance finding should be emitted
        stale_findings = [
            g for g in governance
            if g.rule_id == RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE
        ]
        assert len(stale_findings) == 1


class TestMatchingExceptionStillWorks:
    """Taint and level match -> normal suppression."""

    def test_matching_exception_still_works(self, tmp_path: Path) -> None:
        """When taint and level match, exception suppresses normally."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        py_file = src_dir / "app.py"
        py_file.write_text("def my_func():\n    pass\n")

        from wardline.scanner.fingerprint import compute_ast_fingerprint

        fp = compute_ast_fingerprint(py_file, "my_func", project_root=tmp_path)
        assert fp is not None

        exc = _make_exception(
            taint_state="ASSURED",
            location="src/app.py::my_func",
            analysis_level=3,
            ast_fingerprint=fp,
        )

        finding = _make_finding(
            file_path=str(py_file),
            taint_state=TaintState.ASSURED,
        )

        taint_map = {"my_func": TaintState.ASSURED}

        processed, governance = apply_exceptions(
            [finding],
            (exc,),
            tmp_path,
            now=FIXED_NOW,
            analysis_level=3,
            taint_map=taint_map,
        )

        # Finding should be suppressed
        assert len(processed) == 1
        assert processed[0].severity == Severity.SUPPRESS

        # No drift or stale findings
        drift_findings = [
            g for g in governance
            if g.rule_id == RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT
        ]
        stale_findings = [
            g for g in governance
            if g.rule_id == RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE
        ]
        assert len(drift_findings) == 0
        assert len(stale_findings) == 0


class TestDriftFindingIsUnconditional:
    """Drift findings cannot be excepted (UNCONDITIONAL exceptionability)."""

    def test_drift_finding_is_unconditional(self) -> None:
        """GOVERNANCE_EXCEPTION_TAINT_DRIFT finding has UNCONDITIONAL exceptionability."""
        exc = _make_exception(
            taint_state="ASSURED",
            location="src/app.py::my_func",
        )
        taint_map = {"my_func": TaintState.EXTERNAL_RAW}

        _, governance = apply_exceptions(
            [],
            (exc,),
            PROJECT_ROOT,
            now=FIXED_NOW,
            taint_map=taint_map,
        )

        drift_findings = [
            g for g in governance
            if g.rule_id == RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT
        ]
        assert len(drift_findings) == 1
        assert drift_findings[0].exceptionability == Exceptionability.UNCONDITIONAL
