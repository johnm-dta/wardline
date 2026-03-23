"""Tests for exception matching and finding suppression."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import ExceptionEntry
from wardline.scanner.context import Finding
from wardline.scanner.exceptions import apply_exceptions
from wardline.scanner.fingerprint import compute_ast_fingerprint

NOW = datetime.date(2026, 3, 23)


def _make_finding(
    *,
    rule_id: RuleId = RuleId.PY_WL_001,
    file_path: str = "src/app.py",
    line: int = 10,
    col: int = 0,
    end_line: int | None = None,
    end_col: int | None = None,
    message: str = "test finding",
    severity: Severity = Severity.ERROR,
    exceptionability: Exceptionability = Exceptionability.STANDARD,
    taint_state: TaintState | None = TaintState.EXTERNAL_RAW,
    analysis_level: int = 1,
    source_snippet: str | None = None,
    qualname: str | None = "my_func",
    exception_id: str | None = None,
    exception_expires: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
        message=message,
        severity=severity,
        exceptionability=exceptionability,
        taint_state=taint_state,
        analysis_level=analysis_level,
        source_snippet=source_snippet,
        qualname=qualname,
        exception_id=exception_id,
        exception_expires=exception_expires,
    )


def _make_exception(
    *,
    id: str = "EXC-001",
    rule: str = "PY-WL-001",
    taint_state: str = "EXTERNAL_RAW",
    location: str = "src/app.py::my_func",
    exceptionability: str = "STANDARD",
    severity_at_grant: str = "ERROR",
    rationale: str = "accepted risk",
    reviewer: str = "alice",
    expires: str | None = "2026-12-31",
    provenance: str | None = None,
    agent_originated: bool | None = False,
    ast_fingerprint: str = "",
    recurrence_count: int = 0,
    governance_path: str = "standard",
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
        provenance=provenance,
        agent_originated=agent_originated,
        ast_fingerprint=ast_fingerprint,
        recurrence_count=recurrence_count,
        governance_path=governance_path,
    )


def _write_source(tmp_path: Path, relpath: str, source: str) -> str:
    """Write a Python source file and return the full path string."""
    full = tmp_path / relpath
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(source, encoding="utf-8")
    return str(full)


# ── Test 1: matching active exception suppresses finding ──────────────

def test_matching_active_exception_suppresses(tmp_path: Path) -> None:
    source = "def my_func():\n    pass\n"
    fpath = _write_source(tmp_path, "src/app.py", source)
    fp = compute_ast_fingerprint(Path(fpath), "my_func")
    assert fp is not None

    finding = _make_finding(file_path=fpath)
    exc = _make_exception(
        location=f"{fpath}::my_func",
        ast_fingerprint=fp,
    )

    processed, governance = apply_exceptions(
        [finding], (exc,), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0].severity == Severity.SUPPRESS
    assert processed[0].exceptionability == Exceptionability.TRANSPARENT
    assert processed[0].exception_id == "EXC-001"
    assert processed[0].exception_expires == "2026-12-31"


# ── Test 2: expired exception does not suppress ──────────────────────

def test_expired_exception_not_suppressed(tmp_path: Path) -> None:
    source = "def my_func():\n    pass\n"
    fpath = _write_source(tmp_path, "src/app.py", source)
    fp = compute_ast_fingerprint(Path(fpath), "my_func")

    finding = _make_finding(file_path=fpath)
    exc = _make_exception(
        location=f"{fpath}::my_func",
        ast_fingerprint=fp,
        expires="2026-01-01",  # before NOW
    )

    processed, governance = apply_exceptions(
        [finding], (exc,), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0].severity == Severity.ERROR  # not suppressed


# ── Test 3: fingerprint mismatch → not suppressed + GOVERNANCE-STALE ─

def test_fingerprint_mismatch_emits_stale_governance(tmp_path: Path) -> None:
    source = "def my_func():\n    pass\n"
    fpath = _write_source(tmp_path, "src/app.py", source)

    finding = _make_finding(file_path=fpath)
    exc = _make_exception(
        location=f"{fpath}::my_func",
        ast_fingerprint="deadbeef12345678",  # wrong fingerprint
    )

    processed, governance = apply_exceptions(
        [finding], (exc,), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0].severity == Severity.ERROR  # not suppressed

    stale = [g for g in governance if g.rule_id == RuleId.GOVERNANCE_STALE_EXCEPTION]
    assert len(stale) >= 1
    assert "stale AST fingerprint" in stale[0].message


# ── Test 4: UNCONDITIONAL exceptionability → not suppressed ──────────

def test_unconditional_finding_not_suppressed(tmp_path: Path) -> None:
    source = "def my_func():\n    pass\n"
    fpath = _write_source(tmp_path, "src/app.py", source)
    fp = compute_ast_fingerprint(Path(fpath), "my_func")

    finding = _make_finding(
        file_path=fpath,
        exceptionability=Exceptionability.UNCONDITIONAL,
    )
    exc = _make_exception(
        location=f"{fpath}::my_func",
        ast_fingerprint=fp,
    )

    processed, governance = apply_exceptions(
        [finding], (exc,), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0].severity == Severity.ERROR
    assert processed[0].exceptionability == Exceptionability.UNCONDITIONAL


# ── Test 5: no matching exception → unchanged ────────────────────────

def test_no_matching_exception_unchanged(tmp_path: Path) -> None:
    finding = _make_finding()
    # No exceptions at all
    processed, governance = apply_exceptions(
        [finding], (), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0] is finding  # exact same object


# ── Test 6: agent_originated=None → GOVERNANCE-UNKNOWN-PROVENANCE ────

def test_unknown_provenance_governance(tmp_path: Path) -> None:
    exc = _make_exception(agent_originated=None)

    processed, governance = apply_exceptions(
        [], (exc,), tmp_path, now=NOW
    )

    provenance = [
        g for g in governance
        if g.rule_id == RuleId.GOVERNANCE_UNKNOWN_PROVENANCE
    ]
    assert len(provenance) == 1
    assert "unknown agent provenance" in provenance[0].message


# ── Test 7: recurrence_count >= 2 → GOVERNANCE-RECURRING-EXCEPTION ───

def test_recurring_exception_governance(tmp_path: Path) -> None:
    exc = _make_exception(recurrence_count=2)

    processed, governance = apply_exceptions(
        [], (exc,), tmp_path, now=NOW
    )

    recurring = [
        g for g in governance
        if g.rule_id == RuleId.GOVERNANCE_RECURRING_EXCEPTION
    ]
    assert len(recurring) == 1
    assert "renewed 2 times" in recurring[0].message


# ── Test 8: expires=None → GOVERNANCE-NO-EXPIRY-EXCEPTION ────────────

def test_no_expiry_governance(tmp_path: Path) -> None:
    exc = _make_exception(expires=None)

    processed, governance = apply_exceptions(
        [], (exc,), tmp_path, now=NOW
    )

    no_expiry = [
        g for g in governance
        if g.rule_id == RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION
    ]
    assert len(no_expiry) == 1
    assert "no expiry date" in no_expiry[0].message


# ── Test 9: recurrence_count == 1 → no recurring governance ──────────

def test_recurrence_count_one_no_governance(tmp_path: Path) -> None:
    exc = _make_exception(recurrence_count=1)

    processed, governance = apply_exceptions(
        [], (exc,), tmp_path, now=NOW
    )

    recurring = [
        g for g in governance
        if g.rule_id == RuleId.GOVERNANCE_RECURRING_EXCEPTION
    ]
    assert len(recurring) == 0


# ── Test 10: empty fingerprint → GOVERNANCE-STALE (always stale) ─────

def test_empty_fingerprint_emits_stale_governance(tmp_path: Path) -> None:
    source = "def my_func():\n    pass\n"
    fpath = _write_source(tmp_path, "src/app.py", source)

    finding = _make_finding(file_path=fpath)
    exc = _make_exception(
        location=f"{fpath}::my_func",
        ast_fingerprint="",  # empty
    )

    processed, governance = apply_exceptions(
        [finding], (exc,), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0].severity == Severity.ERROR  # not suppressed

    stale = [g for g in governance if g.rule_id == RuleId.GOVERNANCE_STALE_EXCEPTION]
    assert len(stale) >= 1
    assert "no AST fingerprint" in stale[0].message


# ── Test 11: qualname=None → unchanged (not matchable) ───────────────

def test_qualname_none_not_matchable(tmp_path: Path) -> None:
    source = "def my_func():\n    pass\n"
    fpath = _write_source(tmp_path, "src/app.py", source)
    fp = compute_ast_fingerprint(Path(fpath), "my_func")

    finding = _make_finding(file_path=fpath, qualname=None)
    exc = _make_exception(
        location=f"{fpath}::my_func",
        ast_fingerprint=fp,
    )

    processed, governance = apply_exceptions(
        [finding], (exc,), tmp_path, now=NOW
    )

    assert len(processed) == 1
    assert processed[0].severity == Severity.ERROR
    assert processed[0] is finding
