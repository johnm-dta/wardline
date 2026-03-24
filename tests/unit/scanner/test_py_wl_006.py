"""Tests for PY-WL-006: Audit-critical writes in broad exception handlers."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_006 import RulePyWl006

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl006:
    """Parse source inside a function and run PY-WL-006."""
    tree = parse_function_source(source)
    rule = RulePyWl006(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl006:
    """Parse raw module source and run PY-WL-006."""
    tree = parse_module_source(source)
    rule = RulePyWl006(file_path="test.py")
    rule.visit(tree)
    return rule


class TestAuditShapedSinks:
    """Clearly audit-shaped sinks in broad handlers fire PY-WL-006."""

    def test_audit_emit_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    audit.emit("event_failed", data)
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_006
        assert rule.findings[0].severity == Severity.ERROR

    def test_db_record_failure_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    db.record_failure(data)
"""
        )

        assert len(rule.findings) == 1

    def test_ledger_emit_event_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    audit_ledger.emit_event(data)
"""
        )

        assert len(rule.findings) == 1


class TestDecoratedAuditTargets:
    """Locally declared audit writers and critical paths count as audit-critical."""

    def test_local_audit_writer_call_fires(self) -> None:
        rule = _run_rule_module(
            """\
@audit_writer
def write_audit(data):
    return None

def target():
    try:
        process(data)
    except Exception:
        write_audit(data)
"""
        )

        assert len(rule.findings) == 1

    def test_local_audit_critical_call_fires(self) -> None:
        rule = _run_rule_module(
            """\
@audit_critical
def emit_legal_record(data):
    return None

def target():
    try:
        process(data)
    except Exception:
        emit_legal_record(data)
"""
        )

        assert len(rule.findings) == 1


class TestSpecificHandlersNoFire:
    """Specific exception handlers do not trigger PY-WL-006."""

    def test_audit_call_in_specific_handler_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except ValueError:
    audit.emit("failed", data)
"""
        )

        assert len(rule.findings) == 0


class TestNonAuditTelemetryNoFire:
    """Generic telemetry is not treated as audit-critical by this rule."""

    def test_logger_error_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    logger.error("failed")
"""
        )

        assert len(rule.findings) == 0

    def test_print_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    print("error occurred")
"""
        )

        assert len(rule.findings) == 0

    def test_cleanup_call_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    cleanup()
"""
        )

        assert len(rule.findings) == 0


class TestAuditPathDominance:
    """Success paths that bypass audit should fire PY-WL-006."""

    def test_success_branch_without_audit_fires(self) -> None:
        rule = _run_rule(
            """\
if ok:
    audit.emit("success", data)
    return result
return cached_result
"""
        )

        assert len(rule.findings) == 1
        assert "bypass audit" in rule.findings[0].message

    def test_broad_handler_fallback_success_without_audit_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    return cached_result
audit.emit("processed", data)
return result
"""
        )

        assert len(rule.findings) == 1
        assert "bypass audit" in rule.findings[0].message

    def test_local_audit_writer_must_dominate_success_paths(self) -> None:
        rule = _run_rule_module(
            """\
@audit_writer
def write_audit(data):
    return None

def target():
    if skip:
        return result
    write_audit(data)
    return result
"""
        )

        assert len(rule.findings) == 1
        assert "bypass audit" in rule.findings[0].message

    def test_rejection_path_without_audit_is_allowed(self) -> None:
        rule = _run_rule(
            """\
if not ok:
    raise ValueError("bad")
audit.emit("success", data)
return result
"""
        )

        assert len(rule.findings) == 0

    def test_fallback_raise_without_audit_is_allowed(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    raise
audit.emit("processed", data)
return result
"""
        )

        assert len(rule.findings) == 0


class TestNestedAndAsyncBehavior:
    """Nested scopes and async handlers still work."""

    def test_async_broad_handler_with_audit_emit_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    try:
        await process(data)
    except Exception:
        audit.emit("async failed", data)
"""
        )

        assert len(rule.findings) == 1

    def test_nested_function_handler_fires_separately(self) -> None:
        rule = _run_rule_module(
            """\
def outer():
    try:
        pass
    except Exception:
        audit.emit("outer", data)

    def inner():
        try:
            pass
        except Exception:
            audit.emit("inner", data)
"""
        )

        assert len(rule.findings) == 2
