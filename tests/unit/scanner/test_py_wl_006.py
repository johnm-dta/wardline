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


# -- Positive: logger calls in broad handlers ------------------------------


class TestLoggerInBroadHandler:
    """Logger calls inside broad exception handlers fire PY-WL-006."""

    def test_logger_error_in_except_exception(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    logger.error("failed")
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_006
        assert rule.findings[0].severity == Severity.ERROR

    def test_logger_info_in_bare_except(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except:
    logger.info("something happened")
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_006

    def test_logger_warning_in_except_base_exception(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except BaseException:
    logger.warning("base exception caught")
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_006

    def test_logger_debug_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    logger.debug("debug info")
"""
        )

        assert len(rule.findings) == 1

    def test_logger_critical_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    logger.critical("critical failure")
"""
        )

        assert len(rule.findings) == 1

    def test_logger_exception_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception as e:
    logger.exception("unhandled error")
"""
        )

        assert len(rule.findings) == 1


# -- Positive: database/audit writes in broad handlers --------------------


class TestAuditWritesInBroadHandler:
    """Database and audit writes inside broad handlers fire PY-WL-006."""

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
        assert rule.findings[0].rule_id == RuleId.PY_WL_006

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

    def test_store_save_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    store.save(record)
"""
        )

        assert len(rule.findings) == 1

    def test_db_insert_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception as e:
    db.insert(error_record)
"""
        )

        assert len(rule.findings) == 1

    def test_writer_write_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    writer.write(log_entry)
"""
        )

        assert len(rule.findings) == 1


# -- Positive: multiple audit writes in one handler -----------------------


class TestMultipleAuditWrites:
    """Multiple audit writes in a single handler each produce a finding."""

    def test_two_writes_produce_two_findings(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    logger.error("failed")
    db.record_failure(data)
"""
        )

        assert len(rule.findings) == 2

    def test_two_broad_handlers_each_with_writes(self) -> None:
        rule = _run_rule(
            """\
try:
    foo()
except Exception:
    logger.error("foo failed")

try:
    bar()
except BaseException:
    logger.error("bar failed")
"""
        )

        assert len(rule.findings) == 2


# -- Positive: tuple with broad member ------------------------------------


class TestTupleBroadHandler:
    """except (Exception, ValueError) is still broad."""

    def test_tuple_with_exception_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except (Exception, ValueError):
    logger.error("failed")
"""
        )

        assert len(rule.findings) == 1


# -- Positive: async function ---------------------------------------------


class TestAsyncFunction:
    """Broad handlers in async functions fire PY-WL-006."""

    def test_async_except_exception_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    try:
        await process(data)
    except Exception:
        logger.error("async failed")
"""
        )

        assert len(rule.findings) == 1


# -- Positive: bare function names ----------------------------------------


class TestBareFunctionAuditCalls:
    """Bare audit function calls in broad handlers fire."""

    def test_print_in_broad_handler_fires(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    print("error occurred")
"""
        )

        assert len(rule.findings) == 1


# -- Negative: specific exception handlers --------------------------------


class TestSpecificHandlersNoFire:
    """Audit writes in specific exception handlers do NOT fire PY-WL-006."""

    def test_logger_in_value_error_handler_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except ValueError:
    logger.error("value error")
"""
        )

        assert len(rule.findings) == 0

    def test_logger_in_key_error_handler_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except KeyError as e:
    logger.error("key error: %s", e)
"""
        )

        assert len(rule.findings) == 0

    def test_logger_in_specific_tuple_handler_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except (TypeError, ValueError):
    logger.error("type or value error")
"""
        )

        assert len(rule.findings) == 0


# -- Negative: non-audit calls in broad handlers --------------------------


class TestNonAuditCallsNoFire:
    """Non-audit calls in broad handlers do NOT fire PY-WL-006."""

    def test_regular_method_call_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    cleanup()
"""
        )

        assert len(rule.findings) == 0

    def test_data_processing_in_handler_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    result = transform(data)
"""
        )

        assert len(rule.findings) == 0

    def test_reraise_only_silent(self) -> None:
        rule = _run_rule(
            """\
try:
    process(data)
except Exception:
    raise
"""
        )

        assert len(rule.findings) == 0


# -- Negative: no try/except at all ---------------------------------------


class TestNoTryExcept:
    """No try/except produces no findings."""

    def test_plain_function_silent(self) -> None:
        rule = _run_rule("x = 1\n")

        assert len(rule.findings) == 0


# -- Edge: nested functions ------------------------------------------------


class TestNestedFunctions:
    """Audit writes in nested function broad handlers are separate findings."""

    def test_nested_function_handler_fires_separately(self) -> None:
        rule = _run_rule_module(
            """\
def outer():
    try:
        pass
    except Exception:
        logger.error("outer")

    def inner():
        try:
            pass
        except Exception:
            logger.error("inner")
"""
        )

        assert len(rule.findings) == 2
