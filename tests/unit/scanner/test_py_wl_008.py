"""Tests for PY-WL-008: Validation with no rejection path."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.scanner.rules.py_wl_008 import RulePyWl008

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl008:
    """Parse source inside a function and run PY-WL-008."""
    tree = parse_function_source(source)
    rule = RulePyWl008(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl008:
    """Parse raw module source and run PY-WL-008."""
    tree = parse_module_source(source)
    rule = RulePyWl008(file_path="test.py")
    rule.visit(tree)
    return rule


# -- Positive: validation result ignored ----------------------------------


class TestValidationResultIgnored:
    """Validation result captured but never used in rejection fires PY-WL-008."""

    def test_check_schema_result_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
is_valid = check_schema(data)
return data
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_008
        assert rule.findings[0].severity == Severity.ERROR

    def test_validate_result_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
process(data)
"""
        )

        assert len(rule.findings) == 1

    def test_verify_result_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
ok = verify_input(data)
return data
"""
        )

        assert len(rule.findings) == 1

    def test_check_result_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
passed = check_input(data)
return data
"""
        )

        assert len(rule.findings) == 1

    def test_sanitize_result_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
clean = sanitize_input(data)
return data
"""
        )

        assert len(rule.findings) == 1

    def test_method_validation_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
is_valid = validator.check_input(data)
return data
"""
        )

        assert len(rule.findings) == 1

    def test_multiple_ignored_validations_fire(self) -> None:
        rule = _run_rule(
            """\
r1 = validate_schema(data)
r2 = check_format(data)
return data
"""
        )

        assert len(rule.findings) == 2


# -- Negative: validation result used in rejection path --------------------


class TestRejectionPathPresent:
    """Validation result used in if/assert/raise suppresses PY-WL-008."""

    def test_result_in_if_silent(self) -> None:
        rule = _run_rule(
            """\
is_valid = check_schema(data)
if not is_valid:
    raise ValueError("invalid")
return data
"""
        )

        assert len(rule.findings) == 0

    def test_result_in_assert_silent(self) -> None:
        rule = _run_rule(
            """\
is_valid = validate(data)
assert is_valid
return data
"""
        )

        assert len(rule.findings) == 0

    def test_result_in_raise_silent(self) -> None:
        rule = _run_rule(
            """\
error = verify_data(data)
if error:
    raise error
return data
"""
        )

        assert len(rule.findings) == 0

    def test_result_in_compound_if_with_raise_silent(self) -> None:
        rule = _run_rule(
            """\
is_valid = validate(data)
if is_valid and data:
    process(data)
else:
    raise ValueError("invalid")
"""
        )

        assert len(rule.findings) == 0

    def test_result_in_nested_if_with_return_silent(self) -> None:
        rule = _run_rule(
            """\
result = check_input(data)
if condition:
    if result:
        return data
"""
        )

        assert len(rule.findings) == 0


# -- Negative: no validation calls -----------------------------------------


class TestNoValidationCalls:
    """Functions without validation calls produce no findings."""

    def test_plain_function_silent(self) -> None:
        rule = _run_rule("x = 1\n")

        assert len(rule.findings) == 0

    def test_regular_function_call_silent(self) -> None:
        rule = _run_rule(
            """\
result = transform(data)
return result
"""
        )

        assert len(rule.findings) == 0

    def test_validation_call_not_assigned_fires(self) -> None:
        """Bare validation call (result discarded) is worse — fires PY-WL-008."""
        rule = _run_rule("validate(data)\n")

        assert len(rule.findings) == 1


# -- Positive: async function ---------------------------------------------


class TestAsyncFunction:
    """Ignored validation results in async functions fire PY-WL-008."""

    def test_async_validation_ignored_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    is_valid = check_schema(data)
    return data
"""
        )

        assert len(rule.findings) == 1


# -- Positive: annotated assignment ----------------------------------------


class TestAnnotatedAssignment:
    """Annotated assignments with validation calls fire PY-WL-008."""

    def test_annotated_validation_ignored_fires(self) -> None:
        rule = _run_rule(
            """\
is_valid: bool = validate(data)
return data
"""
        )

        assert len(rule.findings) == 1


# -- Edge: nested functions ------------------------------------------------


class TestNestedFunctions:
    """Ignored validations in nested functions produce separate findings."""

    def test_nested_function_fires_separately(self) -> None:
        rule = _run_rule_module(
            """\
def outer():
    r1 = validate(a)
    return a

    def inner():
        r2 = check(b)
        return b
"""
        )

        assert len(rule.findings) == 2


# -- Edge: validation in conditional but wrong variable --------------------


class TestWrongVariableInConditional:
    """Using a different variable in conditional does not suppress."""

    def test_different_variable_in_if_fires(self) -> None:
        rule = _run_rule(
            """\
is_valid = check_schema(data)
if other_var:
    raise ValueError("bad")
return data
"""
        )

        assert len(rule.findings) == 1


# -- Negative: rejection via function call ---------------------------------


class TestRejectionViaFunctionCall:
    """Passing result to rejection-like function suppresses PY-WL-008."""

    def test_abort_if_invalid_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
abort_if_invalid(result)
return data
"""
        )

        assert len(rule.findings) == 0


# -- Bug fix: bare validate() calls (wardline-f357c7f) ---------------------


class TestBareValidationCalls:
    """Bare validation calls (expression statements) fire PY-WL-008."""

    def test_bare_validate_fires(self) -> None:
        rule = _run_rule("validate(data)\n")
        assert len(rule.findings) == 1

    def test_bare_check_schema_fires(self) -> None:
        rule = _run_rule("check_schema(data)\n")
        assert len(rule.findings) == 1

    def test_bare_method_validation_fires(self) -> None:
        rule = _run_rule("obj.verify_input(data)\n")
        assert len(rule.findings) == 1

    def test_bare_non_validation_silent(self) -> None:
        rule = _run_rule("process(data)\n")
        assert len(rule.findings) == 0


# -- Bug fix: tighter rejection path (wardline-383463d) --------------------


class TestTighterRejectionPath:
    """if-test referencing result must have raise/return/reject in body."""

    def test_if_result_log_only_fires(self) -> None:
        """if result: log.info('ok') has no actual rejection — fires."""
        rule = _run_rule(
            """\
result = validate(data)
if result:
    log.info("ok")
return data
"""
        )
        assert len(rule.findings) == 1

    def test_if_result_with_raise_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
if not result:
    raise ValueError("bad")
return data
"""
        )
        assert len(rule.findings) == 0

    def test_if_result_with_return_in_else_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
if result:
    process(data)
else:
    return None
"""
        )
        assert len(rule.findings) == 0

    def test_if_result_with_reject_call_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
if not result:
    abort("invalid")
"""
        )
        assert len(rule.findings) == 0

    def test_if_result_with_only_assignment_fires(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
if result:
    x = 1
return data
"""
        )
        assert len(rule.findings) == 1


# -- Bug fix: return result delegation (wardline-5ed6fcf) ------------------


class TestReturnDelegation:
    """return result delegates rejection responsibility — suppresses."""

    def test_return_result_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return result
"""
        )
        assert len(rule.findings) == 0

    def test_return_result_in_tuple_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return data, result
"""
        )
        assert len(rule.findings) == 0

    def test_return_unrelated_fires(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return data
"""
        )
        assert len(rule.findings) == 1
