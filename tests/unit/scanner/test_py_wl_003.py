"""Tests for PY-WL-003: Existence-checking as structural gate."""

from __future__ import annotations

from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_003 import RulePyWl003

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl003:
    """Parse source inside a function and run PY-WL-003."""
    tree = parse_function_source(source)
    rule = RulePyWl003(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_with_boundary(
    source: str,
    *,
    qualname: str = "target",
    transition: str = "shape_validation",
    taint: TaintState = TaintState.EXTERNAL_RAW,
    overlay_scope: str = "/project/src/api",
    file_path: str = "/project/src/api/handler.py",
) -> RulePyWl003:
    """Parse source inside a function, attach boundary context, run the rule."""
    tree = parse_function_source(source, name=qualname)
    rule = RulePyWl003(file_path=file_path)
    rule.set_context(
        ScanContext(
            file_path=file_path,
            function_level_taint_map={qualname: taint},
            boundaries=(
                BoundaryEntry(
                    function=qualname,
                    transition=transition,
                    overlay_scope=overlay_scope,
                ),
            ),
        )
    )
    rule.visit(tree)
    return rule


def _run_rule_match(source: str) -> RulePyWl003:
    """Parse source with match/case (must be module-level function)."""
    tree = parse_module_source(source)
    rule = RulePyWl003(file_path="test.py")
    rule.visit(tree)
    return rule


# ── Positive: `in` operator ─────────────────────────────────────


class TestInOperator:
    """``in`` operator fires PY-WL-003."""

    def test_key_in_dict_fires(self) -> None:
        rule = _run_rule('"key" in d\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003
        assert rule.findings[0].severity == Severity.ERROR
        assert "'in' operator" in rule.findings[0].message

    def test_key_in_dict_keys_fires(self) -> None:
        rule = _run_rule("key in d.keys()\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003

    def test_not_in_fires(self) -> None:
        """``not in`` is still an existence check."""
        rule = _run_rule('"key" not in d\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003
        assert "'in' operator" in rule.findings[0].message


# ── Positive: hasattr() ─────────────────────────────────────────


class TestHasattr:
    """``hasattr()`` fires PY-WL-003."""

    def test_hasattr_string_attr_fires(self) -> None:
        rule = _run_rule('hasattr(obj, "name")\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003
        assert "hasattr()" in rule.findings[0].message

    def test_hasattr_variable_attr_fires(self) -> None:
        rule = _run_rule("hasattr(obj, attr_var)\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003


# ── Positive: match/case ────────────────────────────────────────


class TestMatchCase:
    """Structural pattern matching fires PY-WL-003."""

    def test_match_mapping_fires(self) -> None:
        source = '''\
        def target():
            match d:
                case {"key": value}:
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003
        assert "mapping" in rule.findings[0].message

    def test_match_class_fires(self) -> None:
        source = '''\
        def target():
            match obj:
                case MyClass(x=1):
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003
        assert "class" in rule.findings[0].message


# ── Positive: multiple patterns / async ─────────────────────────


class TestMultipleAndAsync:
    """Multiple patterns and async functions."""

    def test_multiple_patterns_in_same_function(self) -> None:
        rule = _run_rule('''\
            "key" in d
            hasattr(obj, "name")
        ''')

        assert len(rule.findings) == 2

    def test_in_async_function(self) -> None:
        source = '''\
        async def target():
            "key" in d
            hasattr(obj, "name")
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 2


# ── Negative: should NOT fire ───────────────────────────────────


class TestNoFalsePositives:
    """Patterns that should NOT fire PY-WL-003."""

    def test_getattr_with_default_silent(self) -> None:
        """getattr() is NOT detected by this rule."""
        rule = _run_rule('getattr(obj, "name", default)\n')

        assert len(rule.findings) == 0

    def test_no_existence_checks_silent(self) -> None:
        rule = _run_rule("x = 1\n")

        assert len(rule.findings) == 0

    def test_regular_comparison_silent(self) -> None:
        """``x == y`` is not an existence check."""
        rule = _run_rule("x == y\n")

        assert len(rule.findings) == 0

    def test_match_value_silent(self) -> None:
        """MatchValue (``case 42:``) is NOT an existence check."""
        source = '''\
        def target():
            match x:
                case 42:
                    pass
                case "hello":
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 0

    def test_match_sequence_silent(self) -> None:
        """MatchSequence (``case [a, b]:``) is NOT an existence check."""
        source = '''\
        def target():
            match x:
                case [a, b]:
                    pass
                case [1, 2, 3]:
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 0

    def test_match_star_silent(self) -> None:
        """MatchStar (``case [first, *rest]:``) is NOT dynamic dispatch."""
        source = '''\
        def target():
            match x:
                case [first, *rest]:
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 0

    def test_match_or_silent(self) -> None:
        """MatchOr (``case 1 | 2 | 3:``) is NOT dynamic dispatch."""
        source = '''\
        def target():
            match x:
                case 1 | 2 | 3:
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 0

    def test_match_as_wildcard_silent(self) -> None:
        """MatchAs / wildcard (``case _:``) is NOT dynamic dispatch."""
        source = '''\
        def target():
            match x:
                case _ as y:
                    pass
                case _:
                    pass
        '''
        rule = _run_rule_match(source)

        assert len(rule.findings) == 0


class TestDeclaredValidationBoundarySuppression:
    """Shape and combined validators suppress PY-WL-003 inside the body."""

    def test_shape_validation_boundary_silent(self) -> None:
        rule = _run_rule_with_boundary('"key" in d\n')

        assert len(rule.findings) == 0

    def test_validates_external_boundary_silent(self) -> None:
        rule = _run_rule_with_boundary(
            '"key" in d\n',
            transition="validates_external",
        )

        assert len(rule.findings) == 0

    def test_boundary_outside_overlay_scope_does_not_suppress(self) -> None:
        rule = _run_rule_with_boundary(
            '"key" in d\n',
            overlay_scope="/project/src/other",
            file_path="/project/src/api/handler.py",
        )

        assert len(rule.findings) == 1

    def test_boundary_with_matching_overlay_scope_suppresses(self) -> None:
        rule = _run_rule_with_boundary(
            '"key" in d\n',
            overlay_scope="/project/src/api",
            file_path="/project/src/api/handler.py",
        )

        assert len(rule.findings) == 0

    def test_combined_validation_boundary_silent(self) -> None:
        rule = _run_rule_with_boundary(
            '"key" in d\n',
            transition="combined_validation",
        )

        assert len(rule.findings) == 0

    def test_other_boundary_transition_still_fires(self) -> None:
        rule = _run_rule_with_boundary(
            '"key" in d\n',
            transition="construction",
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_003
