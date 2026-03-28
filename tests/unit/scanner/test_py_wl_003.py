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
        assert rule.findings[0].severity == Severity.SUPPRESS
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

    def test_value_membership_in_list_silent(self) -> None:
        """``x in [1, 2, 3]`` is value membership, not existence-check gating."""
        rule = _run_rule("x in [1, 2, 3]\n")

        assert len(rule.findings) == 0

    def test_value_membership_in_values_view_silent(self) -> None:
        """``x in data.values()`` is value membership, not key existence."""
        rule = _run_rule("x in data.values()\n")

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


# ── RC1: Closure frozenset params suppress inner `in` ──────────


class TestClosureFrozensetParams:
    """Frozenset params from outer function should suppress `in` in nested defs."""

    def test_frozenset_closure_param_silent(self) -> None:
        """node.id in names where names: frozenset[str] is outer param."""
        rule = _run_rule_match(
            '''\
            def outer(*, names: frozenset[str]) -> bool:
                def _walk(node):
                    if node.id in names:
                        return True
                return _walk(root)
            '''
        )
        assert len(rule.findings) == 0

    def test_non_frozenset_closure_param_still_fires(self) -> None:
        """node.id in data where data: dict[str, str] is outer param."""
        rule = _run_rule_match(
            '''\
            def outer(*, data: dict[str, str]) -> bool:
                def _walk(node):
                    if node.id in data:
                        return True
                return _walk(root)
            '''
        )
        assert len(rule.findings) == 1


# ── RC2: Variable LHS substring suppression ────────────────────


class TestVariableLhsSubstring:
    """Variable `in` string-named comparator should be suppressed."""

    def test_variable_in_lowered_string_silent(self) -> None:
        """hint in lowered where lowered = name.lower()."""
        rule = _run_rule(
            'lowered = name.lower()\n'
            'for hint in hints:\n'
            '    if hint in lowered:\n'
            '        return True\n'
        )
        assert len(rule.findings) == 0

    def test_variable_in_receiver_lower_silent(self) -> None:
        """sub in receiver_lower where receiver_lower = receiver.lower()."""
        rule = _run_rule(
            'receiver_lower = receiver.lower()\n'
            'if sub in receiver_lower:\n'
            '    return True\n'
        )
        assert len(rule.findings) == 0

    def test_variable_in_dict_still_fires(self) -> None:
        """Variable in non-string-named comparator still fires."""
        rule = _run_rule(
            'if key in data:\n'
            '    return True\n'
        )
        assert len(rule.findings) == 1


# ── RC3: obj.attr suppression generalised beyond self ──────────


class TestObjAttrSuppression:
    """Membership test against any local.frozenset_attr should suppress."""

    def test_false_in_analysis_continue_states_silent(self) -> None:
        """False in analysis.continue_states — analysis is a local."""
        rule = _run_rule(
            'analysis = self._analyze_block(body)\n'
            'if False in analysis.continue_states:\n'
            '    nodes.append(node)\n'
        )
        assert len(rule.findings) == 0

    def test_self_attr_still_silent(self) -> None:
        """Existing: x in self.names is already suppressed."""
        rule = _run_rule(
            'if x in self.names:\n'
            '    return True\n'
        )
        assert len(rule.findings) == 0


# ── RC4: Intermediate variable from set-returning call ─────────


class TestIntermediateSetVariable:
    """sccs = compute_sccs(g); for scc in sccs — scc should be known set."""

    def test_for_loop_over_intermediate_scc_call_silent(self) -> None:
        """caller in scc where scc comes from for scc in sccs, sccs = compute_sccs(g)."""
        rule = _run_rule(
            'sccs = compute_sccs(graph)\n'
            'for scc in sccs:\n'
            '    for caller in callers:\n'
            '        if caller in scc:\n'
            '            worklist.add(caller)\n'
        )
        assert len(rule.findings) == 0

    def test_for_loop_over_dict_values_still_fires(self) -> None:
        """caller in chunk where chunk is not from a set-yielding call."""
        rule = _run_rule(
            'chunks = partition(items)\n'
            'for chunk in chunks:\n'
            '    if caller in chunk:\n'
            '        found = True\n'
        )
        assert len(rule.findings) == 1
