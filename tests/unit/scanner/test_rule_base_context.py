"""Tests for RuleBase context integration: set_context, taint lookup, scope tracking."""

from __future__ import annotations

import ast
from types import MappingProxyType

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.base import RuleBase


class _StubRule(RuleBase):
    """Minimal concrete rule for testing RuleBase behaviour."""

    RULE_ID = RuleId.PY_WL_001

    def __init__(self) -> None:
        super().__init__()
        self.visited_qualnames: list[str] = []

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.visited_qualnames.append(self._current_qualname)


class TestSetContext:
    """set_context() stores/clears ScanContext and syncs _file_path."""

    def test_context_initially_none(self) -> None:
        rule = _StubRule()
        assert rule._context is None

    def test_stores_context(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(file_path="a.py", function_level_taint_map={})
        rule.set_context(ctx)
        assert rule._context is ctx
        assert rule._file_path == "a.py"

    def test_replaces_previous_context(self) -> None:
        rule = _StubRule()
        ctx1 = ScanContext(file_path="a.py", function_level_taint_map={})
        ctx2 = ScanContext(file_path="b.py", function_level_taint_map={})
        rule.set_context(ctx1)
        rule.set_context(ctx2)
        assert rule._context is ctx2
        assert rule._file_path == "b.py"

    def test_accepts_none_to_clear(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(file_path="a.py", function_level_taint_map={})
        rule.set_context(ctx)
        rule.set_context(None)
        assert rule._context is None
        assert rule._file_path == ""


class TestGetFunctionTaint:
    """_get_function_taint() looks up qualname in context's taint map."""

    def test_returns_taint_for_known_function(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="a.py",
            function_level_taint_map={"my_func": TaintState.EXTERNAL_RAW},
        )
        rule.set_context(ctx)
        assert rule._get_function_taint("my_func") == TaintState.EXTERNAL_RAW

    def test_returns_unknown_raw_for_unknown_function(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(file_path="a.py", function_level_taint_map={})
        rule.set_context(ctx)
        assert rule._get_function_taint("no_such") == TaintState.UNKNOWN_RAW

    def test_returns_unknown_raw_when_no_context(self) -> None:
        rule = _StubRule()
        assert rule._get_function_taint("anything") == TaintState.UNKNOWN_RAW

    def test_dotted_qualname_lookup(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="a.py",
            function_level_taint_map={"MyClass.my_method": TaintState.PIPELINE},
        )
        rule.set_context(ctx)
        assert rule._get_function_taint("MyClass.my_method") == TaintState.PIPELINE


class TestScopeTracking:
    """_dispatch builds qualname from scope stack before calling visit_function."""

    def test_top_level_function_qualname(self) -> None:
        rule = _StubRule()
        source = "def foo(): pass"
        tree = ast.parse(source)
        rule.visit(tree)
        assert rule.visited_qualnames == ["foo"]

    def test_class_method_qualname(self) -> None:
        rule = _StubRule()
        source = """\
class MyClass:
    def bar(self): pass
"""
        tree = ast.parse(source)
        rule.visit(tree)
        assert rule.visited_qualnames == ["MyClass.bar"]
