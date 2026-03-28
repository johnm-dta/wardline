"""Tests for Level 2 taint — per-variable taint tracking within function bodies."""

from __future__ import annotations

import ast
import textwrap

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints


def _parse_func(source: str) -> ast.FunctionDef:
    """Parse source and return the first function node."""
    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    raise ValueError("No function found in source")


# ── Simple assignment ────────────────────────────────────────────


class TestSimpleAssignment:
    def test_literal_gets_audit_trail(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_string_literal_gets_audit_trail(self) -> None:
        func = _parse_func("""
            def f():
                x = "hello"
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_unknown_expr_gets_function_taint(self) -> None:
        func = _parse_func("""
            def f():
                x = some_global.attr
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_variable_reference_propagates(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                y = x
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL
        assert result["y"] == TaintState.INTEGRAL

    def test_reassignment_overwrites(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                x = some_unknown
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW


# ── Binary operations ────────────────────────────────────────────


class TestBinaryOps:
    def test_binop_joins_operands(self) -> None:
        func = _parse_func("""
            def f():
                a = 42
                b = unknown_thing
                c = a + b
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["a"] == TaintState.INTEGRAL
        assert result["b"] == TaintState.UNKNOWN_RAW
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["c"] == TaintState.MIXED_RAW


# ── Function calls ───────────────────────────────────────────────


class TestFunctionCalls:
    def test_known_callee_taint(self) -> None:
        func = _parse_func("""
            def f():
                x = validate(data)
        """)
        taint_map = {"validate": TaintState.GUARDED}
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, taint_map)
        assert result["x"] == TaintState.GUARDED

    def test_unknown_callee_gets_function_taint(self) -> None:
        func = _parse_func("""
            def f():
                x = unknown_func(data)
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_method_call_gets_function_taint(self) -> None:
        """Method calls (obj.method()) are not in the taint_map, so they
        get the function's own L1 taint."""
        func = _parse_func("""
            def f():
                x = obj.method()
        """)
        result = compute_variable_taints(func, TaintState.ASSURED, {})
        assert result["x"] == TaintState.ASSURED


# ── Augmented assignment ─────────────────────────────────────────


class TestAugmentedAssignment:
    def test_augassign_joins_with_existing(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                x += unknown_thing
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_augassign_new_variable(self) -> None:
        """If variable wasn't previously assigned, treat existing as function taint."""
        func = _parse_func("""
            def f():
                x += 42
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # UNKNOWN_RAW join INTEGRAL = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW


# ── Tuple unpacking ──────────────────────────────────────────────


class TestTupleUnpacking:
    def test_tuple_unpack_literals(self) -> None:
        func = _parse_func("""
            def f():
                a, b = 1, 2
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["a"] == TaintState.INTEGRAL
        assert result["b"] == TaintState.INTEGRAL

    def test_tuple_unpack_from_call(self) -> None:
        """When RHS is not a tuple, all targets get the RHS taint."""
        func = _parse_func("""
            def f():
                a, b = some_func()
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["a"] == TaintState.EXTERNAL_RAW
        assert result["b"] == TaintState.EXTERNAL_RAW

    def test_tuple_unpack_mixed(self) -> None:
        func = _parse_func("""
            def f():
                a, b = 42, unknown
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["a"] == TaintState.INTEGRAL
        assert result["b"] == TaintState.EXTERNAL_RAW


# ── For-loop target ──────────────────────────────────────────────


class TestForLoop:
    def test_for_loop_target_gets_iterable_taint(self) -> None:
        func = _parse_func("""
            def f():
                for x in some_iterable:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_for_loop_over_literal_list(self) -> None:
        func = _parse_func("""
            def f():
                for x in [1, 2, 3]:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL


# ── With-as ──────────────────────────────────────────────────────


class TestWithAs:
    def test_with_as_gets_expr_taint(self) -> None:
        func = _parse_func("""
            def f():
                with open("file.txt") as handle:
                    pass
        """)
        taint_map = {"open": TaintState.INTEGRAL}
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, taint_map)
        assert result["handle"] == TaintState.INTEGRAL

    def test_with_as_unknown_call(self) -> None:
        func = _parse_func("""
            def f():
                with something() as handle:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["handle"] == TaintState.EXTERNAL_RAW


# ── Exception handler ────────────────────────────────────────────


class TestExceptAs:
    def test_except_as_inherits_function_taint(self) -> None:
        """Exception objects inherit function taint — str(e) may contain attacker input."""
        func = _parse_func("""
            def f():
                try:
                    pass
                except ValueError as e:
                    pass
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["e"] == TaintState.EXTERNAL_RAW


# ── Walrus operator ──────────────────────────────────────────────


class TestWalrus:
    def test_walrus_assigns_taint(self) -> None:
        func = _parse_func("""
            def f():
                if (x := 42):
                    pass
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL

    def test_walrus_with_call(self) -> None:
        func = _parse_func("""
            def f():
                if (x := validate(data)):
                    pass
        """)
        taint_map = {"validate": TaintState.GUARDED}
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, taint_map)
        assert result["x"] == TaintState.GUARDED


# ── Control flow merges (if/else) ────────────────────────────────


class TestControlFlowMerge:
    def test_if_else_merges_variable_taint(self) -> None:
        func = _parse_func("""
            def f():
                if condition:
                    x = 42
                else:
                    x = unknown_thing
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_if_only_merges_with_pre_existing(self) -> None:
        """If there's no else, the if-branch merges with pre-existing taint."""
        func = _parse_func("""
            def f():
                x = 42
                if condition:
                    x = unknown_thing
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW


# ── Parameters get function taint ────────────────────────────────


class TestParameters:
    def test_parameters_get_function_taint(self) -> None:
        func = _parse_func("""
            def f(a, b, c=None):
                x = a
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["a"] == TaintState.EXTERNAL_RAW
        assert result["b"] == TaintState.EXTERNAL_RAW
        assert result["c"] == TaintState.EXTERNAL_RAW
        assert result["x"] == TaintState.EXTERNAL_RAW


# ── Async function ───────────────────────────────────────────────


class TestAsync:
    def test_async_function_works(self) -> None:
        func = _parse_func("""
            async def f():
                x = 42
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        assert result["x"] == TaintState.INTEGRAL


# ── Nested constructs ────────────────────────────────────────────


class TestNested:
    def test_variable_in_for_body(self) -> None:
        func = _parse_func("""
            def f():
                for item in items:
                    x = item
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["item"] == TaintState.EXTERNAL_RAW
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_variable_in_while_body(self) -> None:
        func = _parse_func("""
            def f():
                x = 42
                while True:
                    x = unknown
        """)
        result = compute_variable_taints(func, TaintState.UNKNOWN_RAW, {})
        # INTEGRAL join UNKNOWN_RAW = MIXED_RAW (while body merges with pre-loop)
        assert result["x"] == TaintState.MIXED_RAW


# ── Try/except branch merge ──────────────────────────────────────


class TestTryExceptBranchMerge:
    def test_try_except_branch_merge(self) -> None:
        """try/except should join branches, not sequential overwrite."""
        func = _parse_func("""
            def f():
                x = unknown_thing
                try:
                    x = 42
                except:
                    x = "fallback"
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # Both branches assign INTEGRAL; join should still be INTEGRAL
        assert result["x"] == TaintState.INTEGRAL

    def test_try_except_divergent_branches(self) -> None:
        """try body and handler with different taints should join."""
        func = _parse_func("""
            def f():
                x = "safe"
                try:
                    x = unknown_thing
                except:
                    x = "fallback"
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        # try branch: EXTERNAL_RAW, except branch: INTEGRAL → MIXED_RAW
        assert result["x"] == TaintState.MIXED_RAW

    def test_try_except_handler_name_inherits_function_taint(self) -> None:
        """Exception variable in handler inherits function taint (conservative)."""
        func = _parse_func("""
            def f():
                try:
                    pass
                except ValueError as e:
                    x = e
        """)
        result = compute_variable_taints(func, TaintState.EXTERNAL_RAW, {})
        assert result["e"] == TaintState.EXTERNAL_RAW
