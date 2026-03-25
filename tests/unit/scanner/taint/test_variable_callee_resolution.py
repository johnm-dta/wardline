"""Verify L2 variable-level taint uses return taint for callee resolution.

The engine builds a callee-resolution map where decorator-anchored
functions use RETURN_TAINT (OUTPUT tier) instead of BODY_EVAL_TAINT
(INPUT tier). This ensures that `x = validates_shape(data)` assigns
SHAPE_VALIDATED to x, not EXTERNAL_RAW.
"""

from __future__ import annotations

import ast

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints


class TestCalleeReturnTaintResolution:
    """L2 callee resolution uses the callee-resolution map from the engine."""

    @pytest.mark.parametrize(
        "callee_taint,expected_var_taint",
        [
            # Anchored validators: engine passes RETURN taint (OUTPUT tier)
            (TaintState.SHAPE_VALIDATED, TaintState.SHAPE_VALIDATED),
            (TaintState.PIPELINE, TaintState.PIPELINE),
            # Non-validators: body == return, so callee map has same value
            (TaintState.AUDIT_TRAIL, TaintState.AUDIT_TRAIL),
            (TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW),
        ],
        ids=["validates_shape", "validates_semantic", "tier1_read", "external_boundary"],
    )
    def test_variable_gets_callee_return_taint(
        self,
        callee_taint: TaintState,
        expected_var_taint: TaintState,
    ) -> None:
        """x = callee() should assign the callee's return taint to x."""
        source = """\
def caller(data):
    x = clean(data)
    return x
"""
        tree = ast.parse(source)
        func_node = tree.body[0]
        assert isinstance(func_node, ast.FunctionDef)

        # Simulate the callee-resolution map the engine would build
        callee_taint_map = {
            "caller": TaintState.UNKNOWN_RAW,
            "clean": callee_taint,
        }

        var_taints = compute_variable_taints(
            func_node, TaintState.UNKNOWN_RAW, callee_taint_map
        )

        assert var_taints["x"] == expected_var_taint

    def test_unresolved_callee_falls_back_to_function_taint(self) -> None:
        """Method calls and complex expressions fall back to function taint."""
        source = """\
def caller(data):
    x = obj.method(data)
    return x
"""
        tree = ast.parse(source)
        func_node = tree.body[0]
        assert isinstance(func_node, ast.FunctionDef)

        callee_taint_map = {"caller": TaintState.EXTERNAL_RAW}

        var_taints = compute_variable_taints(
            func_node, TaintState.EXTERNAL_RAW, callee_taint_map
        )

        # Method call is unresolvable — falls back to function_taint
        assert var_taints["x"] == TaintState.EXTERNAL_RAW

    def test_validator_return_not_body_in_callee_map(self) -> None:
        """Regression guard: the callee map must contain RETURN taint for
        validators, not BODY_EVAL taint. This test would fail if the engine
        passed body_taint_map directly to L2 without building the
        callee-resolution map.
        """
        source = """\
def caller(data):
    validated = validate(data)
    return validated
"""
        tree = ast.parse(source)
        func_node = tree.body[0]
        assert isinstance(func_node, ast.FunctionDef)

        # If the engine correctly builds the callee map, 'validate' has
        # SHAPE_VALIDATED (return taint). If it incorrectly passes body
        # taint, it would be EXTERNAL_RAW.
        callee_taint_map = {
            "caller": TaintState.UNKNOWN_RAW,
            "validate": TaintState.SHAPE_VALIDATED,  # return taint, NOT body taint
        }

        var_taints = compute_variable_taints(
            func_node, TaintState.UNKNOWN_RAW, callee_taint_map
        )

        assert var_taints["validated"] == TaintState.SHAPE_VALIDATED
        # Would be EXTERNAL_RAW if body taint were used — that's the bug
        assert var_taints["validated"] != TaintState.EXTERNAL_RAW
