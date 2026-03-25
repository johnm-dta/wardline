"""Tests for split DECORATOR_TAINT_MAP: body eval vs return taint.

Verifies that assign_function_taints returns a 3-tuple
(body_taint_map, return_taint_map, taint_sources) with correct taint
values for each decorator.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.context import WardlineAnnotation
from wardline.scanner.taint.function_level import assign_function_taints

# ── Expected body eval taints (INPUT tier) ─────────────────────

BODY_EVAL_EXPECTED: dict[str, TaintState] = {
    "validates_shape": TaintState.EXTERNAL_RAW,
    "validates_external": TaintState.EXTERNAL_RAW,
    "validates_semantic": TaintState.SHAPE_VALIDATED,
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
    "external_boundary": TaintState.EXTERNAL_RAW,
}

# ── Expected return taints (OUTPUT tier) ───────────────────────

RETURN_EXPECTED: dict[str, TaintState] = {
    "validates_shape": TaintState.SHAPE_VALIDATED,
    "validates_external": TaintState.PIPELINE,
    "validates_semantic": TaintState.PIPELINE,
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
    "external_boundary": TaintState.EXTERNAL_RAW,
}


def _make_decorated_function(decorator_name: str) -> tuple[ast.Module, dict]:
    """Build a minimal AST and annotations dict for a decorated function."""
    source = textwrap.dedent(f"""\
        @{decorator_name}
        def my_func():
            pass
    """)
    tree = ast.parse(source)
    file_path = "test.py"
    annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {
        (file_path, "my_func"): [
            WardlineAnnotation(
                canonical_name=decorator_name,
                group=7,
                attrs={},
            )
        ]
    }
    return tree, annotations


@pytest.mark.parametrize(
    "decorator_name,expected_body_taint",
    list(BODY_EVAL_EXPECTED.items()),
    ids=list(BODY_EVAL_EXPECTED.keys()),
)
def test_body_eval_taint(
    decorator_name: str, expected_body_taint: TaintState
) -> None:
    """Body eval taint uses INPUT tier for each decorator."""
    tree, annotations = _make_decorated_function(decorator_name)
    body_taint_map, _return_taint_map, _taint_sources, _conflicts = assign_function_taints(
        tree, "test.py", annotations
    )
    assert body_taint_map["my_func"] == expected_body_taint


@pytest.mark.parametrize(
    "decorator_name,expected_return_taint",
    list(RETURN_EXPECTED.items()),
    ids=list(RETURN_EXPECTED.keys()),
)
def test_return_taint(
    decorator_name: str, expected_return_taint: TaintState
) -> None:
    """Return taint uses OUTPUT tier for each decorator."""
    tree, annotations = _make_decorated_function(decorator_name)
    _body_taint_map, return_taint_map, _taint_sources, _conflicts = assign_function_taints(
        tree, "test.py", annotations
    )
    assert return_taint_map["my_func"] == expected_return_taint
