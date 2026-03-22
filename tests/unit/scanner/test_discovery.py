"""Tests for decorator discovery — import table, TYPE_CHECKING, annotations."""

from __future__ import annotations

import ast
import textwrap

from wardline.scanner.discovery import (
    _build_import_table,
    _collect_type_checking_lines,
    discover_annotations,
)


def _parse(source: str) -> ast.Module:
    """Parse dedented source into an AST module."""
    return ast.parse(textwrap.dedent(source))


# ── TYPE_CHECKING block detection ────────────────────────────────


class TestTypeCheckingDetection:
    """Phase 1: identify lines inside ``if TYPE_CHECKING:`` blocks."""

    def test_direct_type_checking_import(self) -> None:
        tree = _parse("""\
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from wardline import external_boundary
            def foo(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)

        # The import inside the if block should be in tc_lines
        # Line 3 is the from-import inside the if block
        assert len(tc_lines) > 0
        # Line 4 (def foo) should NOT be in tc_lines
        # Find the FunctionDef node's line number
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "foo":
                assert node.lineno not in tc_lines

    def test_qualified_type_checking_import(self) -> None:
        tree = _parse("""\
            import typing
            if typing.TYPE_CHECKING:
                from wardline import external_boundary
            def bar(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)

        assert len(tc_lines) > 0
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "bar":
                assert node.lineno not in tc_lines

    def test_no_type_checking_block(self) -> None:
        tree = _parse("""\
            from wardline import external_boundary
            def foo(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)
        assert len(tc_lines) == 0

    def test_normal_if_not_detected(self) -> None:
        """An ``if`` block that isn't TYPE_CHECKING should not be filtered."""
        tree = _parse("""\
            DEBUG = True
            if DEBUG:
                from wardline import external_boundary
            def foo(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)
        assert len(tc_lines) == 0


# ── Import table construction ────────────────────────────────────


class TestImportTable:
    """Phase 2: build local name → canonical name mapping."""

    def test_direct_from_import(self) -> None:
        """``from wardline import external_boundary``"""
        tree = _parse("""\
            from wardline import external_boundary
        """)
        table = _build_import_table(tree, frozenset())

        assert table["external_boundary"] == "external_boundary"

    def test_submodule_from_import(self) -> None:
        """``from wardline.decorators.authority import external_boundary``"""
        tree = _parse("""\
            from wardline.decorators.authority import external_boundary
        """)
        table = _build_import_table(tree, frozenset())

        assert table["external_boundary"] == "external_boundary"

    def test_qualified_import(self) -> None:
        """``import wardline`` registers as qualified source."""
        tree = _parse("""\
            import wardline
        """)
        table = _build_import_table(tree, frozenset())

        assert "__qualified__:wardline" in table

    def test_non_wardline_import_ignored(self) -> None:
        """Non-wardline imports are not in the table."""
        tree = _parse("""\
            from os.path import join
            import json
        """)
        table = _build_import_table(tree, frozenset())

        assert len(table) == 0

    def test_unknown_wardline_name_ignored(self) -> None:
        """Importing a name from wardline that's not in the registry."""
        tree = _parse("""\
            from wardline import some_unknown_thing
        """)
        table = _build_import_table(tree, frozenset())

        assert "some_unknown_thing" not in table

    def test_type_checking_import_excluded(self) -> None:
        """Imports inside TYPE_CHECKING blocks are filtered out."""
        tree = _parse("""\
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from wardline import external_boundary
            from wardline import validates_shape
        """)
        tc_lines = _collect_type_checking_lines(tree)
        table = _build_import_table(tree, tc_lines)

        assert "external_boundary" not in table
        assert table["validates_shape"] == "validates_shape"

    def test_qualified_type_checking_excluded(self) -> None:
        """Qualified TYPE_CHECKING block excludes imports."""
        tree = _parse("""\
            import typing
            if typing.TYPE_CHECKING:
                from wardline import external_boundary
            from wardline import audit_critical
        """)
        tc_lines = _collect_type_checking_lines(tree)
        table = _build_import_table(tree, tc_lines)

        assert "external_boundary" not in table
        assert table["audit_critical"] == "audit_critical"

    def test_multiple_decorators_imported(self) -> None:
        """Multiple decorators from one import statement."""
        tree = _parse("""\
            from wardline import external_boundary, validates_shape
        """)
        table = _build_import_table(tree, frozenset())

        assert table["external_boundary"] == "external_boundary"
        assert table["validates_shape"] == "validates_shape"


# ── Annotation map (end-to-end discovery) ────────────────────────


class TestDiscoverAnnotations:
    """Phase 3: full discovery pipeline — imports → decorators → annotations."""

    def test_direct_import_decorator(self) -> None:
        """``from wardline import X`` + ``@X`` on a function."""
        tree = _parse("""\
            from wardline import external_boundary
            @external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        annotations = result[key]
        assert len(annotations) == 1
        ann = next(iter(annotations))
        assert ann.canonical_name == "external_boundary"
        assert ann.group == 1

    def test_submodule_import_decorator(self) -> None:
        """``from wardline.decorators.authority import X`` + ``@X``."""
        tree = _parse("""\
            from wardline.decorators.authority import validates_shape
            @validates_shape
            def validate(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "validate")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "validates_shape"

    def test_qualified_import_decorator(self) -> None:
        """``import wardline`` + ``@wardline.external_boundary``."""
        tree = _parse("""\
            import wardline
            @wardline.external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_type_checking_import_not_discovered(self) -> None:
        """Decorators imported under TYPE_CHECKING are invisible."""
        tree = _parse("""\
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from wardline import external_boundary
            @external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        # external_boundary is not in the import table, so
        # the decorator is not resolved
        assert ("test.py", "handler") not in result

    def test_qualified_type_checking_not_discovered(self) -> None:
        """Qualified TYPE_CHECKING import also invisible."""
        tree = _parse("""\
            import typing
            if typing.TYPE_CHECKING:
                from wardline import external_boundary
            @external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        assert ("test.py", "handler") not in result

    def test_undecorated_function_not_in_map(self) -> None:
        """Functions without wardline decorators don't appear."""
        tree = _parse("""\
            from wardline import external_boundary
            def plain(): pass
        """)
        result = discover_annotations(tree, "test.py")

        assert ("test.py", "plain") not in result

    def test_async_function_discovered(self) -> None:
        """Async functions are discovered the same as sync."""
        tree = _parse("""\
            from wardline import external_boundary
            @external_boundary
            async def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result

    def test_method_in_class(self) -> None:
        """Decorated method gets qualname with class prefix."""
        tree = _parse("""\
            from wardline import external_boundary
            class MyService:
                @external_boundary
                def handle(self): pass
        """)
        result = discover_annotations(tree, "svc.py")

        key = ("svc.py", "MyService.handle")
        assert key in result

    def test_multiple_decorators_on_one_function(self) -> None:
        """Function with two wardline decorators gets both annotations."""
        tree = _parse("""\
            from wardline import external_boundary, audit_critical
            @external_boundary
            @audit_critical
            def critical_handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "critical_handler")
        assert key in result
        names = {a.canonical_name for a in result[key]}  # noqa: C401
        assert names == {"external_boundary", "audit_critical"}

    def test_non_wardline_decorator_ignored(self) -> None:
        """Non-wardline decorators don't pollute the annotation map."""
        tree = _parse("""\
            from wardline import external_boundary
            from functools import lru_cache
            @lru_cache
            @external_boundary
            def cached_handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "cached_handler")
        assert key in result
        # Only the wardline decorator should be in annotations
        assert len(result[key]) == 1
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_decorator_with_call_syntax(self) -> None:
        """``@external_boundary()`` (with parens) is resolved."""
        tree = _parse("""\
            from wardline import external_boundary
            @external_boundary()
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_empty_file(self) -> None:
        """Empty file produces empty annotation map."""
        tree = _parse("")
        result = discover_annotations(tree, "empty.py")

        assert result == {}
