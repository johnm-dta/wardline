"""Tests for wardline.scanner._scope — qualname resolution from AST."""

from __future__ import annotations

import ast

from wardline.scanner._scope import find_function_node


class TestFindFunctionNode:
    def test_top_level_function(self) -> None:
        tree = ast.parse("def foo():\n    pass\n")
        node = find_function_node(tree, "foo")
        assert node is not None
        assert node.name == "foo"

    def test_class_method(self) -> None:
        tree = ast.parse("class MyClass:\n    def handle(self):\n        pass\n")
        node = find_function_node(tree, "MyClass.handle")
        assert node is not None
        assert node.name == "handle"

    def test_nested_function(self) -> None:
        tree = ast.parse("def outer():\n    def inner():\n        pass\n")
        node = find_function_node(tree, "outer.inner")
        assert node is not None
        assert node.name == "inner"

    def test_async_function(self) -> None:
        tree = ast.parse("async def fetch():\n    pass\n")
        node = find_function_node(tree, "fetch")
        assert node is not None

    def test_nonexistent_returns_none(self) -> None:
        tree = ast.parse("def foo():\n    pass\n")
        assert find_function_node(tree, "bar") is None

    def test_class_not_found_returns_none(self) -> None:
        tree = ast.parse("class A:\n    def m(self):\n        pass\n")
        assert find_function_node(tree, "B.m") is None

    def test_deeply_nested(self) -> None:
        source = "class A:\n    class B:\n        def deep(self):\n            pass\n"
        tree = ast.parse(source)
        node = find_function_node(tree, "A.B.deep")
        assert node is not None
        assert node.name == "deep"
