"""Tests for schema_default marker."""

from __future__ import annotations

from wardline.decorators.schema import schema_default


class TestSchemaDefault:
    """schema_default(expr) behaviour."""

    def test_returns_argument_unchanged(self) -> None:
        assert schema_default(42) == 42

    def test_returns_string_unchanged(self) -> None:
        assert schema_default("hello") == "hello"

    def test_returns_none_unchanged(self) -> None:
        assert schema_default(None) is None

    def test_returns_dict_unchanged(self) -> None:
        d = {"key": "value"}
        assert schema_default(d) is d

    def test_is_callable(self) -> None:
        assert callable(schema_default)
