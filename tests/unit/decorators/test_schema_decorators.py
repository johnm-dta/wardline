"""Tests for Group 5 schema decorators."""

from __future__ import annotations

from wardline.decorators.schema import all_fields_mapped, output_schema


class TestAllFieldsMapped:
    """@all_fields_mapped decorator behaviour."""

    def test_sets_all_fields_mapped_attr(self) -> None:
        @all_fields_mapped
        def f() -> int:
            return 1

        assert f._wardline_all_fields_mapped is True  # type: ignore[attr-defined]

    def test_sets_group_5(self) -> None:
        @all_fields_mapped
        def f() -> int:
            return 1

        assert 5 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @all_fields_mapped
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @all_fields_mapped
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestOutputSchema:
    """@output_schema decorator behaviour."""

    def test_sets_output_schema_attr(self) -> None:
        @output_schema
        def f() -> int:
            return 1

        assert f._wardline_output_schema is True  # type: ignore[attr-defined]

    def test_sets_group_5(self) -> None:
        @output_schema
        def f() -> int:
            return 1

        assert 5 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @output_schema
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @output_schema
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
