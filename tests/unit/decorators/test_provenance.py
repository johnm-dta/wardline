"""Tests for Group 4 provenance decorators."""

from __future__ import annotations

from wardline.decorators.provenance import int_data


class TestIntData:
    """@int_data decorator behaviour."""

    def test_sets_int_data_attr(self) -> None:
        @int_data
        def f() -> int:
            return 1

        assert f._wardline_int_data is True  # type: ignore[attr-defined]

    def test_sets_group_4(self) -> None:
        @int_data
        def f() -> int:
            return 1

        assert 4 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @int_data
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @int_data
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
