"""Tests for Group 12 determinism decorators."""

from __future__ import annotations

from wardline.decorators.determinism import deterministic, time_dependent


class TestDeterministic:
    """@deterministic decorator behaviour."""

    def test_sets_deterministic_attr(self) -> None:
        @deterministic
        def f() -> int:
            return 1

        assert f._wardline_deterministic is True  # type: ignore[attr-defined]

    def test_sets_group_11(self) -> None:
        @deterministic
        def f() -> int:
            return 1

        assert 12 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @deterministic
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @deterministic
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestTimeDependent:
    """@time_dependent decorator behaviour."""

    def test_sets_time_dependent_attr(self) -> None:
        @time_dependent
        def f() -> int:
            return 1

        assert f._wardline_time_dependent is True  # type: ignore[attr-defined]

    def test_sets_group_12(self) -> None:
        @time_dependent
        def f() -> int:
            return 1

        assert 12 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @time_dependent
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @time_dependent
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
