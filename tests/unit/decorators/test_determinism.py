"""Tests for Group 11 determinism decorators."""

from __future__ import annotations

from wardline.decorators.determinism import deterministic, nondeterministic


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

        assert 11 in f._wardline_groups  # type: ignore[attr-defined]

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


class TestNondeterministic:
    """@nondeterministic decorator behaviour."""

    def test_sets_nondeterministic_attr(self) -> None:
        @nondeterministic
        def f() -> int:
            return 1

        assert f._wardline_nondeterministic is True  # type: ignore[attr-defined]

    def test_sets_group_11(self) -> None:
        @nondeterministic
        def f() -> int:
            return 1

        assert 11 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @nondeterministic
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @nondeterministic
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
