"""Tests for Group 7 safety decorators."""

from __future__ import annotations

from wardline.decorators.safety import fail_safe, fail_secure, graceful_degradation


class TestFailSafe:
    """@fail_safe decorator behaviour."""

    def test_sets_fail_safe_attr(self) -> None:
        @fail_safe
        def f() -> int:
            return 1

        assert f._wardline_fail_safe is True  # type: ignore[attr-defined]

    def test_sets_group_7(self) -> None:
        @fail_safe
        def f() -> int:
            return 1

        assert 7 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @fail_safe
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @fail_safe
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestFailSecure:
    """@fail_secure decorator behaviour."""

    def test_sets_fail_secure_attr(self) -> None:
        @fail_secure
        def f() -> int:
            return 1

        assert f._wardline_fail_secure is True  # type: ignore[attr-defined]

    def test_sets_group_7(self) -> None:
        @fail_secure
        def f() -> int:
            return 1

        assert 7 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @fail_secure
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @fail_secure
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestGracefulDegradation:
    """@graceful_degradation decorator behaviour."""

    def test_sets_graceful_degradation_attr(self) -> None:
        @graceful_degradation
        def f() -> int:
            return 1

        assert f._wardline_graceful_degradation is True  # type: ignore[attr-defined]

    def test_sets_group_7(self) -> None:
        @graceful_degradation
        def f() -> int:
            return 1

        assert 7 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @graceful_degradation
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @graceful_degradation
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
