"""Tests for Group 14 access decorators."""

from __future__ import annotations

from wardline.decorators.access import privileged_operation, requires_identity


class TestRequiresIdentity:
    """@requires_identity decorator behaviour."""

    def test_sets_requires_identity_attr(self) -> None:
        @requires_identity
        def f() -> int:
            return 1

        assert f._wardline_requires_identity is True  # type: ignore[attr-defined]

    def test_sets_group_14(self) -> None:
        @requires_identity
        def f() -> int:
            return 1

        assert 14 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @requires_identity
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @requires_identity
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestPrivilegedOperation:
    """@privileged_operation decorator behaviour."""

    def test_sets_privileged_operation_attr(self) -> None:
        @privileged_operation
        def f() -> int:
            return 1

        assert f._wardline_privileged_operation is True  # type: ignore[attr-defined]

    def test_sets_group_14(self) -> None:
        @privileged_operation
        def f() -> int:
            return 1

        assert 14 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @privileged_operation
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @privileged_operation
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
