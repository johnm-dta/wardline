"""Tests for Group 9-10 operations decorators."""

from __future__ import annotations

import pytest

from wardline.decorators.operations import (
    atomic,
    compensatable,
    emits_or_explains,
    exception_boundary,
    fail_closed,
    fail_open,
    idempotent,
    must_propagate,
    preserve_cause,
)


class TestIdempotent:
    """@idempotent decorator behaviour."""

    def test_sets_idempotent_attr(self) -> None:
        @idempotent
        def f() -> int:
            return 1

        assert f._wardline_idempotent is True  # type: ignore[attr-defined]

    def test_sets_group_9(self) -> None:
        @idempotent
        def f() -> int:
            return 1

        assert 9 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @idempotent
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @idempotent
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestAtomic:
    """@atomic decorator behaviour."""

    def test_sets_atomic_attr(self) -> None:
        @atomic
        def f() -> int:
            return 1

        assert f._wardline_atomic is True  # type: ignore[attr-defined]

    def test_sets_group_9(self) -> None:
        @atomic
        def f() -> int:
            return 1

        assert 9 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @atomic
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @atomic
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestCompensatable:
    """@compensatable decorator behaviour."""

    def test_sets_compensatable_attrs(self) -> None:
        def rollback(exc: Exception) -> None:
            del exc

        @compensatable(rollback=rollback)
        def f() -> int:
            return 1

        assert f._wardline_compensatable is True  # type: ignore[attr-defined]
        assert f._wardline_rollback is rollback  # type: ignore[attr-defined]

    def test_sets_group_9(self) -> None:
        def rollback(exc: Exception) -> None:
            del exc

        @compensatable(rollback=rollback)
        def f() -> int:
            return 1

        assert 9 in f._wardline_groups  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("decorator", "attr_name"),
    [
        (fail_closed, "_wardline_fail_closed"),
        (fail_open, "_wardline_fail_open"),
        (emits_or_explains, "_wardline_emits_or_explains"),
        (exception_boundary, "_wardline_exception_boundary"),
        (must_propagate, "_wardline_must_propagate"),
        (preserve_cause, "_wardline_preserve_cause"),
    ],
)
def test_group_10_failure_mode_decorators(
    decorator: object,
    attr_name: str,
) -> None:
    @decorator  # type: ignore[misc]
    def stub() -> int:
        return 42

    assert getattr(stub, attr_name) is True
    assert 10 in stub._wardline_groups  # type: ignore[attr-defined]
    assert stub() == 42
    assert stub.__name__ == "stub"
