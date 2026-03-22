"""Tests for wardline decorator factory."""

from __future__ import annotations

import asyncio
import inspect
import logging

import pytest

from wardline.core.taints import TaintState
from wardline.decorators._base import get_wardline_attrs, wardline_decorator
from wardline.decorators.authority import (
    audit_writer,
    authoritative_construction,
    tier1_read,
    validates_external,
    validates_semantic,
    validates_shape,
)
from wardline.decorators.authority import (
    external_boundary as eb_decorator,
)

# ---------------------------------------------------------------------------
# Helpers — real registry-based decorators
# ---------------------------------------------------------------------------

external_boundary = wardline_decorator(
    1,
    "external_boundary",
    _wardline_tier_source=TaintState.EXTERNAL_RAW,
)

audit_critical = wardline_decorator(
    2,
    "audit_critical",
    _wardline_audit_critical=True,
)


# ---------------------------------------------------------------------------
# TestDecoratorBasic
# ---------------------------------------------------------------------------


class TestDecoratorBasic:
    """Basic decorator factory behaviour."""

    def test_decorated_function_callable(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 42

        assert my_func() == 42

    def test_signature_preserved(self) -> None:
        @external_boundary
        def my_func() -> int:
            """My docstring."""
            return 1

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."

    def test_wardline_groups_set(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 1

        assert hasattr(my_func, "_wardline_groups")
        assert 1 in my_func._wardline_groups  # type: ignore[attr-defined]

    def test_semantic_attrs_set(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 1

        assert (
            my_func._wardline_tier_source  # type: ignore[attr-defined]
            is TaintState.EXTERNAL_RAW
        )


# ---------------------------------------------------------------------------
# TestRegistryEnforcement
# ---------------------------------------------------------------------------


class TestRegistryEnforcement:
    """Registry validation at decorator creation time."""

    def test_unknown_name_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown decorator 'nonexistent'"):
            wardline_decorator(1, "nonexistent")

    def test_unknown_attr_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown attribute"):
            wardline_decorator(
                1, "external_boundary", _wardline_bogus=True
            )

    def test_valid_decorator_succeeds(self) -> None:
        dec = wardline_decorator(
            1,
            "external_boundary",
            _wardline_tier_source=TaintState.EXTERNAL_RAW,
        )
        assert callable(dec)


# ---------------------------------------------------------------------------
# TestStacking
# ---------------------------------------------------------------------------


class TestStacking:
    """Multiple wardline decorators on the same function."""

    def test_stacking_groups_accumulate(self) -> None:
        @audit_critical
        @external_boundary
        def my_func() -> int:
            return 1

        groups = my_func._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups
        assert 2 in groups

    def test_stacking_attrs_merge(self) -> None:
        @audit_critical
        @external_boundary
        def my_func() -> int:
            return 1

        assert (
            my_func._wardline_tier_source  # type: ignore[attr-defined]
            is TaintState.EXTERNAL_RAW
        )
        assert my_func._wardline_audit_critical is True  # type: ignore[attr-defined]

    def test_copy_on_accumulate(self) -> None:
        """Inner decorator's _wardline_groups set is NOT mutated by outer."""

        @external_boundary
        def inner_func() -> int:
            return 1

        inner_groups = inner_func._wardline_groups  # type: ignore[attr-defined]
        inner_groups_copy = set(inner_groups)

        @audit_critical
        @external_boundary
        def stacked_func() -> int:
            return 1

        # The original inner_func's groups must not have been mutated
        assert inner_groups == inner_groups_copy


# ---------------------------------------------------------------------------
# TestWrappedChain
# ---------------------------------------------------------------------------


class TestWrappedChain:
    """__wrapped__ chain traversal via get_wardline_attrs."""

    def test_get_attrs_returns_attrs(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 1

        attrs = get_wardline_attrs(my_func)
        assert attrs is not None
        assert "_wardline_tier_source" in attrs
        assert attrs["_wardline_tier_source"] is TaintState.EXTERNAL_RAW

    def test_plain_func_returns_none(self) -> None:
        """Plain function with no wardline attrs returns None."""
        def plain_func() -> int:
            return 1

        result = get_wardline_attrs(plain_func)
        assert result is None

    def test_severed_chain_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Severed __wrapped__ chain logs WARNING and returns None."""
        import functools

        def inner() -> int:
            return 1

        @functools.wraps(inner)
        def wrapper(*args: object, **kwargs: object) -> int:
            return inner(*args, **kwargs)  # type: ignore[return-value]

        # wrapper has __wrapped__ pointing to inner, but neither
        # has _wardline_* attrs — this is the "severed chain" case
        with caplog.at_level(logging.WARNING):
            result = get_wardline_attrs(wrapper)

        assert result is None
        assert "Severed __wrapped__ chain" in caplog.text


# ---------------------------------------------------------------------------
# TestCallableTypes
# ---------------------------------------------------------------------------


class TestCallableTypes:
    """Decorator works on different callable types."""

    def test_works_on_regular_function(self) -> None:
        @external_boundary
        def my_func(x: int) -> int:
            return x + 1

        assert my_func(5) == 6

    def test_works_on_method(self) -> None:
        class MyClass:
            @external_boundary
            def my_method(self, x: int) -> int:
                return x + 1

        obj = MyClass()
        assert obj.my_method(5) == 6
        assert hasattr(MyClass.my_method, "_wardline_groups")

    def test_works_on_staticmethod(self) -> None:
        class MyClass:
            @external_boundary
            @staticmethod
            def my_static(x: int) -> int:
                return x + 1

        assert MyClass.my_static(5) == 6

    def test_works_on_classmethod(self) -> None:
        class MyClass:
            @external_boundary
            @classmethod
            def my_cls(cls, x: int) -> int:
                return x + 1

        assert MyClass.my_cls(5) == 6


# ---------------------------------------------------------------------------
# TestGroup1Decorators
# ---------------------------------------------------------------------------


class TestGroup1Decorators:
    """Group 1 (Authority Tier Flow) decorators from authority.py."""

    def test_external_boundary_group(self) -> None:
        @eb_decorator
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_external_boundary_attrs(self) -> None:
        @eb_decorator
        def f() -> int:
            return 1

        assert f._wardline_tier_source is TaintState.EXTERNAL_RAW  # type: ignore[attr-defined]

    def test_external_boundary_callable(self) -> None:
        @eb_decorator
        def f() -> int:
            return 42

        assert f() == 42

    def test_validates_shape_group(self) -> None:
        @validates_shape
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_validates_shape_attrs(self) -> None:
        @validates_shape
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.EXTERNAL_RAW, TaintState.SHAPE_VALIDATED)  # type: ignore[attr-defined]

    def test_validates_shape_callable(self) -> None:
        @validates_shape
        def f() -> int:
            return 42

        assert f() == 42

    def test_validates_semantic_group(self) -> None:
        @validates_semantic
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_validates_semantic_attrs(self) -> None:
        @validates_semantic
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.SHAPE_VALIDATED, TaintState.PIPELINE)  # type: ignore[attr-defined]

    def test_validates_semantic_callable(self) -> None:
        @validates_semantic
        def f() -> int:
            return 42

        assert f() == 42

    def test_validates_external_group(self) -> None:
        @validates_external
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_validates_external_attrs(self) -> None:
        @validates_external
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.EXTERNAL_RAW, TaintState.PIPELINE)  # type: ignore[attr-defined]

    def test_validates_external_callable(self) -> None:
        @validates_external
        def f() -> int:
            return 42

        assert f() == 42

    def test_tier1_read_group(self) -> None:
        @tier1_read
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_tier1_read_attrs(self) -> None:
        @tier1_read
        def f() -> int:
            return 1

        assert f._wardline_tier_source is TaintState.AUDIT_TRAIL  # type: ignore[attr-defined]

    def test_tier1_read_callable(self) -> None:
        @tier1_read
        def f() -> int:
            return 42

        assert f() == 42

    def test_audit_writer_group(self) -> None:
        @audit_writer
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_audit_writer_attrs(self) -> None:
        @audit_writer
        def f() -> int:
            return 1

        assert f._wardline_tier_source is TaintState.AUDIT_TRAIL  # type: ignore[attr-defined]
        assert f._wardline_audit_writer is True  # type: ignore[attr-defined]

    def test_audit_writer_callable(self) -> None:
        @audit_writer
        def f() -> int:
            return 42

        assert f() == 42

    def test_authoritative_construction_group(self) -> None:
        @authoritative_construction
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_authoritative_construction_attrs(self) -> None:
        @authoritative_construction
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.PIPELINE, TaintState.AUDIT_TRAIL)  # type: ignore[attr-defined]

    def test_authoritative_construction_callable(self) -> None:
        @authoritative_construction
        def f() -> int:
            return 42

        assert f() == 42


# ---------------------------------------------------------------------------
# TestAsyncSupport
# ---------------------------------------------------------------------------


class TestAsyncSupport:
    """Async function decorator support."""

    def test_async_function_stays_coroutine(self) -> None:
        """Decorating async def preserves coroutine function status."""

        @external_boundary
        async def my_async_func() -> int:
            return 42

        assert asyncio.iscoroutinefunction(my_async_func)
        assert inspect.iscoroutinefunction(my_async_func)

    def test_async_function_callable(self) -> None:
        """Decorated async function can be awaited."""

        @external_boundary
        async def my_async_func() -> int:
            return 42

        result = asyncio.run(my_async_func())
        assert result == 42

    def test_async_function_has_wardline_groups(self) -> None:
        """Decorated async function has _wardline_groups."""

        @external_boundary
        async def my_async_func() -> int:
            return 1

        assert hasattr(my_async_func, "_wardline_groups")
        assert 1 in my_async_func._wardline_groups  # type: ignore[attr-defined]

    def test_async_function_has_semantic_attrs(self) -> None:
        """Decorated async function has semantic attributes."""

        @external_boundary
        async def my_async_func() -> int:
            return 1

        assert (
            my_async_func._wardline_tier_source  # type: ignore[attr-defined]
            is TaintState.EXTERNAL_RAW
        )

    def test_async_stacking(self) -> None:
        """Stacked decorators on async preserve coroutine status."""

        @audit_critical
        @external_boundary
        async def my_async_func() -> int:
            return 1

        assert asyncio.iscoroutinefunction(my_async_func)
        groups = my_async_func._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups
        assert 2 in groups

    def test_sync_function_not_coroutine(self) -> None:
        """Sync function remains non-coroutine after decoration."""

        @external_boundary
        def my_sync_func() -> int:
            return 1

        assert not asyncio.iscoroutinefunction(my_sync_func)

    def test_async_name_preserved(self) -> None:
        """Async decorated function preserves __name__."""

        @external_boundary
        async def my_async_func() -> int:
            """My async docstring."""
            return 1

        assert my_async_func.__name__ == "my_async_func"
        assert my_async_func.__doc__ == "My async docstring."
