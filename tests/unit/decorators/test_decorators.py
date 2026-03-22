"""Tests for wardline decorator factory."""

from __future__ import annotations

import logging

import pytest

from wardline.core.taints import TaintState
from wardline.decorators._base import get_wardline_attrs, wardline_decorator

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

    def test_severed_chain_returns_none(self, caplog: pytest.LogCaptureFixture) -> None:
        def plain_func() -> int:
            return 1

        with caplog.at_level(logging.WARNING):
            result = get_wardline_attrs(plain_func)

        assert result is None


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
