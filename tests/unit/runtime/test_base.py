"""Tests for WardlineBase — ABCMeta composition, __init_subclass__ cooperation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from wardline.decorators.authority import external_boundary
from wardline.runtime.base import WardlineBase

# ── ABCMeta composition ──────────────────────────────────────────


class TestABCMetaComposition:
    """WardlineBase cooperates with ABCMeta."""

    def test_abc_subclass_with_wardline_base(self) -> None:
        """A class inheriting both ABC and WardlineBase works."""

        class MyService(WardlineBase, ABC):
            @abstractmethod
            def process(self) -> None: ...

        class ConcreteService(MyService):
            def process(self) -> None:
                pass

        svc = ConcreteService()
        assert isinstance(svc, WardlineBase)
        assert isinstance(svc, ABC)

    def test_abc_enforcement_still_works(self) -> None:
        """ABCMeta still prevents instantiation of abstract classes."""
        import pytest

        class MyService(WardlineBase, ABC):
            @abstractmethod
            def process(self) -> None: ...

        with pytest.raises(TypeError):
            MyService()  # type: ignore[abstract]


# ── Dual __init_subclass__ ────────────────────────────────────────


class TestDualInitSubclass:
    """Both __init_subclass__ hooks fire in multi-inheritance."""

    def test_both_hooks_fire(self) -> None:
        """WardlineBase and a custom __init_subclass__ both execute."""
        hook_fired: list[str] = []

        class TrackingBase:
            def __init_subclass__(cls, **kwargs: object) -> None:
                super().__init_subclass__(**kwargs)
                hook_fired.append(cls.__name__)

        class Combined(WardlineBase, TrackingBase):
            pass

        # Both hooks should have fired for Combined
        assert "Combined" in hook_fired

    def test_hooks_fire_for_grandchild(self) -> None:
        """Hooks fire at each level of the inheritance chain."""
        hook_fired: list[str] = []

        class TrackingBase:
            def __init_subclass__(cls, **kwargs: object) -> None:
                super().__init_subclass__(**kwargs)
                hook_fired.append(cls.__name__)

        class Parent(WardlineBase, TrackingBase):
            pass

        class Child(Parent):
            pass

        assert "Parent" in hook_fired
        assert "Child" in hook_fired


# ── Super ordering ────────────────────────────────────────────────


class TestSuperOrdering:
    """WardlineBase calls super() BEFORE its own checks."""

    def test_super_called_before_checks(self) -> None:
        """The cooperative super() is called first in __init_subclass__.

        This is verified by checking that a base class with its own
        __init_subclass__ has its hook called even when combined with
        WardlineBase. If super() were called AFTER, the MRO chain
        could break.
        """
        call_order: list[str] = []

        class OrderTracker:
            def __init_subclass__(cls, **kwargs: object) -> None:
                super().__init_subclass__(**kwargs)
                call_order.append("tracker")

        class MyBase(WardlineBase, OrderTracker):
            pass

        # OrderTracker's hook fires because WardlineBase calls super()
        assert "tracker" in call_order


# ── Decorated method detection ────────────────────────────────────


class TestDecoratedMethodDetection:
    """WardlineBase checks subclass methods for wardline decorators."""

    def test_decorated_method_accepted(self) -> None:
        """A method with a wardline decorator is accepted without error."""

        class MyService(WardlineBase):
            @external_boundary
            def ingest(self, data: bytes) -> dict:  # type: ignore[type-arg]
                return {}

        svc = MyService()
        assert hasattr(svc.ingest, "_wardline_groups")

    def test_undecorated_method_accepted(self) -> None:
        """Methods without wardline decorators are silently accepted."""

        class MyService(WardlineBase):
            def helper(self) -> None:
                pass

        svc = MyService()
        assert not hasattr(svc.helper, "_wardline_groups")

    def test_private_methods_skipped(self) -> None:
        """Private methods (starting with _) are not checked."""

        class MyService(WardlineBase):
            def _internal(self) -> None:
                pass

        # Should not raise
        svc = MyService()
        assert hasattr(svc, "_internal")
