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
        """Verify super().__init_subclass__() fires BEFORE wardline checks.

        We instrument both the MRO chain hook and the wardline check
        to record call order, then assert the sequence.
        """
        import unittest.mock

        call_order: list[str] = []

        class OrderTracker:
            def __init_subclass__(cls, **kwargs: object) -> None:
                super().__init_subclass__(**kwargs)
                call_order.append("mro_hook")

        original_check = __import__(
            "wardline.runtime.base", fromlist=["_check_decorated_methods"]
        )._check_decorated_methods

        def tracking_check(cls: type) -> None:
            call_order.append("wardline_check")
            original_check(cls)

        with unittest.mock.patch(
            "wardline.runtime.base._check_decorated_methods",
            side_effect=tracking_check,
        ):
            class MyBase(WardlineBase, OrderTracker):
                pass

        # MRO hook fires BEFORE wardline check
        assert call_order == ["mro_hook", "wardline_check"]


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

    def test_unrecognized_wardline_attribute_rejected(self) -> None:
        """Spoofed _wardline_* attrs on methods fail class creation."""
        import pytest

        with pytest.raises(ValueError, match="unrecognized wardline attribute"):
            class MyService(WardlineBase):
                def ingest(self) -> None:
                    pass

                ingest._wardline_groups = (1,)  # type: ignore[attr-defined]
                ingest._wardline_fake = True  # type: ignore[attr-defined]


# ── Cooperative MRO ──────────────────────────────────────────────


class TestCooperativeMRO:
    """WardlineBase.__init__ cooperates with the MRO via *args/**kwargs."""

    def test_init_cooperative_mro(self) -> None:
        """WardlineBase works with a mixin that takes positional args."""

        class SomeMixin:
            def __init__(self, x: int, **kwargs: object) -> None:
                super().__init__(**kwargs)
                self.x = x

        class C(WardlineBase, SomeMixin):
            pass

        obj = C(42)
        assert isinstance(obj, WardlineBase)
        assert isinstance(obj, SomeMixin)
        assert obj.x == 42

    def test_init_with_abc(self) -> None:
        """WardlineBase works with ABC in the MRO."""

        class SomeABC(ABC):
            @abstractmethod
            def do_thing(self) -> str: ...

        class C(WardlineBase, SomeABC):
            def do_thing(self) -> str:
                return "done"

        obj = C()
        assert isinstance(obj, WardlineBase)
        assert isinstance(obj, SomeABC)
        assert obj.do_thing() == "done"

    def test_init_no_args(self) -> None:
        """Bare subclass with no-arg init still works (regression)."""

        class C(WardlineBase):
            pass

        obj = C()
        assert isinstance(obj, WardlineBase)
