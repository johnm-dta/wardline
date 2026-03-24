"""Tests for decorator auto-stamping (Task 4, WP 3.2).

When runtime enforcement is enabled, decorated functions auto-stamp their
return values with tier metadata. Unstampable objects (dicts, primitives,
frozen dataclasses) get wrapped in TierStamped.
"""

from __future__ import annotations

import logging
from collections import namedtuple
from dataclasses import dataclass
from typing import Any

import pytest

from wardline.core.taints import TaintState
from wardline.decorators._base import wardline_decorator
from wardline.runtime.enforcement import (
    TierStamped,
    _reset_enforcement_state,
    enable,
    is_enabled,
)


@pytest.fixture(autouse=True)
def _enforcement_reset():
    """Enable enforcement for all tests, reset after each."""
    _reset_enforcement_state()
    enable()
    yield
    _reset_enforcement_state()


# ── Helpers: real decorators from semantic_attrs ─────────────

# Decorator with _wardline_transition: EXTERNAL_RAW -> SHAPE_VALIDATED => tier 3
shape_dec = wardline_decorator(
    1,
    "validates_shape",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.SHAPE_VALIDATED),
)

# Decorator with _wardline_tier_source: EXTERNAL_RAW => tier 4
boundary_dec = wardline_decorator(
    1,
    "external_boundary",
    _wardline_tier_source=TaintState.EXTERNAL_RAW,
)

# Supplementary decorator (no tier info) — group 2, audit_critical
supplementary_dec = wardline_decorator(
    2,
    "audit_critical",
    _wardline_audit_critical=True,
)


# ── Tests ────────────────────────────────────────────────────


class TestStampsReturnInstance:
    """Class instances get _wardline_tier set directly."""

    def test_stamps_return_instance(self):
        class Record:
            pass

        @shape_dec
        def make_record() -> Record:
            return Record()

        result = make_record()
        assert isinstance(result, Record)
        assert result._wardline_tier == 3  # SHAPE_VALIDATED -> TIER_3
        assert isinstance(result._wardline_groups, tuple)
        assert result._wardline_stamped_by == make_record.__qualname__


class TestWrapsReturnDict:
    """Dicts cannot have attrs set, so they get wrapped in TierStamped."""

    def test_wraps_return_dict(self):
        @shape_dec
        def make_dict() -> dict[str, int]:
            return {"key": 42}

        result = make_dict()
        assert isinstance(result, TierStamped)
        assert result.value == {"key": 42}
        assert result._wardline_tier == 3


class TestWrapsReturnPrimitive:
    """Primitives (int, str) get wrapped in TierStamped."""

    def test_wraps_return_primitive(self):
        @shape_dec
        def make_int() -> int:
            return 42

        result = make_int()
        assert isinstance(result, TierStamped)
        assert result.value == 42
        assert result._wardline_tier == 3


class TestWrapsReturnNoneSkipped:
    """None return values are not wrapped (guard: result is not None)."""

    def test_wraps_return_none_skipped(self):
        @shape_dec
        def returns_none() -> None:
            return None

        result = returns_none()
        assert result is None


class TestWrapsFrozenDataclass:
    """Frozen dataclasses get wrapped in TierStamped."""

    def test_wraps_frozen_dataclass(self):
        @dataclass(frozen=True)
        class FrozenRecord:
            x: int

        @shape_dec
        def make_frozen() -> FrozenRecord:
            return FrozenRecord(x=1)

        result = make_frozen()
        assert isinstance(result, TierStamped)
        assert result.value == FrozenRecord(x=1)
        assert result._wardline_tier == 3


class TestWrapsGenerator:
    """Generator objects get wrapped in TierStamped (they are not None)."""

    def test_wraps_generator(self):
        @shape_dec
        def make_gen() -> Any:
            # Return a generator object
            return (x for x in range(3))

        result = make_gen()
        assert isinstance(result, TierStamped)
        assert result._wardline_tier == 3
        # The wrapped generator still works
        assert list(result.value) == [0, 1, 2]


class TestWrapsNamedtuple:
    """Named tuples (immutable) get wrapped in TierStamped."""

    def test_wraps_namedtuple(self):
        Point = namedtuple("Point", ["x", "y"])

        @shape_dec
        def make_point() -> Any:
            return Point(1, 2)

        result = make_point()
        assert isinstance(result, TierStamped)
        assert result.value == Point(1, 2)
        assert result._wardline_tier == 3


class TestNoStampWhenDisabled:
    """When enforcement is disabled, no stamping occurs."""

    def test_no_stamp_when_disabled(self):
        _reset_enforcement_state()  # disabled by default
        assert not is_enabled()

        @shape_dec
        def make_dict() -> dict[str, int]:
            return {"key": 42}

        result = make_dict()
        assert isinstance(result, dict)
        assert not hasattr(result, "_wardline_tier")


class TestSupplementaryNoStamp:
    """Supplementary decorators (no tier info) never stamp."""

    def test_supplementary_no_stamp(self):
        @supplementary_dec
        def make_dict() -> dict[str, int]:
            return {"key": 42}

        result = make_dict()
        assert isinstance(result, dict)
        assert not hasattr(result, "_wardline_tier")


class TestOutputTierFromTransition:
    """Output tier derived from _wardline_transition[1] via TAINT_TO_TIER."""

    def test_output_tier_from_transition(self):
        @shape_dec
        def make() -> Any:
            class Obj:
                pass
            return Obj()

        result = make()
        # SHAPE_VALIDATED maps to TIER_3
        assert result._wardline_tier == 3


class TestOutputTierFromTierSource:
    """Output tier derived from _wardline_tier_source via TAINT_TO_TIER."""

    def test_output_tier_from_tier_source(self):
        @boundary_dec
        def make() -> Any:
            class Obj:
                pass
            return Obj()

        result = make()
        # EXTERNAL_RAW maps to TIER_4
        assert result._wardline_tier == 4


class TestGroupsNormalizedToTuple:
    """_wardline_groups is normalized to tuple(sorted(...)) at stamp time."""

    def test_groups_normalized_to_tuple(self):
        @shape_dec
        def make() -> Any:
            class Obj:
                pass
            return Obj()

        result = make()
        assert isinstance(result._wardline_groups, tuple)
        # Group 1 from validates_shape
        assert result._wardline_groups == (1,)


class TestStampedByQualname:
    """_wardline_stamped_by is the wrapper's __qualname__ (original via wraps)."""

    def test_stamped_by_qualname(self):
        @shape_dec
        def my_function() -> Any:
            class Obj:
                pass
            return Obj()

        result = my_function()
        assert result._wardline_stamped_by == my_function.__qualname__


class TestWarningLoggedOnWrap:
    """A WARNING is logged when auto-wrapping to TierStamped."""

    def test_warning_logged_on_wrap(self, caplog: pytest.LogCaptureFixture):
        @shape_dec
        def make_dict() -> dict[str, int]:
            return {"key": 42}

        with caplog.at_level(logging.WARNING):
            result = make_dict()

        assert isinstance(result, TierStamped)
        # stamp_tier logs WARNING before raising TypeError on unstampable objects
        assert any("Cannot stamp tier" in msg for msg in caplog.messages)
