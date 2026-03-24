"""Tests for runtime enforcement hooks — opt-in production monitoring."""

from __future__ import annotations

import dataclasses
import logging

import pytest

from wardline.runtime import enforcement
from wardline.runtime.enforcement import (
    TierStamped,
    TierViolationError,
    _reset_enforcement_state,
    check_subclass_tier_consistency,
    check_tier_boundary,
    check_validated_record,
    enforce_construction,
    stamp_tier,
    unstamp,
)


@pytest.fixture(autouse=True)
def _reset_enforcement():
    """Reset enforcement state before each test for call-once latch isolation."""
    _reset_enforcement_state()
    yield
    _reset_enforcement_state()
    enforcement.set_violation_handler(None)


# ── Enable/disable ────────────────────────────────────────────


class TestEnableDisable:
    def test_disabled_by_default(self) -> None:
        assert not enforcement.is_enabled()

    def test_enable(self) -> None:
        enforcement.enable()
        assert enforcement.is_enabled()

    def test_disable_before_first_check(self) -> None:
        enforcement.enable()
        enforcement.disable()
        assert not enforcement.is_enabled()

    def test_disable_after_first_check_raises(self) -> None:
        """Call-once latch: disable() raises after check_tier_boundary."""
        enforcement.enable()
        obj = _make_tier_obj(1)
        check_tier_boundary(obj, expected_min_tier=2)
        with pytest.raises(RuntimeError, match="cannot be changed after first use"):
            enforcement.disable()

    def test_disable_after_check_validated_record(self) -> None:
        """Call-once latch fires after check_validated_record too."""
        enforcement.enable()
        check_validated_record(_GoodRecord())
        with pytest.raises(RuntimeError, match="cannot be changed after first use"):
            enforcement.disable()

    def test_disable_after_enforce_construction(self) -> None:
        """Call-once latch fires after enforce_construction too."""
        enforcement.enable()

        class Dummy:
            pass

        enforce_construction(Dummy())
        with pytest.raises(RuntimeError, match="cannot be changed after first use"):
            enforcement.disable()

    def test_enable_idempotent(self) -> None:
        enforcement.enable()
        enforcement.enable()
        assert enforcement.is_enabled()

    def test_enable_disable_log_events(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="wardline.runtime.enforcement"):
            enforcement.enable()
            enforcement.disable()
        assert "enabled" in caplog.text
        assert "disabled" in caplog.text


# ── TierStamped ──────────────────────────────────────────────


class TestTierStamped:
    def test_construction(self) -> None:
        ts = TierStamped(value={"key": "val"}, _wardline_tier=2, _wardline_groups=(1,))
        assert ts.value == {"key": "val"}
        assert ts._wardline_tier == 2
        assert ts._wardline_groups == (1,)

    def test_validates_range(self) -> None:
        with pytest.raises(ValueError, match="1-4"):
            TierStamped(value="x", _wardline_tier=0)
        with pytest.raises(ValueError, match="1-4"):
            TierStamped(value="x", _wardline_tier=5)

    def test_frozen(self) -> None:
        ts = TierStamped(value="x", _wardline_tier=1)
        with pytest.raises(dataclasses.FrozenInstanceError):
            ts._wardline_tier = 2  # type: ignore[misc]

    def test_satisfies_validated_record(self) -> None:
        from wardline.runtime.protocols import ValidatedRecord

        ts = TierStamped(value="x", _wardline_tier=1, _wardline_groups=(1,))
        assert isinstance(ts, ValidatedRecord)

    def test_generic_type(self) -> None:
        """TierStamped[dict[str, int]] is valid type annotation."""
        ts: TierStamped[dict[str, int]] = TierStamped(
            value={"a": 1}, _wardline_tier=2
        )
        assert ts.value == {"a": 1}

    def test_nested_blocked(self) -> None:
        """Nesting TierStamped inside TierStamped is detectable."""
        inner = TierStamped(value="x", _wardline_tier=1)
        outer = TierStamped(value=inner, _wardline_tier=2)
        # The outer value IS a TierStamped — callers should check
        assert isinstance(outer.value, TierStamped)

    def test_isinstance_subscripted_raises(self) -> None:
        """isinstance(x, TierStamped[dict]) raises TypeError (Python gotcha)."""
        ts = TierStamped(value={}, _wardline_tier=1)
        with pytest.raises(TypeError):
            isinstance(ts, TierStamped[dict])  # type: ignore[arg-type]


# ── stamp_tier ───────────────────────────────────────────────


class TestStampTier:
    def test_sets_attributes(self) -> None:
        obj = _Stampable()
        stamp_tier(obj, 2, groups=(3, 1), stamped_by="test")
        assert obj._wardline_tier == 2
        assert obj._wardline_groups == (1, 3)  # sorted
        assert obj._wardline_stamped_by == "test"

    def test_validates_range(self) -> None:
        obj = _Stampable()
        with pytest.raises(ValueError, match="1-4"):
            stamp_tier(obj, 0)
        with pytest.raises(ValueError, match="1-4"):
            stamp_tier(obj, 5)

    def test_raises_on_frozen(self, caplog: pytest.LogCaptureFixture) -> None:
        @dataclasses.dataclass(frozen=True)
        class Frozen:
            x: int = 1

        obj = Frozen()
        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            with pytest.raises(TypeError, match="Cannot set attributes"):
                stamp_tier(obj, 1)
        assert "Cannot stamp tier" in caplog.text

    def test_raises_on_restamp(self) -> None:
        obj = _Stampable()
        stamp_tier(obj, 1)
        with pytest.raises(ValueError, match="already has _wardline_tier"):
            stamp_tier(obj, 2)

    def test_overwrite_allows_restamp(self) -> None:
        obj = _Stampable()
        stamp_tier(obj, 1)
        stamp_tier(obj, 3, overwrite=True)
        assert obj._wardline_tier == 3

    def test_normalizes_groups(self) -> None:
        obj = _Stampable()
        stamp_tier(obj, 1, groups={5, 2, 9})
        assert obj._wardline_groups == (2, 5, 9)

    def test_logs_before_type_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """WARNING is logged BEFORE TypeError propagates (security audit trail)."""

        @dataclasses.dataclass(frozen=True, slots=True)
        class Slotted:
            x: int = 1

        obj = Slotted()
        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            with pytest.raises(TypeError):
                stamp_tier(obj, 2)
        # The WARNING must have been emitted
        assert any("Cannot stamp tier" in r.message for r in caplog.records)


# ── unstamp ──────────────────────────────────────────────────


class TestUnstamp:
    def test_tier_stamped_returns_value(self) -> None:
        ts = TierStamped(value={"a": 1}, _wardline_tier=2)
        assert unstamp(ts) == {"a": 1}

    def test_plain_object_returns_object(self) -> None:
        obj = {"a": 1}
        assert unstamp(obj) is obj


# ── check_tier_boundary ──────────────────────────────────────


class TestCheckTierBoundary:
    def test_passes_more_trusted(self) -> None:
        enforcement.enable()
        obj = _make_tier_obj(1)
        check_tier_boundary(obj, expected_min_tier=2)  # tier 1 <= 2

    def test_passes_exact(self) -> None:
        enforcement.enable()
        obj = _make_tier_obj(2)
        check_tier_boundary(obj, expected_min_tier=2)

    def test_fails_less_trusted(self) -> None:
        enforcement.enable()
        obj = _make_tier_obj(3)
        with pytest.raises(TierViolationError, match="tier 3.*expected <=2"):
            check_tier_boundary(obj, expected_min_tier=2)

    def test_fails_no_tier(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="no _wardline_tier"):
            check_tier_boundary(object(), expected_min_tier=2)

    def test_fails_non_int_tier(self) -> None:
        enforcement.enable()
        obj = _Stampable()
        obj._wardline_tier = "high"  # type: ignore[assignment]
        with pytest.raises(TierViolationError, match="non-int"):
            check_tier_boundary(obj, expected_min_tier=2)

    def test_logs_before_raise(self, caplog: pytest.LogCaptureFixture) -> None:
        enforcement.enable()
        obj = _make_tier_obj(4)
        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            with pytest.raises(TierViolationError):
                check_tier_boundary(obj, expected_min_tier=1)
        assert "Tier boundary violation" in caplog.text

    def test_calls_on_violation(self) -> None:
        enforcement.enable()
        called_with: list[tuple[object, int, int | None]] = []
        enforcement.set_violation_handler(
            lambda obj, exp, act: called_with.append((obj, exp, act))
        )

        obj = _make_tier_obj(4)
        with pytest.raises(TierViolationError):
            check_tier_boundary(obj, expected_min_tier=1)

        assert len(called_with) == 1
        assert called_with[0][1] == 1  # expected
        assert called_with[0][2] == 4  # actual

    def test_noop_when_disabled(self) -> None:
        obj = _make_tier_obj(4)
        check_tier_boundary(obj, expected_min_tier=1)  # should not raise

    def test_on_violation_exception_is_caught(self) -> None:
        """If on_violation raises, TierViolationError still propagates (callback isolated)."""
        enforcement.enable()

        def bad_callback(obj: object, exp: int, act: int | None) -> None:
            raise RuntimeError("callback failed")

        enforcement.set_violation_handler(bad_callback)

        obj = _make_tier_obj(4)
        # Callback exception is caught; TierViolationError always propagates
        with pytest.raises(TierViolationError):
            check_tier_boundary(obj, expected_min_tier=1)

    def test_fails_tier_out_of_range(self) -> None:
        enforcement.enable()
        obj = _make_tier_obj(5)
        with pytest.raises(TierViolationError, match="out of valid range 1-4"):
            check_tier_boundary(obj, expected_min_tier=2)

        obj0 = _make_tier_obj(0)
        with pytest.raises(TierViolationError, match="out of valid range 1-4"):
            check_tier_boundary(obj0, expected_min_tier=2)

    def test_on_tierstamped_object(self) -> None:
        """check_tier_boundary works on TierStamped objects."""
        enforcement.enable()
        ts = TierStamped(value="x", _wardline_tier=1, _wardline_groups=(1,))
        check_tier_boundary(ts, expected_min_tier=2)  # tier 1 <= 2

        ts_bad = TierStamped(value="x", _wardline_tier=4, _wardline_groups=(1,))
        with pytest.raises(TierViolationError):
            check_tier_boundary(ts_bad, expected_min_tier=2)


# ── check_validated_record ───────────────────────────────────


class TestCheckValidatedRecord:
    def test_passes_conforming(self) -> None:
        enforcement.enable()
        check_validated_record(_GoodRecord())

    def test_accepts_set_groups(self) -> None:
        enforcement.enable()
        check_validated_record(_SetGroupsRecord())

    def test_accepts_frozenset_groups(self) -> None:
        enforcement.enable()
        check_validated_record(_FrozensetGroupsRecord())

    def test_rejects_missing_tier(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="does not conform"):
            check_validated_record(object())

    def test_rejects_bad_tier_type(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="must be int 1-4"):
            check_validated_record(_BadTierTypeRecord())

    def test_logs_before_raise(self, caplog: pytest.LogCaptureFixture) -> None:
        enforcement.enable()
        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            with pytest.raises(TierViolationError):
                check_validated_record(object())
        assert "ValidatedRecord check failed" in caplog.text


# ── TierViolationError ───────────────────────────────────────


class TestTierViolationError:
    def test_is_not_type_error(self) -> None:
        """TierViolationError is NOT catchable by except TypeError."""
        assert not issubclass(TierViolationError, TypeError)

    def test_attributes(self) -> None:
        sentinel = object()
        err = TierViolationError(
            "test", obj=sentinel, expected_tier=2, actual_tier=4
        )
        assert err.obj is sentinel
        assert err.expected_tier == 2
        assert err.actual_tier == 4
        assert str(err) == "test"


# ── enforce_construction ─────────────────────────────────────


class TestEnforceConstruction:
    def test_uses_real_attrs(self) -> None:
        """Reads _wardline_tier_source from decorated methods."""
        from wardline.decorators.authority import external_boundary, tier1_read

        enforcement.enable()

        class Mixed:
            @external_boundary
            def ingest(self) -> None:
                pass

            @tier1_read
            def read(self) -> None:
                pass

        # Should not raise, but should detect mixed tiers
        enforce_construction(Mixed())

    def test_warns_mixed_tiers(self, caplog: pytest.LogCaptureFixture) -> None:
        from wardline.decorators.authority import external_boundary, tier1_read

        enforcement.enable()

        class MixedTiers:
            @external_boundary
            def ingest(self) -> None:
                pass

            @tier1_read
            def read(self) -> None:
                pass

        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            enforce_construction(MixedTiers())
        assert "spanning multiple tiers" in caplog.text

    def test_noop_when_disabled(self) -> None:
        class Anything:
            pass

        enforce_construction(Anything())  # should not raise

    def test_zero_decorated_methods_no_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        enforcement.enable()

        class Empty:
            pass

        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            enforce_construction(Empty())
        assert "spanning multiple tiers" not in caplog.text


# ── Helpers ──────────────────────────────────────────────────


class _Stampable:
    """Plain mutable object for stamping tests."""

    pass


class _GoodRecord:
    @property
    def _wardline_tier(self) -> int:
        return 1

    @property
    def _wardline_groups(self) -> tuple[int, ...]:
        return (1,)


class _SetGroupsRecord:
    @property
    def _wardline_tier(self) -> int:
        return 2

    @property
    def _wardline_groups(self) -> set[int]:
        return {1, 3}


class _BadTierTypeRecord:
    @property
    def _wardline_tier(self) -> str:
        return "high"  # type: ignore[return-type]

    @property
    def _wardline_groups(self) -> tuple[int, ...]:
        return (1,)


class _FrozensetGroupsRecord:
    @property
    def _wardline_tier(self) -> int:
        return 2

    @property
    def _wardline_groups(self) -> frozenset[int]:
        return frozenset({1, 3})


def _make_tier_obj(tier: int) -> object:
    """Create a simple object with _wardline_tier set."""
    obj = _Stampable()
    obj._wardline_tier = tier  # type: ignore[attr-defined]
    return obj


# ── check_subclass_tier_consistency (direct) ────────────────


class TestCheckSubclassTierConsistency:
    """F8: Direct tests for check_subclass_tier_consistency warnings list."""

    def test_consistent_class_returns_empty(self) -> None:
        from wardline.decorators.authority import tier1_read

        class Consistent:
            @tier1_read
            def read_a(self) -> None:
                pass

            @tier1_read
            def read_b(self) -> None:
                pass

        warnings = check_subclass_tier_consistency(Consistent)
        assert warnings == []

    def test_mixed_tiers_returns_warnings(self) -> None:
        from wardline.decorators.authority import external_boundary, tier1_read

        class Mixed:
            @external_boundary
            def ingest(self) -> None:
                pass

            @tier1_read
            def read(self) -> None:
                pass

        warnings = check_subclass_tier_consistency(Mixed)
        assert len(warnings) == 1
        assert "spanning multiple tiers" in warnings[0]
        assert "Mixed" in warnings[0]

    def test_no_decorated_methods_returns_empty(self) -> None:
        class Plain:
            def method(self) -> None:
                pass

        warnings = check_subclass_tier_consistency(Plain)
        assert warnings == []
