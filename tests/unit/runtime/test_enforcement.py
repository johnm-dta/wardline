"""Tests for runtime enforcement hooks — opt-in production monitoring."""

from __future__ import annotations

import pytest

from wardline.runtime import enforcement
from wardline.runtime.enforcement import (
    TierViolationError,
    check_subclass_tier_consistency,
    check_tier_boundary,
    check_validated_record,
)


@pytest.fixture(autouse=True)
def _reset_enforcement():
    """Ensure enforcement is disabled after each test."""
    enforcement.disable()
    yield
    enforcement.disable()


# ── Enable/disable ────────────────────────────────────────────


class TestEnableDisable:
    def test_disabled_by_default(self) -> None:
        assert not enforcement.is_enabled()

    def test_enable(self) -> None:
        enforcement.enable()
        assert enforcement.is_enabled()

    def test_disable(self) -> None:
        enforcement.enable()
        enforcement.disable()
        assert not enforcement.is_enabled()


# ── check_validated_record ────────────────────────────────────


class _GoodRecord:
    @property
    def _wardline_tier(self) -> int:
        return 1

    @property
    def _wardline_groups(self) -> tuple[int, ...]:
        return (1,)


class _BadRecord:
    pass


class TestCheckValidatedRecord:
    def test_noop_when_disabled(self) -> None:
        """No error even for non-conforming objects when disabled."""
        check_validated_record(_BadRecord())

    def test_passes_for_conforming(self) -> None:
        enforcement.enable()
        check_validated_record(_GoodRecord())  # should not raise

    def test_raises_for_non_conforming(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="does not conform"):
            check_validated_record(_BadRecord())

    def test_error_has_obj_attribute(self) -> None:
        enforcement.enable()
        bad = _BadRecord()
        with pytest.raises(TierViolationError) as exc_info:
            check_validated_record(bad)
        assert exc_info.value.obj is bad


# ── check_tier_boundary ───────────────────────────────────────


class _Tier1Record:
    _wardline_tier = 1


class _Tier4Record:
    _wardline_tier = 4


class _NoTierRecord:
    pass


class TestCheckTierBoundary:
    def test_noop_when_disabled(self) -> None:
        check_tier_boundary(_Tier4Record(), expected_min_tier=1)

    def test_passes_when_tier_sufficient(self) -> None:
        enforcement.enable()
        check_tier_boundary(_Tier1Record(), expected_min_tier=2)

    def test_passes_when_tier_equal(self) -> None:
        enforcement.enable()
        check_tier_boundary(_Tier1Record(), expected_min_tier=1)

    def test_raises_when_tier_insufficient(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="tier 4.*expected <=1"):
            check_tier_boundary(_Tier4Record(), expected_min_tier=1)

    def test_raises_when_no_tier(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="no _wardline_tier"):
            check_tier_boundary(_NoTierRecord(), expected_min_tier=1)

    def test_error_includes_context(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError, match="context: ingest"):
            check_tier_boundary(
                _Tier4Record(), expected_min_tier=1, context="ingest"
            )

    def test_error_attributes(self) -> None:
        enforcement.enable()
        with pytest.raises(TierViolationError) as exc_info:
            check_tier_boundary(_Tier4Record(), expected_min_tier=1)
        assert exc_info.value.expected_tier == 1
        assert exc_info.value.actual_tier == 4


# ── WardlineBase enforcement at construction ──────────────────


class TestWardlineBaseEnforcement:
    def test_construction_noop_when_disabled(self) -> None:
        """WardlineBase.__init__ does nothing when enforcement is off."""
        from wardline.runtime.base import WardlineBase

        class MyService(WardlineBase):
            pass

        svc = MyService()  # should not raise
        assert isinstance(svc, WardlineBase)

    def test_construction_runs_when_enabled(self) -> None:
        """WardlineBase.__init__ runs enforcement checks when enabled."""
        from wardline.runtime.base import WardlineBase

        enforcement.enable()

        class MyService(WardlineBase):
            pass

        svc = MyService()  # should not raise (no decorated methods = no issues)
        assert isinstance(svc, WardlineBase)


# ── check_subclass_tier_consistency ───────────────────────────


class TestTierConsistency:
    def test_no_warnings_for_clean_class(self) -> None:
        from wardline.runtime.base import WardlineBase

        class Clean(WardlineBase):
            pass

        warnings = check_subclass_tier_consistency(Clean)
        assert warnings == []

    def test_no_warnings_single_tier(self) -> None:
        from wardline.decorators.authority import external_boundary
        from wardline.runtime.base import WardlineBase

        class SingleTier(WardlineBase):
            @external_boundary
            def ingest(self) -> None:
                pass

        warnings = check_subclass_tier_consistency(SingleTier)
        assert warnings == []


# ── TierViolationError ────────────────────────────────────────


class TestTierViolationError:
    def test_is_type_error(self) -> None:
        assert issubclass(TierViolationError, TypeError)

    def test_message(self) -> None:
        err = TierViolationError("test message")
        assert str(err) == "test message"

    def test_attributes_default_none(self) -> None:
        err = TierViolationError("test")
        assert err.obj is None
        assert err.expected_tier is None
        assert err.actual_tier is None
