"""Integration tests for runtime enforcement — end-to-end scenarios.

Tests the full pipeline: decorators → auto-stamping → checking → WardlineBase,
with enforcement enabled and disabled.
"""

from __future__ import annotations

import pytest

from wardline.runtime import enforcement
from wardline.runtime.enforcement import (
    TierStamped,
    TierViolationError,
    _reset_enforcement_state,
    check_tier_boundary,
    stamp_tier,
    unstamp,
)


@pytest.fixture(autouse=True)
def _reset_enforcement():
    """Reset enforcement state before/after each test for latch isolation."""
    _reset_enforcement_state()
    yield
    _reset_enforcement_state()
    enforcement.set_violation_handler(None)


class TestDecoratedFunctionStampsReturn:
    """Enable enforcement → call @validates_shape function → check TierStamped result."""

    def test_decorated_function_stamps_return(self) -> None:
        from wardline.decorators.authority import validates_shape

        enforcement.enable()

        @validates_shape
        def parse(data: str) -> dict:
            return {"key": data}

        result = parse("hello")

        # validates_shape transitions to SHAPE_VALIDATED → tier 3
        # Result is a dict (unstampable), so auto-wrapped in TierStamped
        assert isinstance(result, TierStamped)
        assert result._wardline_tier == 3
        assert result.value == {"key": "hello"}

        # unstamp() recovers the original value
        raw = unstamp(result)
        assert raw == {"key": "hello"}
        assert not isinstance(raw, TierStamped)


class TestCheckTierBoundaryIntegration:
    """Stamp + check + pass/fail through the full pipeline."""

    def test_stamp_and_check_passes(self) -> None:
        enforcement.enable()

        class Record:
            pass

        obj = Record()
        stamp_tier(obj, 2, groups=(1,), stamped_by="test")

        # Tier 2 meets min tier 2
        check_tier_boundary(obj, expected_min_tier=2)

        # Tier 2 meets min tier 3 (more trusted than required)
        check_tier_boundary(obj, expected_min_tier=3)

    def test_stamp_and_check_fails(self) -> None:
        enforcement.enable()

        class Record:
            pass

        obj = Record()
        stamp_tier(obj, 3, groups=(1,), stamped_by="test")

        # Tier 3 does NOT meet min tier 2
        with pytest.raises(TierViolationError, match="tier 3.*expected <=2"):
            check_tier_boundary(obj, expected_min_tier=2)

    def test_tierstamped_check_passes(self) -> None:
        """TierStamped objects also work with check_tier_boundary."""
        enforcement.enable()

        ts = TierStamped(value={"data": 1}, _wardline_tier=1, _wardline_groups=(1,))
        check_tier_boundary(ts, expected_min_tier=2)  # tier 1 <= 2, passes

    def test_tierstamped_check_fails(self) -> None:
        enforcement.enable()

        ts = TierStamped(value={"data": 1}, _wardline_tier=4, _wardline_groups=())
        with pytest.raises(TierViolationError):
            check_tier_boundary(ts, expected_min_tier=2)


class TestWardlineBaseConstructionWithEnforcement:
    """WardlineBase subclass with enforcement enabled."""

    def test_wardline_base_construction_with_enforcement(self) -> None:
        from wardline.decorators.authority import validates_shape
        from wardline.runtime.base import WardlineBase

        enforcement.enable()

        class MyService(WardlineBase):
            @validates_shape
            def validate(self, data: str) -> dict:
                return {"key": data}

        # Construction should succeed (single tier — no mixed-tier warning)
        svc = MyService()
        assert isinstance(svc, WardlineBase)

    def test_wardline_base_mixed_tiers_warns(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging

        from wardline.decorators.authority import external_boundary, tier1_read
        from wardline.runtime.base import WardlineBase

        enforcement.enable()

        class MixedService(WardlineBase):
            @external_boundary
            def ingest(self) -> None:
                pass

            @tier1_read
            def read(self) -> None:
                pass

        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            MixedService()
        assert "spanning multiple tiers" in caplog.text


class TestEnforcementDisabledNoOverhead:
    """Enforcement off — verify no TierStamped wrapping occurs."""

    def test_enforcement_disabled_no_overhead(self) -> None:
        from wardline.decorators.authority import validates_shape

        # Enforcement is disabled by default (after _reset_enforcement_state)
        assert not enforcement.is_enabled()

        @validates_shape
        def parse(data: str) -> dict:
            return {"key": data}

        result = parse("hello")

        # With enforcement disabled, raw dict is returned — no wrapping
        assert isinstance(result, dict)
        assert not isinstance(result, TierStamped)
        assert result == {"key": "hello"}


class TestEnforcementOnNoViolations:
    """Enable enforcement, construct well-formed class, no errors/warnings."""

    def test_enforcement_on_no_violations(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging

        from wardline.decorators.authority import validates_shape
        from wardline.runtime.base import WardlineBase

        enforcement.enable()

        class WellFormedService(WardlineBase):
            @validates_shape
            def validate(self, data: str) -> dict:
                return {"key": data}

        with caplog.at_level(logging.WARNING, logger="wardline.runtime.enforcement"):
            svc = WellFormedService()

        # No tier-consistency warnings
        tier_warnings = [
            r for r in caplog.records
            if "spanning multiple tiers" in r.message
        ]
        assert len(tier_warnings) == 0

        # Service is usable
        result = svc.validate("test")
        assert isinstance(result, TierStamped)
        assert result.value == {"key": "test"}
