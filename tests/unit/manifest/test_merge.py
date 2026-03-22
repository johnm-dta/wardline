"""Tests for wardline.manifest.merge — overlay merge logic."""

from __future__ import annotations

import pytest

from wardline.manifest.merge import (
    ManifestWidenError,
    ResolvedManifest,
    merge,
)
from wardline.manifest.models import (
    BoundaryEntry,
    RulesConfig,
    TierEntry,
    WardlineManifest,
    WardlineOverlay,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_manifest(
    tiers: tuple[TierEntry, ...] = (),
    overrides: tuple[dict[str, object], ...] = (),
) -> WardlineManifest:
    return WardlineManifest(
        tiers=tiers,
        rules=RulesConfig(overrides=overrides),
    )


def _overlay(
    name: str = "test-overlay",
    boundaries: tuple[BoundaryEntry, ...] = (),
    rule_overrides: tuple[dict[str, object], ...] = (),
) -> WardlineOverlay:
    return WardlineOverlay(
        overlay_for=name,
        boundaries=boundaries,
        rule_overrides=rule_overrides,
    )


# ---------------------------------------------------------------------------
# Tier narrow-only invariant
# ---------------------------------------------------------------------------


class TestTierNarrowOnly:
    """Overlays may tighten tiers but never relax them."""

    def test_tighten_tier_accepted(self) -> None:
        """Overlay that tightens (lowers) a tier number passes."""
        base = _base_manifest(
            tiers=(TierEntry(id="process_payment", tier=3),),
        )
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="process_payment",
                    transition="TRUST_ELEVATION",
                    from_tier=2,  # stricter than base tier 3
                ),
            ),
        )

        result = merge(base, overlay)

        assert isinstance(result, ResolvedManifest)
        assert len(result.boundaries) == 1

    def test_same_tier_accepted(self) -> None:
        """Overlay that keeps the same tier number passes."""
        base = _base_manifest(
            tiers=(TierEntry(id="process_payment", tier=2),),
        )
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="process_payment",
                    transition="TRUST_ELEVATION",
                    from_tier=2,
                ),
            ),
        )

        result = merge(base, overlay)
        assert len(result.boundaries) == 1

    def test_widen_tier_raises(self) -> None:
        """Overlay that relaxes (raises) a tier number is rejected."""
        base = _base_manifest(
            tiers=(TierEntry(id="process_payment", tier=1),),
        )
        overlay = _overlay(
            name="payments-overlay",
            boundaries=(
                BoundaryEntry(
                    function="process_payment",
                    transition="TRUST_ELEVATION",
                    from_tier=3,  # relaxes tier 1 -> 3
                ),
            ),
        )

        with pytest.raises(ManifestWidenError) as exc_info:
            merge(base, overlay)

        err = exc_info.value
        assert err.overlay_name == "payments-overlay"
        assert err.field_name == "from_tier"
        assert err.base_value == 1
        assert err.attempted_value == 3

    def test_widen_error_message_is_actionable(self) -> None:
        """ManifestWidenError message includes overlay, field, and values."""
        base = _base_manifest(
            tiers=(TierEntry(id="handle_auth", tier=1),),
        )
        overlay = _overlay(
            name="auth-overlay",
            boundaries=(
                BoundaryEntry(
                    function="handle_auth",
                    transition="TRUST_ELEVATION",
                    to_tier=2,
                ),
            ),
        )

        with pytest.raises(ManifestWidenError, match="auth-overlay") as exc_info:
            merge(base, overlay)

        msg = str(exc_info.value)
        assert "to_tier" in msg
        assert "1" in msg  # base value
        assert "2" in msg  # attempted value

    def test_no_base_tier_allows_any_boundary(self) -> None:
        """Boundary referencing a function with no base tier entry passes."""
        base = _base_manifest(tiers=())
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="new_fn",
                    transition="BOUNDARY_CROSSING",
                    from_tier=5,
                ),
            ),
        )

        result = merge(base, overlay)
        assert len(result.boundaries) == 1


# ---------------------------------------------------------------------------
# Severity reduction + governance signals
# ---------------------------------------------------------------------------


class TestSeverityReduction:
    """Severity reduction is allowed but emits a GOVERNANCE INFO signal."""

    def test_severity_reduction_accepted(self) -> None:
        """ERROR -> WARNING is allowed."""
        base = _base_manifest(
            overrides=({"id": "PY-WL-001", "severity": "ERROR"},),
        )
        overlay = _overlay(
            rule_overrides=({"id": "PY-WL-001", "severity": "WARNING"},),
        )

        result = merge(base, overlay)

        # The merged override should have WARNING
        merged = {o["id"]: o for o in result.rules.overrides}
        assert merged["PY-WL-001"]["severity"] == "WARNING"

    def test_governance_signal_emitted_on_reduction(self) -> None:
        """A GOVERNANCE INFO signal is emitted when severity is reduced."""
        base = _base_manifest(
            overrides=({"id": "PY-WL-002", "severity": "ERROR"},),
        )
        overlay = _overlay(
            rule_overrides=({"id": "PY-WL-002", "severity": "WARNING"},),
        )

        result = merge(base, overlay)

        assert len(result.governance_signals) == 1
        signal = result.governance_signals[0]
        assert signal.level == "INFO"
        assert "PY-WL-002" in signal.message
        assert "ERROR" in signal.message
        assert "WARNING" in signal.message

    def test_severity_increase_no_signal(self) -> None:
        """Increasing severity (WARNING -> ERROR) emits no signal."""
        base = _base_manifest(
            overrides=({"id": "PY-WL-003", "severity": "WARNING"},),
        )
        overlay = _overlay(
            rule_overrides=({"id": "PY-WL-003", "severity": "ERROR"},),
        )

        result = merge(base, overlay)

        assert len(result.governance_signals) == 0

    def test_no_base_override_no_signal(self) -> None:
        """New rule override with no base entry emits no signal."""
        base = _base_manifest()
        overlay = _overlay(
            rule_overrides=({"id": "PY-WL-004", "severity": "WARNING"},),
        )

        result = merge(base, overlay)

        assert len(result.governance_signals) == 0
        merged = {o["id"]: o for o in result.rules.overrides}
        assert merged["PY-WL-004"]["severity"] == "WARNING"


# ---------------------------------------------------------------------------
# Boundary merging
# ---------------------------------------------------------------------------


class TestBoundaryMerge:
    """Overlay boundaries are included in the resolved manifest."""

    def test_boundaries_merged(self) -> None:
        """Overlay boundaries appear in the result."""
        base = _base_manifest()
        overlay = _overlay(
            boundaries=(
                BoundaryEntry(
                    function="fn_a",
                    transition="TRUST_ELEVATION",
                ),
                BoundaryEntry(
                    function="fn_b",
                    transition="BOUNDARY_CROSSING",
                ),
            ),
        )

        result = merge(base, overlay)

        assert len(result.boundaries) == 2
        fns = {b.function for b in result.boundaries}
        assert fns == {"fn_a", "fn_b"}

    def test_empty_overlay_produces_empty_boundaries(self) -> None:
        """An overlay with no boundaries produces an empty tuple."""
        result = merge(_base_manifest(), _overlay())
        assert result.boundaries == ()


# ---------------------------------------------------------------------------
# ResolvedManifest structure
# ---------------------------------------------------------------------------


class TestResolvedManifest:
    """ResolvedManifest is a frozen dataclass with expected fields."""

    def test_frozen(self) -> None:
        result = merge(_base_manifest(), _overlay())
        with pytest.raises(AttributeError):
            result.tiers = ()  # type: ignore[misc]

    def test_preserves_base_tiers(self) -> None:
        tiers = (TierEntry(id="x", tier=1),)
        result = merge(_base_manifest(tiers=tiers), _overlay())
        assert result.tiers == tiers
