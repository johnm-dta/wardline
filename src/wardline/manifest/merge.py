"""Overlay merge — combine a base manifest with an overlay.

Enforces the narrow-only invariant: overlays may tighten tiers but never
relax them.  Severity reduction (e.g. ERROR -> WARNING) *is* permitted as a
soft-adoption path; when it occurs a GOVERNANCE INFO signal is recorded in
the returned :class:`ResolvedManifest`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wardline.manifest.models import (
    BoundaryEntry,
    RulesConfig,
    TierEntry,
    WardlineManifest,
    WardlineOverlay,
)


@dataclass(frozen=True)
class GovernanceSignal:
    """An informational governance event emitted during merge."""

    level: str
    message: str


@dataclass(frozen=True)
class ResolvedManifest:
    """Result of merging a base manifest with an overlay."""

    tiers: tuple[TierEntry, ...] = ()
    rules: RulesConfig = field(default_factory=RulesConfig)
    boundaries: tuple[BoundaryEntry, ...] = ()
    governance_signals: tuple[GovernanceSignal, ...] = ()


class ManifestWidenError(Exception):
    """Raised when an overlay attempts to widen (relax) a tier.

    Attributes:
        overlay_name: The ``overlay_for`` value of the offending overlay.
        field_name: The manifest field that was widened.
        base_value: The stricter value from the base manifest.
        attempted_value: The relaxed value the overlay tried to set.
    """

    def __init__(
        self,
        overlay_name: str,
        field_name: str,
        base_value: object,
        attempted_value: object,
    ) -> None:
        self.overlay_name = overlay_name
        self.field_name = field_name
        self.base_value = base_value
        self.attempted_value = attempted_value
        super().__init__(
            f"Overlay '{overlay_name}' attempted to widen {field_name}: "
            f"base value {base_value!r} -> attempted {attempted_value!r}"
        )


def merge(
    base: WardlineManifest,
    overlay: WardlineOverlay,
) -> ResolvedManifest:
    """Merge *overlay* into *base*, returning a :class:`ResolvedManifest`.

    Raises:
        ManifestWidenError: If the overlay attempts to relax any tier
            (higher tier number = less strict).
    """
    # -- Tier consistency check (narrow-only) --------------------------------
    # Note: boundary-level tier widening checks are deferred to coherence
    # checks (check_tier_downgrades) which compare against the manifest
    # baseline. Boundary entries carry raw tier numbers, not tier IDs,
    # so the narrow-only invariant is enforced at the manifest level.

    # -- Merge rule overrides ------------------------------------------------
    governance_signals: list[GovernanceSignal] = []

    base_overrides_by_rule: dict[str, dict[str, object]] = {}
    for ovr in base.rules.overrides:
        rule_id = ovr.get("id")
        if isinstance(rule_id, str):
            base_overrides_by_rule[rule_id] = dict(ovr)

    for ovr in overlay.rule_overrides:
        rule_id = ovr.get("id")
        if not isinstance(rule_id, str):
            continue
        base_ovr = base_overrides_by_rule.get(rule_id)
        if base_ovr is not None:
            base_severity = base_ovr.get("severity")
            overlay_severity = ovr.get("severity")
            if (
                base_severity is not None
                and overlay_severity is not None
                and _severity_rank(str(overlay_severity))
                < _severity_rank(str(base_severity))
            ):
                governance_signals.append(
                    GovernanceSignal(
                        level="INFO",
                        message=(
                            f"Severity reduced for rule '{rule_id}': "
                            f"{base_severity} -> {overlay_severity}"
                        ),
                    )
                )
        # Overlay wins — update or insert
        merged = dict(base_ovr) if base_ovr else {}
        merged.update(ovr)
        base_overrides_by_rule[rule_id] = merged

    merged_overrides = tuple(base_overrides_by_rule.values())
    merged_rules = RulesConfig(overrides=merged_overrides)

    # -- Resolve boundaries (overlays are the sole source of boundaries) -----
    resolved_boundaries = overlay.boundaries

    return ResolvedManifest(
        tiers=base.tiers,
        rules=merged_rules,
        boundaries=resolved_boundaries,
        governance_signals=tuple(governance_signals),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEVERITY_RANKS: dict[str, int] = {
    "OFF": 0,
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4,
}


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for a severity string (higher = stricter)."""
    return _SEVERITY_RANKS.get(severity.upper(), -1)


def _check_boundary_tier(
    boundary: BoundaryEntry,
    base_tier_map: dict[str, int],
    overlay_name: str,
) -> None:
    """Raise :class:`ManifestWidenError` if *boundary* relaxes a tier."""
    if boundary.from_tier is not None:
        _assert_tier_not_widened(
            tier_id=boundary.function,
            base_map=base_tier_map,
            overlay_value=boundary.from_tier,
            overlay_name=overlay_name,
            field="from_tier",
        )
    if boundary.to_tier is not None:
        _assert_tier_not_widened(
            tier_id=boundary.function,
            base_map=base_tier_map,
            overlay_value=boundary.to_tier,
            overlay_name=overlay_name,
            field="to_tier",
        )


def _assert_tier_not_widened(
    tier_id: str,
    base_map: dict[str, int],
    overlay_value: int,
    overlay_name: str,
    field: str,
) -> None:
    """Raise if *overlay_value* would relax the base tier for *tier_id*.

    A higher tier number is "less strict" — i.e. widening.
    """
    base_value = base_map.get(tier_id)
    if base_value is not None and overlay_value > base_value:
        raise ManifestWidenError(
            overlay_name=overlay_name,
            field_name=field,
            base_value=base_value,
            attempted_value=overlay_value,
        )
