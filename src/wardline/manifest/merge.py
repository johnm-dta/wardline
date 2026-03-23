"""Overlay merge — combine a base manifest with an overlay.

Enforces the narrow-only invariant: overlays may tighten tiers but never
relax them.  Severity reduction (e.g. ERROR -> WARNING) raises
:class:`ManifestWidenError` — an overlay CANNOT lower severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wardline.manifest.models import (
    BoundaryEntry,
    ModuleTierEntry,
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
                raise ManifestWidenError(
                    overlay_name=overlay.overlay_for,
                    field_name="severity",
                    base_value=base_severity,
                    attempted_value=overlay_severity,
                )
        # Overlay wins — update or insert.
        # NOTE: narrow-only semantics — the overlay can add or tighten fields
        # but can never *remove* a field present in the base override.  This is
        # intentional: overlays are additive refinements.  To "undo" a base
        # field, the base manifest itself must be changed.
        merged = dict(base_ovr) if base_ovr else {}
        merged.update(ovr)
        base_overrides_by_rule[rule_id] = merged

    merged_overrides = tuple(base_overrides_by_rule.values())
    merged_rules = RulesConfig(overrides=merged_overrides)

    # -- Resolve boundaries (overlays are the sole source of boundaries) -----
    resolved_boundaries = overlay.boundaries

    # -- Boundary-level narrow-only check -----------------------------------
    tier_number_map: dict[str, int] = {t.id: t.tier for t in base.tiers}
    module_tier = _resolve_module_tier(
        overlay.overlay_for, base.module_tiers, tier_number_map
    )
    if module_tier is not None:
        for boundary in resolved_boundaries:
            if boundary.from_tier is not None and boundary.from_tier > module_tier:
                raise ManifestWidenError(
                    overlay_name=overlay.overlay_for,
                    field_name="from_tier",
                    base_value=module_tier,
                    attempted_value=boundary.from_tier,
                )
            if boundary.to_tier is not None and boundary.to_tier > module_tier:
                raise ManifestWidenError(
                    overlay_name=overlay.overlay_for,
                    field_name="to_tier",
                    base_value=module_tier,
                    attempted_value=boundary.to_tier,
                )

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


def _resolve_module_tier(
    overlay_scope: str,
    module_tiers: tuple[ModuleTierEntry, ...],
    tier_number_map: dict[str, int],
) -> int | None:
    """Resolve the module tier for a boundary's overlay scope via longest prefix.

    Uses path-segment-safe prefix matching (requires separator after prefix).
    Returns the tier number, or None if no module tier covers the overlay scope.
    """
    best_match: int | None = None
    best_length = -1

    for mt in module_tiers:
        if (
            overlay_scope == mt.path
            or overlay_scope.startswith(mt.path + "/")
        ) and len(mt.path) > best_length:
            tier_num = tier_number_map.get(mt.default_taint)
            if tier_num is not None:
                best_match = tier_num
                best_length = len(mt.path)

    return best_match
