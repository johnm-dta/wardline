"""Runtime enforcement hooks — opt-in production monitoring.

All enforcement is behind the ``WARDLINE_ENFORCE`` flag. When disabled
(the default), these hooks are no-ops with zero overhead. Enable via:

    import wardline.runtime.enforcement
    wardline.runtime.enforcement.enable()

Or via environment variable::

    WARDLINE_ENFORCE=1

Enforcement checks:
- **Tier consistency:** ``WardlineBase`` subclasses with decorated methods
  are checked for tier consistency at class definition time (always on).
  With enforcement enabled, *instances* are also checked at construction.
- **ValidatedRecord conformance:** Objects passed to tier-typed parameters
  can be checked at runtime via ``check_validated_record(obj)``.
- **Tier transition auditing:** Tier boundary crossings are logged when
  enforcement is enabled.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ── Enforcement flag ──────────────────────────────────────────

_enforcement_enabled: bool = os.environ.get("WARDLINE_ENFORCE", "") == "1"


def is_enabled() -> bool:
    """Return True if runtime enforcement is active."""
    return _enforcement_enabled


def enable() -> None:
    """Enable runtime enforcement hooks."""
    global _enforcement_enabled  # noqa: PLW0603
    _enforcement_enabled = True
    logger.info("Wardline runtime enforcement enabled")


def disable() -> None:
    """Disable runtime enforcement hooks."""
    global _enforcement_enabled  # noqa: PLW0603
    _enforcement_enabled = False
    logger.info("Wardline runtime enforcement disabled")


# ── ValidatedRecord checks ────────────────────────────────────


class TierViolationError(TypeError):
    """Raised when a runtime tier check fails.

    Attributes:
        obj: The object that failed the check.
        expected_tier: The tier that was expected.
        actual_tier: The tier found on the object (or None if missing).
    """

    def __init__(
        self,
        message: str,
        *,
        obj: object = None,
        expected_tier: int | None = None,
        actual_tier: int | None = None,
    ) -> None:
        super().__init__(message)
        self.obj = obj
        self.expected_tier = expected_tier
        self.actual_tier = actual_tier


def check_validated_record(obj: Any) -> None:
    """Verify *obj* conforms to the ValidatedRecord protocol.

    Raises TierViolationError if the object lacks required attributes.
    No-op when enforcement is disabled.
    """
    if not _enforcement_enabled:
        return

    from wardline.runtime.protocols import ValidatedRecord

    if not isinstance(obj, ValidatedRecord):
        raise TierViolationError(
            f"{type(obj).__name__} does not conform to ValidatedRecord protocol "
            f"(missing _wardline_tier or _wardline_groups)",
            obj=obj,
        )


def check_tier_boundary(
    obj: Any,
    *,
    expected_min_tier: int,
    context: str = "",
) -> None:
    """Verify *obj* has a tier at least as trusted as *expected_min_tier*.

    A tier of 1 (AUDIT_TRAIL) is the most trusted; 4 (EXTERNAL_RAW) is
    least trusted. ``expected_min_tier=2`` means tier 1 or 2 are acceptable.

    Raises TierViolationError if the tier is insufficiently trusted.
    No-op when enforcement is disabled.
    """
    if not _enforcement_enabled:
        return

    tier = getattr(obj, "_wardline_tier", None)
    if tier is None:
        raise TierViolationError(
            f"{type(obj).__name__} has no _wardline_tier attribute"
            f"{f' (context: {context})' if context else ''}",
            obj=obj,
            expected_tier=expected_min_tier,
        )

    if not isinstance(tier, int) or tier > expected_min_tier:
        raise TierViolationError(
            f"{type(obj).__name__} has tier {tier}, expected <={expected_min_tier}"
            f"{f' (context: {context})' if context else ''}",
            obj=obj,
            expected_tier=expected_min_tier,
            actual_tier=tier if isinstance(tier, int) else None,
        )


# ── WardlineBase enforcement extension ────────────────────────


def check_subclass_tier_consistency(cls: type) -> list[str]:
    """Check tier consistency across decorated methods in a class.

    Returns a list of warning messages (empty if consistent).
    This runs at class definition time regardless of enforcement flag.
    """
    from wardline.core.registry import REGISTRY

    warnings: list[str] = []
    tier_groups: dict[int, list[str]] = {}

    for name, value in cls.__dict__.items():
        if name.startswith("_") and not name.startswith("__"):
            continue
        if not callable(value):
            continue

        groups = getattr(value, "_wardline_groups", None)
        if groups is None:
            continue

        # Find the tier from the decorator's registry entry
        for group_id in groups:
            for _entry_name, entry in REGISTRY.items():
                if entry.group == group_id:
                    tier = getattr(value, "_wardline_transition_from_tier", None)
                    if tier is not None:
                        tier_groups.setdefault(tier, []).append(name)

    # Check for mixed tiers (methods that span multiple trust levels)
    if len(tier_groups) > 1:
        tiers_str = ", ".join(
            f"tier {t}: {', '.join(methods)}"
            for t, methods in sorted(tier_groups.items())
        )
        warnings.append(
            f"{cls.__name__} has methods spanning multiple tiers: {tiers_str}"
        )

    return warnings


def enforce_construction(instance: object) -> None:
    """Runtime check at instance construction time.

    Called from ``WardlineBase.__init__`` when enforcement is enabled.
    Verifies that decorated methods on the instance's class have
    consistent tier annotations.
    """
    if not _enforcement_enabled:
        return

    warnings = check_subclass_tier_consistency(type(instance))
    for warning in warnings:
        logger.warning("Tier consistency: %s", warning)
