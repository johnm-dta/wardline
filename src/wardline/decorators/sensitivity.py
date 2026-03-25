"""Group 11 decorators — Data sensitivity."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "handles_pii",
    "handles_classified",
    "declassifies",
]


def handles_pii(*, fields: list[str] | tuple[str, ...]) -> object:
    """Mark a callable as handling named PII fields."""
    return wardline_decorator(
        11,
        "handles_pii",
        _wardline_handles_pii=True,
        _wardline_pii_fields=tuple(fields),
    )


def handles_classified(*, level: str) -> object:
    """Mark a callable as handling classified data at a given level."""
    return wardline_decorator(
        11,
        "handles_classified",
        _wardline_handles_classified=True,
        _wardline_classification_level=level,
    )


def declassifies(*, from_level: str, to_level: str) -> object:
    """Mark a callable as declassifying from one level to another."""
    return wardline_decorator(
        11,
        "declassifies",
        _wardline_declassifies=True,
        _wardline_from_level=from_level,
        _wardline_to_level=to_level,
    )
