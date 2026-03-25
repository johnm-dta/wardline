"""Group 12 decorators — Determinism."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "deterministic",
    "time_dependent",
]

deterministic = wardline_decorator(
    12,
    "deterministic",
    _wardline_deterministic=True,
)

time_dependent = wardline_decorator(
    12,
    "time_dependent",
    _wardline_time_dependent=True,
)
