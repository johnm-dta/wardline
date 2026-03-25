"""Group 7 decorators — Template safety."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "parse_at_init",
]

parse_at_init = wardline_decorator(
    7,
    "parse_at_init",
    _wardline_parse_at_init=True,
)
