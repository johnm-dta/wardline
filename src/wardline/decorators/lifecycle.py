"""Group 14 decorators — Lifecycle.

These decorators mark functions with lifecycle metadata
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "deprecated_boundary",
    "experimental",
]

deprecated_boundary = wardline_decorator(
    14,
    "deprecated_boundary",
    _wardline_deprecated_boundary=True,
)

experimental = wardline_decorator(
    14,
    "experimental",
    _wardline_experimental=True,
)
