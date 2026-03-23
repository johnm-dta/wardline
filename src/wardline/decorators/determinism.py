"""Group 11 decorators — Determinism.

These decorators mark functions with determinism metadata
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "deterministic",
    "nondeterministic",
]

deterministic = wardline_decorator(
    11,
    "deterministic",
    _wardline_deterministic=True,
)

nondeterministic = wardline_decorator(
    11,
    "nondeterministic",
    _wardline_nondeterministic=True,
)
