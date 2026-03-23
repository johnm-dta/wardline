"""Group 13 decorators — Access control.

These decorators mark functions with access-control requirements
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "requires_auth",
    "requires_role",
]

requires_auth = wardline_decorator(
    13,
    "requires_auth",
    _wardline_requires_auth=True,
)

requires_role = wardline_decorator(
    13,
    "requires_role",
    _wardline_requires_role=True,
)
