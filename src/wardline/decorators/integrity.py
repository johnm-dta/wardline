"""Group 2 decorators — Audit.

These decorators mark functions with audit-related metadata
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "integrity_critical",
]

integrity_critical = wardline_decorator(
    2,
    "integrity_critical",
    _wardline_integrity_critical=True,
)
