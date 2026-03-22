"""Group 2 decorators — Audit.

These decorators mark functions with audit-related metadata
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "audit_critical",
]

audit_critical = wardline_decorator(
    2,
    "audit_critical",
    _wardline_audit_critical=True,
)
