"""Group 9 decorators — Operational semantics.

These decorators mark functions with idempotency and retry-safety
metadata for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "idempotent",
    "retry_safe",
]

idempotent = wardline_decorator(
    9,
    "idempotent",
    _wardline_idempotent=True,
)

retry_safe = wardline_decorator(
    9,
    "retry_safe",
    _wardline_retry_safe=True,
)
