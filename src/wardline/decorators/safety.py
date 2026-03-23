"""Group 7 decorators — Safety.

These decorators mark functions with failure-mode semantics
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "fail_safe",
    "fail_secure",
    "graceful_degradation",
]

fail_safe = wardline_decorator(
    7,
    "fail_safe",
    _wardline_fail_safe=True,
)

fail_secure = wardline_decorator(
    7,
    "fail_secure",
    _wardline_fail_secure=True,
)

graceful_degradation = wardline_decorator(
    7,
    "graceful_degradation",
    _wardline_graceful_degradation=True,
)
