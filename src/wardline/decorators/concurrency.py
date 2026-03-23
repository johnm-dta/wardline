"""Group 12 decorators — Concurrency safety.

These decorators mark functions with concurrency-safety metadata
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "process_safe",
    "thread_safe",
]

thread_safe = wardline_decorator(
    12,
    "thread_safe",
    _wardline_thread_safe=True,
)

process_safe = wardline_decorator(
    12,
    "process_safe",
    _wardline_process_safe=True,
)
