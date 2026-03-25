"""Group 13 decorators — Concurrency and ordering."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "thread_safe",
    "ordered_after",
    "not_reentrant",
]

thread_safe = wardline_decorator(
    13,
    "thread_safe",
    _wardline_thread_safe=True,
)


def ordered_after(name: str) -> object:
    """Mark a function as ordered after another named function."""
    return wardline_decorator(
        13,
        "ordered_after",
        _wardline_ordered_after=name,
    )


not_reentrant = wardline_decorator(
    13,
    "not_reentrant",
    _wardline_not_reentrant=True,
)
