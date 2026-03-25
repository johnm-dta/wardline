"""Group 9-10 decorators — operation and failure-mode semantics."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "idempotent",
    "atomic",
    "compensatable",
    "fail_closed",
    "fail_open",
    "emits_or_explains",
    "exception_boundary",
    "must_propagate",
    "preserve_cause",
]

idempotent = wardline_decorator(9, "idempotent", _wardline_idempotent=True)

atomic = wardline_decorator(9, "atomic", _wardline_atomic=True)


def compensatable(*, rollback: object) -> object:
    """Mark a function as compensatable with a rollback target."""
    return wardline_decorator(
        9,
        "compensatable",
        _wardline_compensatable=True,
        _wardline_rollback=rollback,
    )

fail_closed = wardline_decorator(
    10,
    "fail_closed",
    _wardline_fail_closed=True,
)

fail_open = wardline_decorator(
    10,
    "fail_open",
    _wardline_fail_open=True,
)

emits_or_explains = wardline_decorator(
    10,
    "emits_or_explains",
    _wardline_emits_or_explains=True,
)

exception_boundary = wardline_decorator(
    10,
    "exception_boundary",
    _wardline_exception_boundary=True,
)

must_propagate = wardline_decorator(
    10,
    "must_propagate",
    _wardline_must_propagate=True,
)

preserve_cause = wardline_decorator(
    10,
    "preserve_cause",
    _wardline_preserve_cause=True,
)
