"""Schema markers — utility function + Group 5 decorators.

Provides ``schema_default(expr)`` — a presence-only marker that the
scanner can detect at call sites.  It is an identity function: it
returns its argument unchanged but signals that the call site has an
explicit schema default.

Group 5 decorators mark functions with schema-completeness metadata.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "all_fields_mapped",
    "output_schema",
    "schema_default",
]


def schema_default[T](expr: T) -> T:
    """Mark *expr* as an explicit schema default.

    Returns *expr* unchanged.  The wardline scanner detects calls to this
    function to verify that schema defaults are explicitly annotated.
    """
    return expr


all_fields_mapped = wardline_decorator(
    5,
    "all_fields_mapped",
    _wardline_all_fields_mapped=True,
)

output_schema = wardline_decorator(
    5,
    "output_schema",
    _wardline_output_schema=True,
)
