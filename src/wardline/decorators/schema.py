"""Group 2 utilities — Schema markers.

Provides ``schema_default(expr)`` — a presence-only marker that the
scanner can detect at call sites.  For MVP it is an identity function:
it returns its argument unchanged but signals that the call site has an
explicit schema default.
"""

from __future__ import annotations


def schema_default[T](expr: T) -> T:
    """Mark *expr* as an explicit schema default.

    Returns *expr* unchanged.  The wardline scanner detects calls to this
    function to verify that schema defaults are explicitly annotated.
    """
    return expr
