"""Decorator factory — creates wardline decorators from registry entries."""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any

from wardline.core.registry import REGISTRY

logger = logging.getLogger(__name__)


def wardline_decorator(
    group: int,
    name: str,
    **semantic_attrs: Any,
) -> Any:
    """Create a wardline decorator that marks functions with metadata.

    Args:
        group: Decorator group number (1=authority, 2=audit).
        name: Canonical decorator name (must be in REGISTRY).
        **semantic_attrs: Semantic attributes to set on the wrapper.
            Keys must match the registry entry's attrs contract.
    """
    # Registry enforcement
    if name not in REGISTRY:
        raise ValueError(
            f"Unknown decorator '{name}' — not in wardline registry"
        )

    entry = REGISTRY[name]
    for key in semantic_attrs:
        attr_key = f"_wardline_{key}" if not key.startswith("_wardline_") else key
        # Check against entry.attrs contract
        if attr_key not in entry.attrs:
            raise ValueError(
                f"Unknown attribute '{key}' for decorator '{name}'. "
                f"Allowed: {sorted(entry.attrs.keys())}"
            )

    def decorator(fn: Any) -> Any:
        # Handle staticmethod/classmethod — unwrap before applying.
        # Known limitation: callable() on descriptors that carry _wardline_*
        # attributes (e.g. AuthoritativeField instances) may return True even
        # though the descriptor is not intended to be decorated.  The
        # isinstance checks below cover the known descriptor types
        # (staticmethod, classmethod).  Arbitrary third-party descriptors
        # that happen to be callable are not guarded against — this is
        # accepted as a very unlikely edge case.
        unwrapped = fn
        wrapper_type: type | None = None
        if isinstance(fn, staticmethod):
            unwrapped = fn.__func__
            wrapper_type = staticmethod
        elif isinstance(fn, classmethod):
            unwrapped = fn.__func__
            wrapper_type = classmethod

        if inspect.iscoroutinefunction(unwrapped):
            @functools.wraps(unwrapped)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                return await unwrapped(*args, **kwargs)
        else:
            @functools.wraps(unwrapped)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return unwrapped(*args, **kwargs)

        # CRITICAL: set _wardline_groups AFTER functools.wraps()
        # Copy-on-accumulate: don't mutate inner decorator's set
        wrapper._wardline_groups = set(  # type: ignore[attr-defined]
            getattr(wrapper, "_wardline_groups", set())
        )
        wrapper._wardline_groups.add(group)  # type: ignore[attr-defined]

        # Set semantic attributes
        for key, value in semantic_attrs.items():
            attr_name = (
                f"_wardline_{key}" if not key.startswith("_wardline_") else key
            )
            setattr(wrapper, attr_name, value)

        # Re-wrap if staticmethod/classmethod
        if wrapper_type is not None:
            return wrapper_type(wrapper)

        return wrapper

    return decorator


def get_wardline_attrs(fn: Any) -> dict[str, Any] | None:
    """Walk __wrapped__ chain to collect all wardline attributes.

    Returns dict of _wardline_* attributes, or None if chain is severed.
    """
    attrs: dict[str, Any] = {}
    current = fn
    seen: set[int] = set()

    while current is not None:
        if id(current) in seen:
            break
        seen.add(id(current))

        # Collect wardline attrs from current level only (not inherited via MRO).
        # Use vars() when available; fall back to dir() for objects without __dict__.
        try:
            current_keys = vars(current)
        except TypeError:
            current_keys = dir(current)
        for key in current_keys:
            if key.startswith("_wardline_") and key not in attrs:
                attrs[key] = getattr(current, key)

        # Follow __wrapped__ chain
        next_fn = getattr(current, "__wrapped__", None)
        if next_fn is None:
            # Only warn about severed chains when the wrapping function
            # is actually a wardline decorator (has _wardline_ attrs).
            # Third-party decorators also set __wrapped__ and should not
            # trigger this warning.
            if (
                current is not fn
                and not attrs
                and any(k.startswith("_wardline_") for k in vars(fn))
            ):
                logger.warning(
                    "Severed __wrapped__ chain on %s — "
                    "wardline attributes may be lost",
                    getattr(fn, "__name__", repr(fn)),
                )
                return None
            break
        current = next_fn

    return attrs if attrs else None
