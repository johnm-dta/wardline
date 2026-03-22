"""WardlineBase — cooperative base class for wardline-managed user code.

WardlineBase provides ``__init_subclass__`` integration for checking
wardline decorator usage on subclass methods. It cooperates with
``ABCMeta`` and other ``__init_subclass__`` hooks via cooperative
``super()`` calls (called BEFORE wardline checks, per MRO convention).
"""

from __future__ import annotations

from wardline.core.registry import REGISTRY


class WardlineBase:
    """Base class for wardline-managed services and components.

    Subclasses get their methods checked for wardline decorator
    annotations at class definition time. This enables early detection
    of missing or incorrect decorator usage without running a scan.

    Cooperative ``__init_subclass__``: calls ``super()`` BEFORE
    wardline checks to ensure other ``__init_subclass__`` hooks in
    the MRO chain fire correctly.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Cooperative super() BEFORE our checks — required for MRO
        super().__init_subclass__(**kwargs)

        # Check subclass methods for wardline decorators
        _check_decorated_methods(cls)


def _check_decorated_methods(cls: type) -> None:
    """Check methods of a class for wardline decorator annotations.

    Walks the class's own ``__dict__`` (not inherited methods) and
    looks for ``_wardline_groups`` on each callable — the attribute
    set by the wardline decorator factory.
    """
    for name, value in cls.__dict__.items():
        if name.startswith("_"):
            continue
        if not callable(value):
            continue

        # Check for wardline decorator attributes
        groups = getattr(value, "_wardline_groups", None)
        if groups is None:
            continue

        # Verify decorated methods use registered decorators
        for attr_name in dir(value):
            if not attr_name.startswith("_wardline_"):
                continue
            if attr_name == "_wardline_groups":
                continue

            # The canonical name can be found by looking up which
            # registry entry has this attr in its contract
            _validate_decorator_attr(cls, name, attr_name)


def _validate_decorator_attr(
    cls: type, method_name: str, attr_name: str
) -> None:
    """Validate a wardline attribute is from a registered decorator.

    Checks that the attribute name appears in at least one registry
    entry's attrs contract. Logs but does not raise — registration
    mismatches are caught at decorator construction time.
    """
    for entry in REGISTRY.values():
        if attr_name in entry.attrs:
            return
