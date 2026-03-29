"""AuthoritativeField — descriptor enforcing access-after-set semantics.

An ``AuthoritativeField`` is a data descriptor that raises
``AuthoritativeAccessError`` if the field is read before it has been
explicitly set on the instance. This prevents code from silently
consuming uninitialized or default values for fields that must be
populated by an authoritative source.

Storage uses the instance ``__dict__`` with a ``_wd_auth_`` prefix to
avoid collision with regular attributes::

    class Order(WardlineBase):
        total = AuthoritativeField()

    o = Order()
    o.total        # raises AuthoritativeAccessError
    o.total = 42
    o.total        # returns 42

**Known residual:** Direct ``__dict__`` writes bypass the descriptor.
This is a Python language-level limitation, not a wardline bug.
"""

from __future__ import annotations

from typing import Any


class AuthoritativeAccessError(AttributeError):
    """Raised when an AuthoritativeField is read before being set.

    Subclasses ``AttributeError`` so that ``hasattr()`` returns
    ``False`` for unset authoritative fields — consistent with Python's
    descriptor protocol semantics.
    """


class AuthoritativeField:
    """Descriptor enforcing access-after-set for authoritative data fields.

    Uses ``__set_name__`` for automatic name detection. The backing
    storage key is ``_wd_auth_{name}`` in the instance ``__dict__``.
    """

    __slots__ = ("name", "storage_name")

    def __init__(self, *, name: str | None = None) -> None:
        # Allow pre-setting the name for dynamic assignment via setattr().
        # When used in a class body, __set_name__ overwrites these.
        if name is not None:
            self.name = name
            self.storage_name = f"_wd_auth_{name}"

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name
        # Include owner class name to prevent subclass field collisions:
        # without it, a subclass field with the same name shares the
        # storage key with the parent class.
        self.storage_name = f"_wd_auth_{owner.__name__}_{name}"

    def __get__(self, obj: Any, objtype: type | None = None) -> Any:
        if obj is None:
            # Class-level access returns the descriptor itself
            return self
        try:
            _ = self.storage_name
        except AttributeError:
            raise AuthoritativeAccessError(
                "AuthoritativeField has no name — was it dynamically assigned "
                "without passing name= to __init__?"
            ) from None
        try:
            return obj.__dict__[self.storage_name]
        except KeyError:
            raise AuthoritativeAccessError(
                f"AuthoritativeField '{self.name}' on "
                f"{type(obj).__name__} has not been set"
            ) from None

    def __set__(self, obj: Any, value: Any) -> None:
        obj.__dict__[self.storage_name] = value
