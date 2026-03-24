"""ValidatedRecord Protocol — structural interface for tier-validated data.

A ``ValidatedRecord`` is any object that carries wardline validation
metadata. It is a ``@runtime_checkable`` Protocol so both static type
checkers and runtime ``isinstance`` checks work::

    from wardline.runtime.protocols import ValidatedRecord

    def process(record: ValidatedRecord) -> None:
        assert record._wardline_tier >= 1
        ...

This is independent of the scanner — it is a runtime contract that
user code can check at development time or in production (behind an
opt-in flag, per WP 3.2).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ValidatedRecord(Protocol):
    """Structural protocol for objects carrying wardline tier metadata.

    Any object with these attributes satisfies the protocol — no
    inheritance required. This enables duck-typed tier checking across
    codebases that use wardline decorators.

    Note: ``@property`` in this Protocol is notation only. Plain attributes
    set via ``setattr`` or dataclass fields (as in ``TierStamped``) satisfy
    the ``runtime_checkable`` ``isinstance`` check.
    """

    @property
    def _wardline_tier(self) -> int:
        """Authority tier level (1-4) assigned to this record."""
        ...

    @property
    def _wardline_groups(self) -> tuple[int, ...]:
        """Wardline annotation group memberships."""
        ...
