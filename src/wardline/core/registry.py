"""Canonical decorator registry — single source of truth for scanner + library."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.taints import TaintState

REGISTRY_VERSION = "0.1"


@dataclass(frozen=True)
class RegistryEntry:
    """A registered wardline decorator with its expected attributes.

    The `args` dict maps parameter names to expected types (None = no type constraint).
    The `attrs` dict maps `_wardline_*` attribute names to their expected types.
    Both are deeply frozen via MappingProxyType to prevent post-construction mutation.

    Pass plain dicts at construction time — __post_init__ wraps them.
    """

    canonical_name: str
    group: int
    # Accept dicts at construction, wrapped to MappingProxyType in __post_init__
    args: MappingProxyType[str, type | None] | dict[str, type | None]
    attrs: MappingProxyType[str, type] | dict[str, type]

    def __post_init__(self) -> None:
        # Frozen dataclass prevents direct assignment — use object.__setattr__
        # to wrap mutable dicts in MappingProxyType for deep immutability.
        object.__setattr__(
            self, "args", MappingProxyType(dict(self.args))
        )
        object.__setattr__(
            self, "attrs", MappingProxyType(dict(self.attrs))
        )


# Group 1: Authority Tier Flow (7 decorators)
# Group 2: Audit (1 decorator)
# These are the MVP-required decorators.
REGISTRY: dict[str, RegistryEntry] = {
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary",
        group=1,
        args={},
        attrs={"_wardline_tier_source": TaintState},
    ),
    "validates_shape": RegistryEntry(
        canonical_name="validates_shape",
        group=1,
        args={},
        attrs={"_wardline_transition": tuple},
    ),
    "validates_semantic": RegistryEntry(
        canonical_name="validates_semantic",
        group=1,
        args={},
        attrs={"_wardline_transition": tuple},
    ),
    "validates_external": RegistryEntry(
        canonical_name="validates_external",
        group=1,
        args={},
        attrs={"_wardline_transition": tuple},
    ),
    "tier1_read": RegistryEntry(
        canonical_name="tier1_read",
        group=1,
        args={},
        attrs={"_wardline_tier_source": TaintState},
    ),
    "audit_writer": RegistryEntry(
        canonical_name="audit_writer",
        group=1,
        args={},
        attrs={
            "_wardline_tier_source": TaintState,
            "_wardline_audit_writer": bool,
        },
    ),
    "authoritative_construction": RegistryEntry(
        canonical_name="authoritative_construction",
        group=1,
        args={},
        attrs={"_wardline_transition": tuple},
    ),
    "audit_critical": RegistryEntry(
        canonical_name="audit_critical",
        group=2,
        args={},
        attrs={"_wardline_audit_critical": bool},
    ),
}
