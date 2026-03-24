"""Canonical decorator registry — single source of truth for scanner + library."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.taints import TaintState

REGISTRY_VERSION = "0.1"


@dataclass(frozen=True)
class RegistryEntry:
    """A registered wardline decorator with its expected attributes.

    The `attrs` dict maps `_wardline_*` attribute names to their expected types.
    Deeply frozen via MappingProxyType to prevent post-construction mutation.

    Pass plain dicts at construction time — __post_init__ wraps them.
    """

    canonical_name: str
    group: int
    attrs: MappingProxyType[str, type]

    def __post_init__(self) -> None:
        # Frozen dataclass prevents direct assignment — use object.__setattr__
        # to wrap mutable dicts in MappingProxyType for deep immutability.
        object.__setattr__(
            self, "attrs", MappingProxyType(dict(self.attrs))
        )


def _bool_entry(name: str, group: int) -> RegistryEntry:
    """Build a RegistryEntry for a simple boolean-marker decorator."""
    return RegistryEntry(
        canonical_name=name,
        group=group,
        attrs={f"_wardline_{name}": bool},  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
    )


# Group 1: Authority Tier Flow (7 decorators)
# Group 2: Audit (1 decorator)
# These are the MVP-required decorators.
#
# Groups 3-14: Structural / operational decorators.
# Each is a simple boolean marker unless noted otherwise.
REGISTRY: MappingProxyType[str, RegistryEntry] = MappingProxyType({
    # --- Group 1: Authority Tier Flow ---
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary",
        group=1,
        attrs={"_wardline_tier_source": TaintState},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "validates_shape": RegistryEntry(
        canonical_name="validates_shape",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "validates_semantic": RegistryEntry(
        canonical_name="validates_semantic",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "validates_external": RegistryEntry(
        canonical_name="validates_external",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "tier1_read": RegistryEntry(
        canonical_name="tier1_read",
        group=1,
        attrs={"_wardline_tier_source": TaintState},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "audit_writer": RegistryEntry(
        canonical_name="audit_writer",
        group=1,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_tier_source": TaintState,
            "_wardline_audit_writer": bool,
        },
    ),
    "authoritative_construction": RegistryEntry(
        canonical_name="authoritative_construction",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    # --- Group 2: Audit ---
    "audit_critical": RegistryEntry(
        canonical_name="audit_critical",
        group=2,
        attrs={"_wardline_audit_critical": bool},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    # --- Group 3: Plugin ---
    "system_plugin": _bool_entry("system_plugin", 3),
    # --- Group 4: Internal Data Provenance ---
    "int_data": _bool_entry("int_data", 4),
    # --- Group 5: Schema ---
    "all_fields_mapped": _bool_entry("all_fields_mapped", 5),
    "output_schema": _bool_entry("output_schema", 5),
    # --- Group 6: Boundaries ---
    "trust_boundary": _bool_entry("trust_boundary", 6),
    "tier_transition": _bool_entry("tier_transition", 6),
    # --- Group 7: Safety ---
    "fail_safe": _bool_entry("fail_safe", 7),
    "fail_secure": _bool_entry("fail_secure", 7),
    "graceful_degradation": _bool_entry("graceful_degradation", 7),
    # --- Group 8: Secrets ---
    "handles_secrets": _bool_entry("handles_secrets", 8),
    "redacts_output": _bool_entry("redacts_output", 8),
    # --- Group 9: Operations ---
    "idempotent": _bool_entry("idempotent", 9),
    "retry_safe": _bool_entry("retry_safe", 9),
    # --- Group 10: Sensitivity ---
    "pii_handler": _bool_entry("pii_handler", 10),
    "phi_handler": _bool_entry("phi_handler", 10),
    "financial_data": _bool_entry("financial_data", 10),
    # --- Group 11: Determinism ---
    "deterministic": _bool_entry("deterministic", 11),
    "nondeterministic": _bool_entry("nondeterministic", 11),
    # --- Group 12: Concurrency ---
    "thread_safe": _bool_entry("thread_safe", 12),
    "process_safe": _bool_entry("process_safe", 12),
    # --- Group 13: Access ---
    "requires_auth": _bool_entry("requires_auth", 13),
    "requires_role": _bool_entry("requires_role", 13),
    # --- Group 14: Lifecycle ---
    "deprecated_boundary": _bool_entry("deprecated_boundary", 14),
    "experimental": _bool_entry("experimental", 14),
})
