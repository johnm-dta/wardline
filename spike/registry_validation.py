"""Registry contract validation — tracer bullet.

Proves that the registry structure supports the T-2.1 decorator factory
assertion pattern: given a decorator name and semantic attrs, the factory
can validate that (a) the name exists in the registry and (b) all attr
keys are present in the entry's attrs contract.
"""

from __future__ import annotations

from wardline.core.registry import REGISTRY, RegistryEntry


def validate_registry_lookup(name: str) -> RegistryEntry:
    """Look up a decorator by canonical name. Raises KeyError if not found."""
    return REGISTRY[name]


def validate_factory_assertion(name: str, semantic_attrs: dict[str, object]) -> None:
    """Simulate the T-2.1 factory assertion pattern.

    The decorator factory will:
    1. Assert `name` exists in REGISTRY
    2. Assert all keys in `semantic_attrs` are declared in the entry's `attrs` contract

    This function proves the registry structure supports both checks.
    Raises KeyError for unknown name, ValueError for undeclared attrs.
    """
    entry = REGISTRY[name]  # Step 1: name must exist

    # Step 2: all semantic attr keys must be in the entry's attrs contract
    allowed_attrs = set(entry.attrs.keys())
    provided_attrs = set(semantic_attrs.keys())
    undeclared = provided_attrs - allowed_attrs

    if undeclared:
        raise ValueError(
            f"Decorator '{name}' does not declare attrs: {undeclared}. "
            f"Allowed: {allowed_attrs}"
        )
