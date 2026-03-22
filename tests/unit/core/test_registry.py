"""Tests for canonical decorator registry."""

import pytest

from wardline.core.registry import REGISTRY, REGISTRY_VERSION, RegistryEntry


def test_registry_version_present() -> None:
    assert isinstance(REGISTRY_VERSION, str)
    assert len(REGISTRY_VERSION) > 0


def test_registry_has_all_group1_decorators() -> None:
    """All 7 Group 1 decorators must be registered."""
    group1_names = {
        "external_boundary",
        "validates_shape",
        "validates_semantic",
        "validates_external",
        "tier1_read",
        "audit_writer",
        "authoritative_construction",
    }
    registered = {name for name, entry in REGISTRY.items() if entry.group == 1}
    assert registered == group1_names


def test_registry_has_group2_decorator() -> None:
    """Group 2 audit_critical must be registered."""
    assert "audit_critical" in REGISTRY
    assert REGISTRY["audit_critical"].group == 2


def test_total_mvp_count() -> None:
    """8 decorators total (7 Group 1 + 1 Group 2)."""
    assert len(REGISTRY) == 8


def test_entry_immutability_args() -> None:
    """args dict is wrapped in MappingProxyType — mutation raises TypeError."""
    entry = REGISTRY["external_boundary"]
    with pytest.raises(TypeError):
        entry.args["new_arg"] = str  # type: ignore[index]


def test_entry_immutability_attrs() -> None:
    """attrs dict is wrapped in MappingProxyType — mutation raises TypeError."""
    entry = REGISTRY["external_boundary"]
    with pytest.raises(TypeError):
        entry.attrs["_wardline_new"] = bool  # type: ignore[index]


def test_entry_frozen() -> None:
    """RegistryEntry is a frozen dataclass — attribute assignment raises."""
    entry = REGISTRY["external_boundary"]
    with pytest.raises(AttributeError):
        entry.canonical_name = "hacked"  # type: ignore[misc]


def test_canonical_name_matches_key() -> None:
    """Every entry's canonical_name must match its dict key."""
    for name, entry in REGISTRY.items():
        assert entry.canonical_name == name


def test_all_entries_have_attrs() -> None:
    """Every entry must have at least one _wardline_* attribute."""
    for name, entry in REGISTRY.items():
        assert len(entry.attrs) > 0, f"{name} has no attrs"
        for attr_name in entry.attrs:
            assert attr_name.startswith("_wardline_"), (
                f"{name} has non-wardline attr: {attr_name}"
            )
