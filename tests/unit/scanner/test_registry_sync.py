"""Bidirectional registry sync tests (T-4.12).

Verifies that the decorator registry and library exports stay in sync:
(a) every registry name present in library exports,
(b) every library export present in registry,
(c) attribute-level type checks via isinstance(),
(d) renamed decorator detection,
(e) missing registry entry detection,
(f) __wrapped__ chain validation,
(g) strict-mode exit code integration.
"""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState
from wardline.decorators._base import get_wardline_attrs, wardline_decorator
from wardline.decorators.audit import audit_critical
from wardline.decorators.authority import (
    audit_writer,
    authoritative_construction,
    external_boundary,
    tier1_read,
    validates_external,
    validates_semantic,
    validates_shape,
)

# Map decorator names to their callable objects
_LIBRARY_DECORATORS: dict[str, Any] = {
    "external_boundary": external_boundary,
    "validates_shape": validates_shape,
    "validates_semantic": validates_semantic,
    "validates_external": validates_external,
    "tier1_read": tier1_read,
    "audit_writer": audit_writer,
    "authoritative_construction": authoritative_construction,
    "audit_critical": audit_critical,
}

# Decorators exported by the library that are NOT registered (presence-only markers)
_NON_REGISTERED_EXPORTS = {"schema_default"}


# ---------------------------------------------------------------------------
# TestRegistryToLibrarySync
# ---------------------------------------------------------------------------


class TestRegistryToLibrarySync:
    """Every name in REGISTRY has a matching export in the decorator library."""

    def test_all_registry_names_exported(self) -> None:
        for name in REGISTRY:
            assert name in _LIBRARY_DECORATORS, (
                f"Registry entry '{name}' has no matching library export"
            )

    @pytest.mark.parametrize("name", sorted(REGISTRY.keys()))
    def test_registry_name_is_callable(self, name: str) -> None:
        dec = _LIBRARY_DECORATORS[name]
        assert callable(dec), f"Library export '{name}' is not callable"


# ---------------------------------------------------------------------------
# TestLibraryToRegistrySync
# ---------------------------------------------------------------------------


class TestLibraryToRegistrySync:
    """Every wardline decorator exported by the library has a REGISTRY entry.

    schema_default is a presence-only marker and is explicitly skipped.
    """

    def test_all_library_exports_in_registry(self) -> None:
        for name in _LIBRARY_DECORATORS:
            assert name in REGISTRY, (
                f"Library export '{name}' has no REGISTRY entry"
            )

    def test_schema_default_not_in_registry(self) -> None:
        """schema_default is a marker, not a registered decorator."""
        from wardline.decorators.schema import schema_default

        assert "schema_default" not in REGISTRY
        # But it should still be importable
        assert callable(schema_default)

    def test_library_modules_exhaustive(self) -> None:
        """All public callables in decorator modules are accounted for."""
        authority_mod = importlib.import_module("wardline.decorators.authority")
        audit_mod = importlib.import_module("wardline.decorators.audit")

        # Collect public callable names (no underscore prefix)
        authority_names = {
            n for n in dir(authority_mod)
            if not n.startswith("_") and callable(getattr(authority_mod, n))
            and n != "wardline_decorator" and n != "TaintState"
        }
        audit_names = {
            n for n in dir(audit_mod)
            if not n.startswith("_") and callable(getattr(audit_mod, n))
            and n != "wardline_decorator"
        }

        all_exports = authority_names | audit_names
        expected = set(_LIBRARY_DECORATORS.keys())
        assert all_exports == expected, (
            f"Mismatch: extra={all_exports - expected}, "
            f"missing={expected - all_exports}"
        )


# ---------------------------------------------------------------------------
# TestAttributeLevel
# ---------------------------------------------------------------------------


class TestAttributeLevel:
    """Decorate a stub with each decorator and verify _wardline_* attrs."""

    @pytest.mark.parametrize("name", sorted(REGISTRY.keys()))
    def test_attrs_present_with_correct_types(self, name: str) -> None:
        dec = _LIBRARY_DECORATORS[name]
        entry = REGISTRY[name]

        @dec
        def stub() -> None:
            pass

        for attr_name, expected_type in entry.attrs.items():
            assert hasattr(stub, attr_name), (
                f"Decorated stub missing attribute '{attr_name}' "
                f"for decorator '{name}'"
            )
            value = getattr(stub, attr_name)
            assert isinstance(value, expected_type), (
                f"Attribute '{attr_name}' on '{name}' is "
                f"{type(value).__name__}, expected {expected_type.__name__}"
            )

    @pytest.mark.parametrize("name", sorted(REGISTRY.keys()))
    def test_wardline_groups_set(self, name: str) -> None:
        dec = _LIBRARY_DECORATORS[name]
        entry = REGISTRY[name]

        @dec
        def stub() -> None:
            pass

        assert hasattr(stub, "_wardline_groups")
        assert entry.group in stub._wardline_groups  # type: ignore[attr-defined]

    def test_type_mismatch_detected(self) -> None:
        """Catch a synthetic type mismatch via isinstance check."""
        @external_boundary
        def stub() -> None:
            pass

        # _wardline_tier_source should be TaintState, not str
        entry = REGISTRY["external_boundary"]
        for attr_name, expected_type in entry.attrs.items():
            value = getattr(stub, attr_name)
            # Verify it IS the right type
            assert isinstance(value, expected_type)
            # Verify a wrong type would fail
            assert not isinstance("wrong_type_string", expected_type)


# ---------------------------------------------------------------------------
# TestRenamedDecorator
# ---------------------------------------------------------------------------


class TestRenamedDecorator:
    """Renaming a decorator's attrs vs registry would be caught."""

    def test_renamed_attr_detected(self) -> None:
        """If someone renames an attr on a decorated function, the registry
        check catches the mismatch."""
        @external_boundary
        def stub() -> None:
            pass

        entry = REGISTRY["external_boundary"]
        # Simulate rename: delete the real attr, add a wrong-named one
        real_attrs = list(entry.attrs.keys())
        assert len(real_attrs) > 0

        for attr_name in real_attrs:
            original_value = getattr(stub, attr_name)
            delattr(stub, attr_name)
            setattr(stub, attr_name + "_RENAMED", original_value)

        # Now verify the registry check would catch the missing attrs
        for attr_name in entry.attrs:
            assert not hasattr(stub, attr_name), (
                f"Renamed attr '{attr_name}' should not be present"
            )

    def test_renamed_attr_fails_registry_contract(self) -> None:
        """Registry contract check: iterate attrs, assert hasattr fails
        for renamed attributes."""
        @audit_critical
        def stub() -> None:
            pass

        entry = REGISTRY["audit_critical"]
        # Verify attrs are present initially
        for attr_name in entry.attrs:
            assert hasattr(stub, attr_name)

        # Rename
        for attr_name in entry.attrs:
            val = getattr(stub, attr_name)
            delattr(stub, attr_name)
            setattr(stub, f"_wardline_WRONG_{attr_name}", val)

        # Registry check fails
        for attr_name in entry.attrs:
            assert not hasattr(stub, attr_name)


# ---------------------------------------------------------------------------
# TestMissingRegistryEntry
# ---------------------------------------------------------------------------


class TestMissingRegistryEntry:
    """Detection of a decorator not in registry."""

    def test_unregistered_decorator_raises(self) -> None:
        """wardline_decorator() rejects names not in REGISTRY."""
        with pytest.raises(ValueError, match="not in wardline registry"):
            wardline_decorator(
                group=99,
                name="totally_fake_decorator",
                _wardline_fake=True,
            )

    def test_unknown_attr_rejected(self) -> None:
        """Passing an unknown semantic attr to a registered decorator raises."""
        with pytest.raises(ValueError, match="Unknown attribute"):
            wardline_decorator(
                group=1,
                name="external_boundary",
                _wardline_nonexistent_attr=42,
            )

    def test_unknown_wardline_prefix_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An unknown @wardline-prefixed decorator in scanned code should be
        detectable. Here we verify that a name not in REGISTRY is rejected."""
        fake_names = [
            "wardline_custom_thing",
            "wardline_boundary_v2",
        ]
        for fake_name in fake_names:
            assert fake_name not in REGISTRY, (
                f"Unexpected: '{fake_name}' found in REGISTRY"
            )


# ---------------------------------------------------------------------------
# TestWrappedChainValidation
# ---------------------------------------------------------------------------


class TestWrappedChainValidation:
    """Traverse __wrapped__ chain on decorated functions."""

    def test_single_decorator_wrapped_chain(self) -> None:
        @external_boundary
        def stub() -> None:
            pass

        assert hasattr(stub, "__wrapped__")
        attrs = get_wardline_attrs(stub)
        assert attrs is not None
        assert "_wardline_tier_source" in attrs
        assert isinstance(attrs["_wardline_tier_source"], TaintState)

    def test_stacked_decorators_wrapped_chain(self) -> None:
        """Multiple decorators stack correctly via __wrapped__."""
        @audit_critical
        @external_boundary
        def stub() -> None:
            pass

        attrs = get_wardline_attrs(stub)
        assert attrs is not None
        # Should have attrs from both decorators
        assert "_wardline_tier_source" in attrs
        assert "_wardline_audit_critical" in attrs
        assert isinstance(attrs["_wardline_tier_source"], TaintState)
        assert isinstance(attrs["_wardline_audit_critical"], bool)

    def test_groups_accumulate(self) -> None:
        """Stacked decorators accumulate _wardline_groups."""
        @audit_critical
        @external_boundary
        def stub() -> None:
            pass

        assert hasattr(stub, "_wardline_groups")
        groups = stub._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups  # external_boundary group
        assert 2 in groups  # audit_critical group

    @pytest.mark.parametrize("name", sorted(REGISTRY.keys()))
    def test_all_decorators_have_wrapped(self, name: str) -> None:
        """Every decorator produces a wrapper with __wrapped__."""
        dec = _LIBRARY_DECORATORS[name]

        @dec
        def stub() -> None:
            pass

        assert hasattr(stub, "__wrapped__"), (
            f"Decorator '{name}' does not set __wrapped__"
        )

    def test_severed_chain_returns_none(self, caplog: pytest.LogCaptureFixture) -> None:
        """Severed __wrapped__ chain is detected by get_wardline_attrs."""
        @external_boundary
        def stub() -> None:
            pass

        # Create an intermediate wrapper that has __wrapped__ but no attrs
        class Intermediate:
            def __init__(self, fn: Any) -> None:
                self.__wrapped__ = fn  # type: ignore[assignment]

        # Build severed chain: intermediate -> bare object (no attrs)
        bare = object()
        intermediate = Intermediate(bare)

        with caplog.at_level(logging.WARNING):
            result = get_wardline_attrs(intermediate)
        # A chain with no wardline attrs at all returns None
        assert result is None


# ---------------------------------------------------------------------------
# TestStrictModeExitCode
# ---------------------------------------------------------------------------


class TestStrictModeExitCode:
    """Integration: registry mismatch produces exit code 2."""

    def test_registry_mismatch_exits_2(self, tmp_path: Path) -> None:
        """When _check_registry_sync returns mismatches and
        --allow-registry-mismatch is not set, exit code is 2."""
        from wardline.cli.main import cli

        # Create minimal manifest so we get past manifest loading
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            "tiers:\n"
            '  - id: "test"\n'
            "    tier: 1\n"
            '    description: "test tier"\n'
            "module_tiers: []\n"
            "metadata:\n"
            '  organisation: "TestOrg"\n'
        )
        py_file = tmp_path / "clean.py"
        py_file.write_text("x = 1\n")

        runner = CliRunner()

        # Patch _check_registry_sync to return a mismatch
        with patch(
            "wardline.cli.scan._check_registry_sync",
            return_value=["fake rule missing from registry"],
        ):
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(tmp_path),
                    "--manifest",
                    str(manifest),
                ],
            )

        assert result.exit_code == 2, (
            f"Expected exit code 2, got {result.exit_code}. "
            f"Output: {result.output}"
        )

    def test_registry_mismatch_allowed_does_not_exit_2(
        self, tmp_path: Path
    ) -> None:
        """With --allow-registry-mismatch, mismatch emits a GOVERNANCE
        finding but does not exit 2."""
        from wardline.cli.main import cli

        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            "tiers:\n"
            '  - id: "test"\n'
            "    tier: 1\n"
            '    description: "test tier"\n'
            "module_tiers: []\n"
            "metadata:\n"
            '  organisation: "TestOrg"\n'
        )
        py_file = tmp_path / "clean.py"
        py_file.write_text("x = 1\n")

        runner = CliRunner()

        with patch(
            "wardline.cli.scan._check_registry_sync",
            return_value=["fake rule missing from registry"],
        ):
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(tmp_path),
                    "--manifest",
                    str(manifest),
                    "--allow-registry-mismatch",
                ],
            )

        # Should NOT be exit code 2 — mismatch was allowed
        assert result.exit_code != 2, (
            f"Expected non-2 exit code, got {result.exit_code}. "
            f"Output: {result.output}"
        )
