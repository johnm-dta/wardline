"""Tests for Level 1 taint assignment — decorator, module_tiers, fallback."""

from __future__ import annotations

import ast
import textwrap
from types import MappingProxyType

from wardline.core.taints import TaintState
from wardline.manifest.models import ModuleTierEntry, WardlineManifest
from wardline.scanner.context import WardlineAnnotation
from wardline.scanner.taint.function_level import (
    DECORATOR_TAINT_MAP,
    assign_function_taints,
)


def _parse(source: str) -> ast.Module:
    """Parse dedented source into an AST module."""
    return ast.parse(textwrap.dedent(source))


def _ann(canonical_name: str, group: int = 1) -> WardlineAnnotation:
    """Build a WardlineAnnotation with empty attrs."""
    return WardlineAnnotation(
        canonical_name=canonical_name,
        group=group,
        attrs=MappingProxyType({}),
    )


# ── Source 1: Decorator taint ────────────────────────────────────


class TestDecoratorTaint:
    """Decorated functions get taint from the decorator mapping."""

    def test_external_boundary_gets_external_raw(self) -> None:
        tree = _parse("def handler(): pass\n")
        annotations = {
            ("test.py", "handler"): [_ann("external_boundary")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["handler"] == TaintState.EXTERNAL_RAW

    def test_validates_shape_gets_shape_validated(self) -> None:
        tree = _parse("def validate(): pass\n")
        annotations = {
            ("test.py", "validate"): [_ann("validates_shape")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["validate"] == TaintState.SHAPE_VALIDATED

    def test_validates_semantic_gets_unknown_sem_validated(self) -> None:
        tree = _parse("def check(): pass\n")
        annotations = {
            ("test.py", "check"): [_ann("validates_semantic")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["check"] == TaintState.UNKNOWN_SEM_VALIDATED

    def test_tier1_read_gets_audit_trail(self) -> None:
        tree = _parse("def read_data(): pass\n")
        annotations = {
            ("test.py", "read_data"): [_ann("tier1_read")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["read_data"] == TaintState.AUDIT_TRAIL

    def test_audit_writer_gets_audit_trail(self) -> None:
        tree = _parse("def write_log(): pass\n")
        annotations = {
            ("test.py", "write_log"): [_ann("audit_writer")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["write_log"] == TaintState.AUDIT_TRAIL

    def test_authoritative_construction_gets_pipeline(self) -> None:
        tree = _parse("def construct(): pass\n")
        annotations = {
            ("test.py", "construct"): [_ann("authoritative_construction")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["construct"] == TaintState.PIPELINE

    def test_audit_critical_flag_only_gets_fallback(self) -> None:
        """audit_critical is a flag, not a taint source → falls to default."""
        tree = _parse("def critical(): pass\n")
        annotations = {
            ("test.py", "critical"): [_ann("audit_critical", group=2)],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        # No taint-assigning decorator → falls to UNKNOWN_RAW
        assert result["critical"] == TaintState.UNKNOWN_RAW

    def test_all_decorator_mappings_present(self) -> None:
        """Every taint-assigning decorator in the map has a valid TaintState."""
        for name, taint in DECORATOR_TAINT_MAP.items():
            assert isinstance(taint, TaintState), f"{name} has invalid taint"


# ── Source 2: Module tiers ───────────────────────────────────────


class TestModuleTiersTaint:
    """Undecorated functions in declared modules get module default."""

    def test_declared_module_gets_module_default(self) -> None:
        tree = _parse("def plain(): pass\n")
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(
                    path="src/myapp",
                    default_taint="SHAPE_VALIDATED",
                ),
            ),
        )
        result = assign_function_taints(
            tree, "src/myapp/handlers.py", {}, manifest=manifest
        )

        assert result["plain"] == TaintState.SHAPE_VALIDATED

    def test_subdirectory_matches_module_tier(self) -> None:
        tree = _parse("def nested(): pass\n")
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(
                    path="src/myapp",
                    default_taint="AUDIT_TRAIL",
                ),
            ),
        )
        result = assign_function_taints(
            tree, "src/myapp/sub/deep.py", {}, manifest=manifest
        )

        assert result["nested"] == TaintState.AUDIT_TRAIL


# ── Source 3: UNKNOWN_RAW fallback ───────────────────────────────


class TestUnknownRawFallback:
    """Undecorated functions in undeclared modules get UNKNOWN_RAW."""

    def test_undeclared_module_gets_unknown_raw(self) -> None:
        tree = _parse("def orphan(): pass\n")
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path="src/other", default_taint="AUDIT_TRAIL"),
            ),
        )
        result = assign_function_taints(
            tree, "src/unknown/module.py", {}, manifest=manifest
        )

        assert result["orphan"] == TaintState.UNKNOWN_RAW

    def test_no_manifest_gets_unknown_raw(self) -> None:
        tree = _parse("def alone(): pass\n")
        result = assign_function_taints(tree, "test.py", {})

        assert result["alone"] == TaintState.UNKNOWN_RAW

    def test_no_manifest_no_annotations_all_unknown_raw(self) -> None:
        tree = _parse("""\
            def a(): pass
            def b(): pass
        """)
        result = assign_function_taints(tree, "test.py", {})

        assert result["a"] == TaintState.UNKNOWN_RAW
        assert result["b"] == TaintState.UNKNOWN_RAW


# ── Precedence: decorator > module_tiers > UNKNOWN_RAW ───────────


class TestTaintPrecedence:
    """Decorator taint takes precedence over module_tiers default."""

    def test_decorator_overrides_module_default(self) -> None:
        """A decorated function in a declared module gets decorator taint."""
        tree = _parse("""\
            def decorated(): pass
            def plain(): pass
        """)
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(
                    path="src/myapp",
                    default_taint="SHAPE_VALIDATED",
                ),
            ),
        )
        annotations = {
            ("src/myapp/api.py", "decorated"): [_ann("external_boundary")],
        }
        result = assign_function_taints(
            tree, "src/myapp/api.py", annotations, manifest=manifest
        )

        # Decorated function: decorator wins over module default
        assert result["decorated"] == TaintState.EXTERNAL_RAW
        # Undecorated function: module default applies
        assert result["plain"] == TaintState.SHAPE_VALIDATED

    def test_module_default_overrides_unknown_raw(self) -> None:
        """Declared module default beats UNKNOWN_RAW fallback."""
        tree = _parse("def func(): pass\n")
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path="src/safe", default_taint="PIPELINE"),
            ),
        )
        result = assign_function_taints(
            tree, "src/safe/mod.py", {}, manifest=manifest
        )

        assert result["func"] == TaintState.PIPELINE


# ── Async functions ──────────────────────────────────────────────


class TestAsyncFunctions:
    """Async functions are assigned taint the same as sync functions."""

    def test_async_decorated_function(self) -> None:
        tree = _parse("async def handler(): pass\n")
        annotations = {
            ("test.py", "handler"): [_ann("external_boundary")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["handler"] == TaintState.EXTERNAL_RAW

    def test_async_undecorated_gets_module_default(self) -> None:
        tree = _parse("async def fetch(): pass\n")
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path="src/api", default_taint="EXTERNAL_RAW"),
            ),
        )
        result = assign_function_taints(
            tree, "src/api/client.py", {}, manifest=manifest
        )

        assert result["fetch"] == TaintState.EXTERNAL_RAW

    def test_async_undeclared_gets_unknown_raw(self) -> None:
        tree = _parse("async def mystery(): pass\n")
        result = assign_function_taints(tree, "test.py", {})

        assert result["mystery"] == TaintState.UNKNOWN_RAW

    def test_mixed_sync_and_async(self) -> None:
        """Both sync and async functions in the same file are assigned."""
        tree = _parse("""\
            def sync_fn(): pass
            async def async_fn(): pass
        """)
        annotations = {
            ("test.py", "sync_fn"): [_ann("tier1_read")],
            ("test.py", "async_fn"): [_ann("external_boundary")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["sync_fn"] == TaintState.AUDIT_TRAIL
        assert result["async_fn"] == TaintState.EXTERNAL_RAW


# ── Nested functions and methods ─────────────────────────────────


class TestNesting:
    """Functions nested in classes or other functions get correct qualnames."""

    def test_method_in_class(self) -> None:
        tree = _parse("""\
            class MyService:
                def handle(self): pass
        """)
        annotations = {
            ("svc.py", "MyService.handle"): [_ann("external_boundary")],
        }
        result = assign_function_taints(tree, "svc.py", annotations)

        assert result["MyService.handle"] == TaintState.EXTERNAL_RAW

    def test_nested_function(self) -> None:
        tree = _parse("""\
            def outer():
                def inner(): pass
        """)
        annotations = {
            ("test.py", "outer.inner"): [_ann("validates_shape")],
        }
        result = assign_function_taints(tree, "test.py", annotations)

        assert result["outer"] == TaintState.UNKNOWN_RAW
        assert result["outer.inner"] == TaintState.SHAPE_VALIDATED

    def test_all_functions_in_file_assigned(self) -> None:
        """Every function gets a taint, even those without annotations."""
        tree = _parse("""\
            def a(): pass
            def b(): pass
            class C:
                def m(self): pass
        """)
        result = assign_function_taints(tree, "test.py", {})

        assert len(result) == 3
        assert "a" in result
        assert "b" in result
        assert "C.m" in result


# ── Edge cases ───────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases for taint assignment."""

    def test_empty_file(self) -> None:
        tree = _parse("")
        result = assign_function_taints(tree, "empty.py", {})

        assert result == {}

    def test_file_with_no_functions(self) -> None:
        tree = _parse("x = 1\ny = 2\n")
        result = assign_function_taints(tree, "constants.py", {})

        assert result == {}
