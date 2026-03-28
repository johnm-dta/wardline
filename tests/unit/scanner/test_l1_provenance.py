"""Tests for L1 taint provenance — verifying TaintSource tracking."""

from __future__ import annotations

import ast
import textwrap
from types import MappingProxyType

from wardline.core.taints import TaintState
from wardline.manifest.models import ModuleTierEntry, WardlineManifest
from wardline.scanner.context import WardlineAnnotation
from wardline.scanner.taint.function_level import assign_function_taints


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


class TestL1Provenance:
    """Verify TaintSource provenance tracking for all three assignment paths."""

    def test_provenance_decorator(self) -> None:
        """@external_boundary → source 'decorator'."""
        tree = _parse("def handler(): pass\n")
        annotations = {
            ("test.py", "handler"): [_ann("external_boundary")],
        }
        taint_map, _return_map, taint_sources, _conflicts, _overclaims = assign_function_taints(
            tree, "test.py", annotations
        )

        assert taint_map["handler"] == TaintState.EXTERNAL_RAW
        assert taint_sources["handler"] == "decorator"

    def test_provenance_module_default(self) -> None:
        """Module_tiers match, no decorator → source 'module_default'."""
        tree = _parse("def plain(): pass\n")
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(
                    path="src/myapp",
                    default_taint="GUARDED",
                ),
            ),
        )
        taint_map, _return_map, taint_sources, _conflicts, _overclaims = assign_function_taints(
            tree, "src/myapp/handlers.py", {}, manifest=manifest
        )

        assert taint_map["plain"] == TaintState.GUARDED
        assert taint_sources["plain"] == "module_default"

    def test_provenance_fallback(self) -> None:
        """No decorator, no module_tiers → source 'fallback'."""
        tree = _parse("def orphan(): pass\n")
        taint_map, _return_map, taint_sources, _conflicts, _overclaims = assign_function_taints(
            tree, "test.py", {}
        )

        assert taint_map["orphan"] == TaintState.UNKNOWN_RAW
        assert taint_sources["orphan"] == "fallback"

    def test_provenance_decorator_overrides_module(self) -> None:
        """Decorated function in module_tiers module → source 'decorator'."""
        tree = _parse("""\
            def decorated(): pass
            def plain(): pass
        """)
        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(
                    path="src/myapp",
                    default_taint="GUARDED",
                ),
            ),
        )
        annotations = {
            ("src/myapp/api.py", "decorated"): [_ann("external_boundary")],
        }
        taint_map, _return_map, taint_sources, _conflicts, _overclaims = assign_function_taints(
            tree, "src/myapp/api.py", annotations, manifest=manifest
        )

        # Decorated function: decorator wins, source is "decorator"
        assert taint_map["decorated"] == TaintState.EXTERNAL_RAW
        assert taint_sources["decorated"] == "decorator"
        # Undecorated function: module default applies, source is "module_default"
        assert taint_map["plain"] == TaintState.GUARDED
        assert taint_sources["plain"] == "module_default"
