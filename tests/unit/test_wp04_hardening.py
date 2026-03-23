"""Tests for WP 0.4 Hardening batch 1 bug fixes.

Bug 2: ast.walk duplicate findings on nested defs
Bug 4: Schema version substring match
Bug 5: Evidence matching namespace mismatch
Bug 6: refresh_agent_originated field
"""

from __future__ import annotations

import ast
import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from wardline.manifest.loader import (
    EXPECTED_SCHEMA_VERSION,
    ManifestLoadError,
    _check_schema_version,
)
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.rules.base import walk_skip_nested_defs


# ── Bug 2: ast.walk duplicate findings on nested defs ─────────────


class TestWalkSkipNestedDefs:
    """walk_skip_nested_defs must not descend into nested function bodies."""

    def test_skips_nested_function_body(self) -> None:
        source = textwrap.dedent("""\
        def outer():
            x.get("a", 1)
            def inner():
                y.get("b", 2)
        """)
        tree = ast.parse(source)
        outer_func = tree.body[0]  # FunctionDef: outer

        # Collect all Call nodes found by walk_skip_nested_defs
        calls = [
            n for n in walk_skip_nested_defs(outer_func)
            if isinstance(n, ast.Call)
        ]
        # Should only find x.get("a", 1), NOT y.get("b", 2)
        assert len(calls) == 1

    def test_includes_root_node_body(self) -> None:
        source = textwrap.dedent("""\
        def outer():
            x.get("a", 1)
            z.get("c", 3)
        """)
        tree = ast.parse(source)
        outer_func = tree.body[0]

        calls = [
            n for n in walk_skip_nested_defs(outer_func)
            if isinstance(n, ast.Call)
        ]
        assert len(calls) == 2

    def test_skips_async_nested_def(self) -> None:
        source = textwrap.dedent("""\
        def outer():
            x.get("a", 1)
            async def inner():
                y.get("b", 2)
        """)
        tree = ast.parse(source)
        outer_func = tree.body[0]

        calls = [
            n for n in walk_skip_nested_defs(outer_func)
            if isinstance(n, ast.Call)
        ]
        assert len(calls) == 1


class TestNestedDefNoDuplicateFindings:
    """Rules should NOT produce duplicate findings for patterns inside nested defs."""

    def test_py_wl_001_no_duplicates_nested(self) -> None:
        """PY-WL-001 should find .get() once per function, not double-count nested."""
        from wardline.scanner.rules.py_wl_001 import RulePyWl001

        source = textwrap.dedent("""\
        def outer():
            d.get("key", "default")
            def inner():
                d.get("key2", "default2")
        """)
        tree = ast.parse(source)
        rule = RulePyWl001(file_path="test.py")
        rule.visit(tree)

        # Should get exactly 2 findings: one for outer, one for inner
        assert len(rule.findings) == 2
        lines = sorted(f.line for f in rule.findings)
        assert lines[0] != lines[1]  # different lines


# ── Bug 4: Schema version substring match ─────────────────────────


class TestSchemaVersionExactMatch:
    """_check_schema_version should not match '0.1' inside '0.10'."""

    def test_exact_version_match_passes(self) -> None:
        data: dict[str, Any] = {
            "$id": f"https://wardline.dev/schemas/{EXPECTED_SCHEMA_VERSION}/wardline.schema.json"
        }
        # Should not raise
        _check_schema_version(data, Path("test.yaml"))

    def test_substring_version_mismatch_raises(self) -> None:
        """Version '0.10' should NOT match expected '0.1'."""
        data: dict[str, Any] = {
            "$id": "https://wardline.dev/schemas/0.10/wardline.schema.json"
        }
        with pytest.raises(ManifestLoadError, match="schema version"):
            _check_schema_version(data, Path("test.yaml"))

    def test_different_version_raises(self) -> None:
        data: dict[str, Any] = {
            "$id": "https://wardline.dev/schemas/2.0/wardline.schema.json"
        }
        with pytest.raises(ManifestLoadError, match="schema version"):
            _check_schema_version(data, Path("test.yaml"))

    def test_empty_id_passes(self) -> None:
        data: dict[str, Any] = {"$id": ""}
        _check_schema_version(data, Path("test.yaml"))

    def test_no_id_passes(self) -> None:
        data: dict[str, Any] = {}
        _check_schema_version(data, Path("test.yaml"))


# ── Bug 5: Evidence matching uses overlay_scope ───────────────────


class TestTierUpgradeEvidenceUsesOverlayScope:
    """Evidence check should use boundary overlay_scope, not function qualnames."""

    def test_overlay_scope_covers_module(self, tmp_path: Path) -> None:
        from wardline.manifest.coherence import check_tier_upgrade_without_evidence
        from wardline.manifest.models import ModuleTierEntry, TierEntry

        baseline = {
            "tiers": [{"id": "strict", "tier": 1}, {"id": "permissive", "tier": 3}],
            "module_tiers": [{"path": "src/core", "default_taint": "permissive"}],
        }
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (TierEntry(id="strict", tier=1), TierEntry(id="permissive", tier=3))
        module_tiers = (ModuleTierEntry(path="src/core", default_taint="strict"),)

        # Boundary with overlay_scope covering the module
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                overlay_scope="/project/src/core",
            ),
        )

        issues = check_tier_upgrade_without_evidence(
            tiers, module_tiers, boundaries, baseline_path
        )
        assert issues == [], "overlay_scope covering module should count as evidence"

    def test_qualname_alone_is_not_evidence(self, tmp_path: Path) -> None:
        from wardline.manifest.coherence import check_tier_upgrade_without_evidence
        from wardline.manifest.models import ModuleTierEntry, TierEntry

        baseline = {
            "tiers": [{"id": "strict", "tier": 1}, {"id": "permissive", "tier": 3}],
            "module_tiers": [{"path": "src/core", "default_taint": "permissive"}],
        }
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (TierEntry(id="strict", tier=1), TierEntry(id="permissive", tier=3))
        module_tiers = (ModuleTierEntry(path="src/core", default_taint="strict"),)

        # Boundary with qualname matching module path but NO overlay_scope
        boundaries = (
            BoundaryEntry(function="src/core.handler", transition="INGRESS"),
        )

        issues = check_tier_upgrade_without_evidence(
            tiers, module_tiers, boundaries, baseline_path
        )
        assert len(issues) == 1, "qualname alone should not count as evidence"
