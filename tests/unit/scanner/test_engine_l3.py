"""Tests for L3 call-graph taint engine integration (WP 2.1, Task 7).

Verifies that:
- L3 is gated on analysis_level (not run at 1 or 2, runs at 3)
- L3 failure falls back to L1 map with TOOL-ERROR finding
- L2 variable taint sees L3-refined taints
- ScanContext carries analysis_level and provenance
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar
from unittest.mock import patch

import pytest

from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.base import RuleBase
from wardline.scanner.taint.callgraph_propagation import TaintProvenance

if TYPE_CHECKING:
    import ast
    from pathlib import Path


# ── Helper rule that captures context ────────────────────────────


class _ContextCapturingRule(RuleBase):
    """Captures the ScanContext set by the engine for later inspection."""

    RULE_ID: ClassVar[RuleId] = RuleId.TOOL_ERROR

    def __init__(self) -> None:
        super().__init__()
        self.captured_contexts: list[ScanContext | None] = []

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.captured_contexts.append(self._context)


# ── Helpers ──────────────────────────────────────────────────────


def _write_py(path: Path, content: str) -> None:
    """Write a Python file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# Source code with a module-level function calling another.
# At L3, `caller` should be refined based on what `callee` has.
_L3_SOURCE = """\
def callee():
    pass

def caller():
    callee()
"""


# ── L3 gating tests ─────────────────────────────────────────────


class TestL3Gating:
    """L3 call-graph taint only runs when analysis_level >= 3."""

    def test_l3_not_run_at_level_1(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", _L3_SOURCE)
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=1,
        )
        with patch(
            "wardline.scanner.engine.extract_call_edges",
            wraps=None,
        ) as mock_extract:
            mock_extract.side_effect = AssertionError("should not be called")
            result = engine.scan()

        # No error from L3 — it was never called
        assert result.errors == []
        # extract_call_edges was never invoked
        mock_extract.assert_not_called()

    def test_l3_not_run_at_level_2(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", _L3_SOURCE)
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=2,
        )
        with patch(
            "wardline.scanner.engine.extract_call_edges",
            wraps=None,
        ) as mock_extract:
            mock_extract.side_effect = AssertionError("should not be called")
            result = engine.scan()

        assert result.errors == []
        mock_extract.assert_not_called()

    def test_l3_runs_at_level_3(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", _L3_SOURCE)
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=3,
        )
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.errors == []
        # The rule should have captured a context for each function
        assert len(rule.captured_contexts) == 2


class TestL3FailureFallback:
    """L3 failure emits TOOL-ERROR finding and falls back to L1 map."""

    def test_l3_failure_falls_back(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", _L3_SOURCE)
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=3,
        )
        with patch(
            "wardline.scanner.engine.extract_call_edges",
            side_effect=RuntimeError("boom"),
        ):
            result = engine.scan()

        # TOOL-ERROR finding should be emitted in result.findings
        tool_errors = [
            f for f in result.findings if f.rule_id == RuleId.TOOL_ERROR
        ]
        assert len(tool_errors) == 1
        assert "L3 call-graph taint failed" in tool_errors[0].message
        assert tool_errors[0].severity == Severity.ERROR

        # Engine should still produce scan results (fell back to L1)
        assert result.files_scanned == 1


class TestL2SeesL3RefinedTaints:
    """L2 variable taint analysis uses L3-refined function-level taints."""

    def test_l2_sees_l3_refined_taints(self, tmp_path: Path) -> None:
        """Module-level function: L3 refines caller from UNKNOWN_RAW to callee's taint.

        Note: This test uses module-level functions only. Method resolution
        (self.method()) is a known limitation — L3 resolves methods but the
        variable taint pass sees them through qualname_map which uses id(node).
        """
        # callee is decorated (will get a specific taint from L1)
        # caller calls callee, so L3 should refine caller's taint
        source = """\
def callee():
    pass

def caller():
    x = callee()
"""
        _write_py(tmp_path / "mod.py", source)
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=3,
        )

        # Mock L1 to return known taints: callee=EXTERNAL_RAW (decorator), caller=PIPELINE (fallback)
        # With floor clamp, caller (PIPELINE=rank 1) can be degraded to EXTERNAL_RAW (rank 5)
        l1_taint_map = {
            "callee": TaintState.EXTERNAL_RAW,
            "caller": TaintState.PIPELINE,
        }
        l1_sources = {
            "callee": "decorator",
            "caller": "fallback",
        }

        with patch(
            "wardline.scanner.engine.assign_function_taints",
            return_value=(l1_taint_map, l1_taint_map, l1_sources),
        ):
            result = engine.scan()

        assert result.files_scanned == 1
        assert result.errors == []

        # Check the context: caller should have been refined by L3
        # (fallback PIPELINE calling EXTERNAL_RAW callee -> degraded to EXTERNAL_RAW)
        assert len(rule.captured_contexts) >= 1
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        # caller should be refined to EXTERNAL_RAW (matching its callee, above floor)
        assert ctx.function_level_taint_map.get("caller") == TaintState.EXTERNAL_RAW


# ── ScanContext field tests ──────────────────────────────────────


class TestScanContextFields:
    """ScanContext carries analysis_level and taint_provenance."""

    def test_scan_context_has_analysis_level(self) -> None:
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},  # type: ignore[arg-type]
            analysis_level=3,
        )
        assert ctx.analysis_level == 3

    def test_scan_context_default_analysis_level(self) -> None:
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},  # type: ignore[arg-type]
        )
        assert ctx.analysis_level == 1

    def test_scan_context_has_provenance(self) -> None:
        prov = {
            "foo": TaintProvenance(
                source="decorator",
                resolved_call_count=1,
                unresolved_call_count=0,
            ),
        }
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},  # type: ignore[arg-type]
            taint_provenance=prov,  # type: ignore[arg-type]
        )
        assert ctx.taint_provenance is not None
        assert isinstance(ctx.taint_provenance, MappingProxyType)
        assert ctx.taint_provenance["foo"].source == "decorator"

    def test_scan_context_provenance_none_by_default(self) -> None:
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},  # type: ignore[arg-type]
        )
        assert ctx.taint_provenance is None

    def test_scan_context_provenance_frozen(self) -> None:
        """Dict is converted to MappingProxyType (immutable)."""
        prov = {
            "bar": TaintProvenance(source="fallback"),
        }
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},  # type: ignore[arg-type]
            taint_provenance=prov,  # type: ignore[arg-type]
        )
        with pytest.raises(TypeError):
            ctx.taint_provenance["new"] = TaintProvenance(source="callgraph")  # type: ignore[index]
