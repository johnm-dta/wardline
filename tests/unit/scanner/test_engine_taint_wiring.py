"""Tests for engine ↔ discovery/taint wiring (Task 2).

Verifies that ScanEngine._scan_file() calls discover_annotations() and
assign_function_taints() per file, builds ScanContext, and passes it to rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar
from unittest.mock import patch

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.base import RuleBase

if TYPE_CHECKING:
    import ast
    from pathlib import Path

    from wardline.scanner.context import ScanContext


# ── Helper rule that captures context ────────────────────────────


class _ContextCapturingRule(RuleBase):
    """Appends self._context to captured_contexts in visit_function."""

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


# ── TestEngineCallsDiscovery ────────────────────────────────────


class TestEngineCallsDiscovery:
    """discover_annotations is called once per scanned file."""

    def test_called_once_per_file(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        _write_py(tmp_path / "sub" / "b.py", "def bar(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(_ContextCapturingRule(),),
        )

        with (
            patch(
                "wardline.scanner.engine.discover_annotations",
                return_value={},
            ) as mock_disc,
            patch(
                "wardline.scanner.engine.assign_function_taints",
                return_value=({}, {}),
            ),
        ):
            engine.scan()

        assert mock_disc.call_count == 2


# ── TestEngineCallsTaintAssignment ──────────────────────────────


class TestEngineCallsTaintAssignment:
    """assign_function_taints is called once per scanned file."""

    def test_called_once_per_file(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        _write_py(tmp_path / "sub" / "b.py", "def bar(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(_ContextCapturingRule(),),
        )

        with (
            patch(
                "wardline.scanner.engine.discover_annotations",
                return_value={},
            ),
            patch(
                "wardline.scanner.engine.assign_function_taints",
                return_value=({}, {}),
            ) as mock_taint,
        ):
            engine.scan()

        assert mock_taint.call_count == 2


# ── TestEngineSetsContext ───────────────────────────────────────


class TestEngineSetsContext:
    """Real scan of a simple function populates ScanContext correctly."""

    def test_context_has_taint_map_entry(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", "def my_func(): pass\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )

        # assign_function_taints returns UNKNOWN_RAW for undecorated
        taint_map = {"my_func": TaintState.UNKNOWN_RAW}
        taint_sources = {"my_func": "fallback"}

        with (
            patch(
                "wardline.scanner.engine.discover_annotations",
                return_value={},
            ),
            patch(
                "wardline.scanner.engine.assign_function_taints",
                return_value=(taint_map, taint_sources),
            ),
        ):
            engine.scan()

        assert len(rule.captured_contexts) == 1
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert ctx.function_level_taint_map["my_func"] == TaintState.UNKNOWN_RAW


# ── TestDiscoveryFailure ────────────────────────────────────────


class TestDiscoveryFailure:
    """If discover_annotations raises, scan continues with empty taint map."""

    def test_scan_continues_with_empty_taint_map(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "bad.py", "def oops(): pass\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )

        with patch(
            "wardline.scanner.engine.discover_annotations",
            side_effect=RuntimeError("boom"),
        ):
            result = engine.scan()

        # Scan should still succeed — file counted as scanned
        assert result.files_scanned == 1
        # Error recorded
        assert any("Discovery/taint failed" in e for e in result.errors)
        # Rule still ran — context has empty taint map
        assert len(rule.captured_contexts) == 1
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert dict(ctx.function_level_taint_map) == {}


# ── TestContextFilePathCorrect ──────────────────────────────────


class TestContextFilePathCorrect:
    """ScanContext.file_path matches the scanned file."""

    def test_file_path_matches(self, tmp_path: Path) -> None:
        target = tmp_path / "check.py"
        _write_py(target, "def fn(): pass\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )

        with (
            patch(
                "wardline.scanner.engine.discover_annotations",
                return_value={},
            ),
            patch(
                "wardline.scanner.engine.assign_function_taints",
                return_value=({}, {}),
            ),
        ):
            engine.scan()

        assert len(rule.captured_contexts) == 1
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert ctx.file_path == str(target.resolve())


# ── TestVariableTaintGating ───────────────────────────────────────


class TestVariableTaintGating:
    """Level 2 variable-level taint only runs when analysis_level >= 2."""

    def test_l1_does_not_populate_variable_taint(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", "def fn():\n    x = 42\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=1,
        )
        engine.scan()

        assert len(rule.captured_contexts) == 1
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert ctx.variable_taint_map is None

    def test_l2_populates_variable_taint(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", "def fn():\n    x = 42\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=2,
        )
        engine.scan()

        assert len(rule.captured_contexts) == 1
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert ctx.variable_taint_map is not None
        assert "fn" in ctx.variable_taint_map
        assert ctx.variable_taint_map["fn"]["x"] == TaintState.AUDIT_TRAIL

    def test_l2_variable_taint_failure_is_fault_tolerant(
        self, tmp_path: Path
    ) -> None:
        _write_py(tmp_path / "mod.py", "def fn():\n    x = 42\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            analysis_level=2,
        )

        with patch(
            "wardline.scanner.engine.compute_variable_taints",
            side_effect=RuntimeError("boom"),
        ):
            result = engine.scan()

        # Scan should still succeed
        assert result.files_scanned == 1
        assert any("Variable-level taint failed" in e for e in result.errors)
        # Context has None variable_taint_map
        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert ctx.variable_taint_map is None
