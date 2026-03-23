"""Tests for ScanEngine — file discovery, parse errors, rule crashes."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import pytest

from wardline.core.severity import RuleId, Severity
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.base import RuleBase

if TYPE_CHECKING:
    import ast
    from pathlib import Path


# ── Test rule implementations ────────────────────────────────────


class _CountingRule(RuleBase):
    """Counts function visits — used to verify the engine runs rules."""

    RULE_ID: ClassVar[RuleId] = RuleId.TOOL_ERROR

    def __init__(self) -> None:
        super().__init__()
        self.visited: list[tuple[str, str]] = []

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.visited.append((node.name, "async" if is_async else "sync"))


class _CrashingRule(RuleBase):
    """Always raises RuntimeError — used to test TOOL-ERROR handling."""

    RULE_ID: ClassVar[RuleId] = RuleId.TOOL_ERROR

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        raise RuntimeError("deliberate crash for testing")


# ── Helpers ──────────────────────────────────────────────────────


def _write_py(path: Path, content: str) -> None:
    """Write a Python file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ── Normal multi-file scan ───────────────────────────────────────


class TestNormalScan:
    """Engine discovers and scans multiple .py files."""

    def test_scans_multiple_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        _write_py(tmp_path / "sub" / "b.py", "async def bar(): pass\n")

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 2
        assert result.files_skipped == 0
        assert len(result.errors) == 0
        # Both functions should be visited
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"foo", "bar"}

    def test_skips_non_python_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "code.py", "def x(): pass\n")
        (tmp_path / "readme.txt").write_text("not python", encoding="utf-8")
        (tmp_path / "data.json").write_text("{}", encoding="utf-8")

        rule = _CountingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        result = engine.scan()

        assert result.files_scanned == 1

    def test_empty_target_returns_empty_result(self, tmp_path: Path) -> None:
        engine = ScanEngine(target_paths=(tmp_path,))
        result = engine.scan()

        assert result.files_scanned == 0
        assert result.findings == []

    def test_no_rules_still_counts_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "x = 1\n")

        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.findings == []


# ── Exclude paths ────────────────────────────────────────────────


class TestExcludePaths:
    """Engine respects exclude_paths for both directories and files."""

    def test_excludes_directory(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "keep" / "a.py", "def keep(): pass\n")
        _write_py(tmp_path / "skip" / "b.py", "def skip(): pass\n")

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(tmp_path / "skip",),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 1
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"keep"}

    def test_excludes_nested_directory(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a" / "b" / "deep.py", "def deep(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(tmp_path / "a" / "b",),
            rules=(_CountingRule(),),
        )
        result = engine.scan()

        assert result.files_scanned == 0


# ── Parse error handling ─────────────────────────────────────────


class TestParseErrors:
    """Engine skips files with syntax errors and continues scanning."""

    def test_syntax_error_skips_file_continues_scan(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "good.py", "def ok(): pass\n")
        _write_py(tmp_path / "bad.py", "def broken(\n")  # unterminated

        rule = _CountingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.files_skipped == 1
        assert any("Syntax error" in e for e in result.errors)
        # The good file's function should still be visited
        assert len(rule.visited) == 1

    def test_all_files_bad_produces_zero_scanned(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "bad1.py", "def (\n")
        _write_py(tmp_path / "bad2.py", "class\n")

        engine = ScanEngine(target_paths=(tmp_path,), rules=(_CountingRule(),))
        result = engine.scan()

        assert result.files_scanned == 0
        assert result.files_skipped == 2


# ── Permission errors ────────────────────────────────────────────


class TestPermissionErrors:
    """Engine handles unreadable files and directories gracefully."""

    def test_unreadable_file_skipped_with_warning(self, tmp_path: Path) -> None:
        good = tmp_path / "good.py"
        bad = tmp_path / "noperm.py"
        _write_py(good, "def ok(): pass\n")
        _write_py(bad, "def secret(): pass\n")

        # Remove read permission
        bad.chmod(0o000)
        try:
            rule = _CountingRule()
            engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
            result = engine.scan()

            assert result.files_scanned == 1
            assert result.files_skipped == 1
            assert any(
                "Permission denied" in e or "Cannot read" in e
                for e in result.errors
            )
        finally:
            # Restore permissions for cleanup
            bad.chmod(0o644)

    def test_unreadable_directory_skipped(self, tmp_path: Path) -> None:
        good_dir = tmp_path / "good"
        bad_dir = tmp_path / "noaccess"
        _write_py(good_dir / "a.py", "def ok(): pass\n")
        bad_dir.mkdir()
        _write_py(bad_dir / "b.py", "def hidden(): pass\n")

        bad_dir.chmod(0o000)
        try:
            rule = _CountingRule()
            engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
            result = engine.scan()

            # Good file should still be scanned
            assert result.files_scanned >= 1
            visited_names = {name for name, _ in rule.visited}
            assert "ok" in visited_names
        finally:
            bad_dir.chmod(0o755)


# ── Rule crash → TOOL-ERROR finding ─────────────────────────────


class TestRuleCrashHandling:
    """A crashing rule produces a TOOL-ERROR finding without aborting."""

    def test_crashing_rule_emits_tool_error(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "code.py", "def trigger(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(_CrashingRule(),),
        )
        result = engine.scan()

        assert result.files_scanned == 1
        assert len(result.findings) == 1

        finding = result.findings[0]
        assert finding.rule_id == RuleId.TOOL_ERROR
        assert finding.severity == Severity.WARNING
        assert "_CrashingRule" in finding.message
        assert "deliberate crash" in finding.message

    def test_crash_does_not_abort_other_rules(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "code.py", "def hello(): pass\n")

        counting = _CountingRule()
        crashing = _CrashingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(crashing, counting),
        )
        result = engine.scan()

        # Counting rule should still have run after the crash
        assert len(counting.visited) == 1
        assert counting.visited[0][0] == "hello"
        # Should have one TOOL-ERROR from the crashing rule
        tool_errors = [f for f in result.findings if f.rule_id == RuleId.TOOL_ERROR]
        assert len(tool_errors) == 1

    def test_crash_on_multiple_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def one(): pass\n")
        _write_py(tmp_path / "b.py", "def two(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(_CrashingRule(),),
        )
        result = engine.scan()

        assert result.files_scanned == 2
        tool_errors = [f for f in result.findings if f.rule_id == RuleId.TOOL_ERROR]
        assert len(tool_errors) == 2


# ── Symlink safety ───────────────────────────────────────────────


class TestSymlinkSafety:
    """Engine does not follow symlinks during directory walk."""

    def test_does_not_follow_directory_symlinks(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        _write_py(real_dir / "a.py", "def real_fn(): pass\n")

        # Create a symlink loop
        link = tmp_path / "scan_root" / "link_to_real"
        (tmp_path / "scan_root").mkdir()
        _write_py(tmp_path / "scan_root" / "b.py", "def scan_fn(): pass\n")
        link.symlink_to(real_dir)

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(tmp_path / "scan_root",),
            rules=(rule,),
        )
        result = engine.scan()

        # Should only scan b.py, not follow the symlink to real/a.py
        assert result.files_scanned == 1
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"scan_fn"}


# ── Target path validation ───────────────────────────────────────


class TestTargetValidation:
    """Engine handles invalid target paths gracefully."""

    def test_nonexistent_target_reported(self, tmp_path: Path) -> None:
        engine = ScanEngine(
            target_paths=(tmp_path / "does_not_exist",),
        )
        result = engine.scan()

        assert result.files_scanned == 0
        assert any("not a directory" in e for e in result.errors)

    def test_file_as_target_reported(self, tmp_path: Path) -> None:
        f = tmp_path / "file.py"
        f.write_text("x = 1\n", encoding="utf-8")

        engine = ScanEngine(target_paths=(f,))
        result = engine.scan()

        assert result.files_scanned == 0
        assert any("not a directory" in e for e in result.errors)


# ── Multiple targets ─────────────────────────────────────────────


class TestMultipleTargets:
    """Engine scans across multiple target directories."""

    def test_scans_all_targets(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        _write_py(dir_a / "mod_a.py", "def fn_a(): pass\n")
        _write_py(dir_b / "mod_b.py", "def fn_b(): pass\n")

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(dir_a, dir_b),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 2
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"fn_a", "fn_b"}


# ── Context-capturing rule for boundary tests ────────────────────


class _ContextCapturingRule(RuleBase):
    """Captures self._context on visit_function for test inspection."""

    RULE_ID: ClassVar[RuleId] = RuleId.TOOL_ERROR

    def __init__(self) -> None:
        super().__init__()
        self.captured_context: ScanContext | None = None

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.captured_context = self._context


# ── ScanContext.boundaries tests ─────────────────────────────────


class TestScanContextBoundaries:
    """ScanContext carries overlay boundaries as a frozen tuple."""

    def test_boundaries_default_empty(self) -> None:
        ctx = ScanContext(file_path="test.py", function_level_taint_map={})
        assert ctx.boundaries == ()

    def test_boundaries_set_at_construction(self) -> None:
        b = BoundaryEntry(function="fn", transition="construction")
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},
            boundaries=(b,),
        )
        assert len(ctx.boundaries) == 1
        assert ctx.boundaries[0].function == "fn"

    def test_boundaries_frozen(self) -> None:
        ctx = ScanContext(file_path="test.py", function_level_taint_map={})
        with pytest.raises(AttributeError):
            ctx.boundaries = ()  # type: ignore[misc]


# ── Engine boundary injection tests ──────────────────────────────


class TestEngineBoundaryInjection:
    """ScanEngine passes boundaries through to ScanContext."""

    def test_engine_passes_boundaries_to_context(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        b = BoundaryEntry(function="foo", transition="construction")
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            boundaries=(b,),
        )
        engine.scan()
        assert rule.captured_context is not None
        assert len(rule.captured_context.boundaries) == 1

    def test_engine_no_boundaries_backward_compat(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        rule = _ContextCapturingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        engine.scan()
        assert rule.captured_context is not None
        assert rule.captured_context.boundaries == ()
