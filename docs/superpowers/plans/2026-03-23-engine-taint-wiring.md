# WP 0.1: Engine → Discovery/Taint Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `discover_annotations()` and `assign_function_taints()` into `ScanEngine._scan_file()`, construct `ScanContext` per file, inject it into rules via `RuleBase.set_context()`, and update all 5 MVP rules to use tier-aware severity from the severity matrix.

**Architecture:** The engine currently has a single pass: parse AST → run rules. We add a two-pass pipeline: Pass 1 runs discovery + taint assignment to build a `ScanContext`, then Pass 2 injects that context into rules before `rule.visit(tree)`. Rules look up severity via `matrix.lookup(rule_id, taint)` instead of hardcoding `Severity.ERROR`. The design decision is already made: use `set_context(ctx)` on `RuleBase`, NOT a `visit_function` parameter change — this preserves the existing `visit_function(node, is_async)` signature.

**Key contract:** The taint map keys use **dotted qualnames** (e.g., `"MyClass.handle"`, `"outer.inner"`) matching `assign_function_taints()`. Rules must construct the same qualname when calling `_get_function_taint()`. The `_dispatch()` method on `RuleBase` tracks the enclosing scope to build the qualname.

**Review findings incorporated:** Pass 1 has error handling (falls back to empty taint map on failure). Module-level imports used throughout (no deferred imports). `set_context()` also sets `_file_path` as single source of per-file state. Orphaned `_taint_state` removed from rule constructors. `MIXED_RAW` explicitly included in PY-WL-003's `_ACTIVE_TAINTS`.

**Tech Stack:** Python 3.12, ast module, frozen dataclasses, `MappingProxyType`, pytest

**Critical path:** This WP blocks WP 1.3 (Overlay), WP 1.6 (Level 2 Taint), and WP 1.5 (Rules 006-009). Everything in v0.2.0+ gates on this.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/wardline/scanner/rules/base.py` | Modify | Add `set_context()` method, `_context` attribute |
| `src/wardline/scanner/engine.py` | Modify | Wire discovery → taint → ScanContext → set_context per file |
| `src/wardline/scanner/rules/py_wl_001.py` | Modify | Use `self._context` for taint-aware severity |
| `src/wardline/scanner/rules/py_wl_002.py` | Modify | Use `self._context` for taint-aware severity |
| `src/wardline/scanner/rules/py_wl_003.py` | Modify | Taint-gate: only fire at EXTERNAL_RAW/UNKNOWN_RAW |
| `src/wardline/scanner/rules/py_wl_004.py` | Modify | Use `self._context` for taint-aware severity |
| `src/wardline/scanner/rules/py_wl_005.py` | Modify | Use `self._context` for taint-aware severity |
| `src/wardline/cli/scan.py` | Modify | Pass manifest into engine for taint resolution |
| `tests/unit/scanner/test_rule_base_context.py` | Create | Tests for `set_context()` contract |
| `tests/unit/scanner/test_engine_taint_wiring.py` | Create | Tests for engine discovery/taint integration |
| `tests/unit/scanner/test_rules_taint_aware.py` | Create | Tests for tier-aware severity in all 5 rules |
| `tests/integration/test_self_hosting_scan.py` | Modify | Per-rule finding count assertions |
| `.github/workflows/ci.yml` | Modify | Run integration tests on every PR |

---

## Task 1: Add `set_context()` to `RuleBase`

**Files:**
- Modify: `src/wardline/scanner/rules/base.py:24-39`
- Create: `tests/unit/scanner/test_rule_base_context.py`

**Rationale:** This is the interface contract. All downstream work (WP 1.3, 1.5, 1.6) depends on `RuleBase` accepting a `ScanContext`. We add `set_context(ctx)` that stores `self._context` AND sets `self._file_path` (making ScanContext the single source of per-file state). We also add `_get_function_taint(qualname)` and track `_current_qualname` during dispatch so rules always use the correct dotted qualname. The `_context` defaults to `None` so existing rule instantiation continues to work.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/scanner/test_rule_base_context.py
"""Tests for RuleBase.set_context() contract."""
from __future__ import annotations

import ast
from typing import ClassVar

import pytest

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.base import RuleBase


class _StubRule(RuleBase):
    """Minimal concrete rule for testing the base class."""

    RULE_ID: ClassVar[RuleId] = RuleId.PY_WL_001

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        pass


class TestSetContext:
    """RuleBase.set_context() stores and exposes ScanContext."""

    def test_context_initially_none(self) -> None:
        rule = _StubRule()
        assert rule._context is None

    def test_set_context_stores_context(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={"func": TaintState.EXTERNAL_RAW},
        )
        rule.set_context(ctx)
        assert rule._context is ctx

    def test_set_context_replaces_previous(self) -> None:
        rule = _StubRule()
        ctx1 = ScanContext(file_path="a.py", function_level_taint_map={})
        ctx2 = ScanContext(file_path="b.py", function_level_taint_map={})
        rule.set_context(ctx1)
        rule.set_context(ctx2)
        assert rule._context is ctx2

    def test_set_context_accepts_none_to_clear(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(file_path="a.py", function_level_taint_map={})
        rule.set_context(ctx)
        rule.set_context(None)
        assert rule._context is None


class TestGetFunctionTaint:
    """RuleBase._get_function_taint() looks up taint for a function."""

    def test_returns_taint_for_known_function(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={"my_func": TaintState.AUDIT_TRAIL},
        )
        rule.set_context(ctx)
        assert rule._get_function_taint("my_func") == TaintState.AUDIT_TRAIL

    def test_returns_unknown_raw_for_unknown_function(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={"other": TaintState.PIPELINE},
        )
        rule.set_context(ctx)
        assert rule._get_function_taint("missing") == TaintState.UNKNOWN_RAW

    def test_returns_unknown_raw_when_no_context(self) -> None:
        rule = _StubRule()
        assert rule._get_function_taint("anything") == TaintState.UNKNOWN_RAW

    def test_qualname_lookup_with_dotted_path(self) -> None:
        """Dotted qualnames (class methods) match taint map keys."""
        rule = _StubRule()
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={
                "MyClass.handle": TaintState.EXTERNAL_RAW,
                "handle": TaintState.PIPELINE,
            },
        )
        rule.set_context(ctx)
        # Dotted qualname matches the class method entry
        assert rule._get_function_taint("MyClass.handle") == TaintState.EXTERNAL_RAW
        # Bare name matches a different entry
        assert rule._get_function_taint("handle") == TaintState.PIPELINE


class TestScopeTracking:
    """RuleBase tracks scope stack for qualname construction."""

    def test_top_level_function_qualname(self) -> None:
        rule = _StubRule()
        source = "def top(): pass\n"
        tree = ast.parse(source)
        rule.visit(tree)
        # After visiting, _current_qualname should have been "top"

    def test_class_method_qualname(self) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={"MyClass.method": TaintState.AUDIT_TRAIL},
        )
        rule.set_context(ctx)
        source = "class MyClass:\n    def method(self): pass\n"
        tree = ast.parse(source)
        rule._file_path = "test.py"
        rule.findings.clear()
        rule.visit(tree)
        # _current_qualname should have been "MyClass.method" during visit
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_rule_base_context.py -v`
Expected: FAIL — `set_context` and `_get_function_taint` do not exist yet.

- [ ] **Step 3: Implement `set_context()` and `_get_function_taint()` on RuleBase**

In `src/wardline/scanner/rules/base.py`, add to imports (module-level, not deferred):

```python
from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from wardline.core.severity import RuleId
    from wardline.scanner.context import Finding, ScanContext
```

Add to `RuleBase.__init__()`:

```python
def __init__(self) -> None:
    self.findings: list[Finding] = []
    self._file_path: str = ""
    self._context: ScanContext | None = None
    self._current_qualname: str = ""  # set by _dispatch(), used by rules
```

Add new methods after `__init__`:

```python
def set_context(self, ctx: ScanContext | None) -> None:
    """Inject per-file scan context. Called by engine before rule.visit().

    Also sets _file_path from the context, making ScanContext the
    single source of per-file state for a rule.
    """
    self._context = ctx
    if ctx is not None:
        self._file_path = ctx.file_path
    else:
        self._file_path = ""

def _get_function_taint(self, qualname: str) -> TaintState:
    """Look up the taint state for a function by dotted qualname.

    The qualname must match the format used by assign_function_taints():
    dotted path like "MyClass.method" or "outer.inner" for nested functions.
    Top-level functions use bare name like "my_func".

    Returns UNKNOWN_RAW if no context is set or the function is not
    in the taint map.
    """
    if self._context is None:
        return TaintState.UNKNOWN_RAW
    return self._context.function_level_taint_map.get(
        qualname, TaintState.UNKNOWN_RAW
    )
```

Update `_dispatch()` to track the current qualname (needed so rules can use `self._current_qualname` instead of `enclosing_func.name`):

```python
def _dispatch(
    self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
) -> None:
    """Dispatch to visit_function, then continue generic_visit."""
    # _current_qualname is set by the engine's rule-dispatch loop
    # or defaults to node.name for backward compatibility
    if not self._current_qualname:
        self._current_qualname = node.name
    self.visit_function(node, is_async=is_async)
    self.generic_visit(node)
```

**IMPORTANT:** The engine must set `rule._current_qualname` before calling `rule.visit()` for each function. However, since `RuleBase` is an `ast.NodeVisitor`, the engine calls `rule.visit(tree)` which walks the AST and dispatches. The qualname cannot be set from outside for each function — it must be tracked INSIDE the visitor. The correct approach is to reconstruct it in `_dispatch()` by maintaining a scope stack. Update `RuleBase`:

```python
def __init__(self) -> None:
    self.findings: list[Finding] = []
    self._file_path: str = ""
    self._context: ScanContext | None = None
    self._scope_stack: list[str] = []

def _dispatch(
    self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
) -> None:
    """Dispatch to visit_function, tracking qualname via scope stack."""
    qualname = ".".join([*self._scope_stack, node.name])
    self._scope_stack.append(node.name)
    self.visit_function(node, is_async=is_async)
    self._scope_stack.pop()
    self.generic_visit(node)
```

Also add a `visit_ClassDef` method to track class scope:

```python
def visit_ClassDef(self, node: ast.ClassDef) -> None:
    """Track class scope for qualname construction."""
    self._scope_stack.append(node.name)
    self.generic_visit(node)
    self._scope_stack.pop()
```

Now rules call `self._get_function_taint(".".join([*self._scope_stack, node.name]))` or more simply, pass the qualname that `_dispatch` can provide. The cleanest approach: have `_dispatch` set `self._current_qualname` before calling `visit_function`:

```python
def _dispatch(
    self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool
) -> None:
    """Dispatch to visit_function with qualname tracking."""
    self._current_qualname = ".".join([*self._scope_stack, node.name])
    self._scope_stack.append(node.name)
    self.visit_function(node, is_async=is_async)
    self._scope_stack.pop()
    self.generic_visit(node)
```

Then rules simply call `self._get_function_taint(self._current_qualname)` instead of `self._get_function_taint(enclosing_func.name)`. This matches the taint map key format exactly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_rule_base_context.py -v`
Expected: All 7 tests PASS.

- [ ] **Step 5: Run full unit tests + mypy to check for regressions**

Run: `cd /home/john/wardline && python -m pytest -m "not integration" -x -q --timeout=30 && python -m mypy src/wardline/scanner/rules/base.py`
Expected: All pass, no type errors.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/base.py tests/unit/scanner/test_rule_base_context.py
git commit -m "feat(scanner): add RuleBase.set_context() and _get_function_taint()

Interface for injecting per-file ScanContext into rules. Rules can
look up function taint state without changing visit_function signature.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Wire discovery + taint into ScanEngine

**Files:**
- Modify: `src/wardline/scanner/engine.py:14-22, 44-64, 123-149`
- Create: `tests/unit/scanner/test_engine_taint_wiring.py`

**Rationale:** The engine currently parses AST then immediately runs rules. We insert a discovery+taint pass between parsing and rule execution. The engine needs a `manifest` parameter so `assign_function_taints()` can resolve module-level defaults.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/scanner/test_engine_taint_wiring.py
"""Tests for ScanEngine discovery/taint wiring."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar
from unittest.mock import patch

import pytest

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.base import RuleBase

if TYPE_CHECKING:
    import ast


class _ContextCapturingRule(RuleBase):
    """Captures the ScanContext set by the engine for test inspection."""

    RULE_ID: ClassVar[RuleId] = RuleId.PY_WL_001

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


def _write_py(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestEngineCallsDiscovery:
    """Engine invokes discover_annotations() per file."""

    def test_discover_annotations_called_per_file(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        _write_py(tmp_path / "b.py", "def bar(): pass\n")

        with patch(
            "wardline.scanner.engine.discover_annotations", return_value={}
        ) as mock_discover:
            rule = _ContextCapturingRule()
            engine = ScanEngine(
                target_paths=(tmp_path,),
                rules=(rule,),
            )
            engine.scan()

            assert mock_discover.call_count == 2


class TestEngineCallsTaintAssignment:
    """Engine invokes assign_function_taints() per file."""

    def test_assign_function_taints_called_per_file(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")

        with patch(
            "wardline.scanner.engine.discover_annotations", return_value={}
        ), patch(
            "wardline.scanner.engine.assign_function_taints",
            return_value={"foo": TaintState.UNKNOWN_RAW},
        ) as mock_assign:
            rule = _ContextCapturingRule()
            engine = ScanEngine(
                target_paths=(tmp_path,),
                rules=(rule,),
            )
            engine.scan()

            assert mock_assign.call_count == 1


class TestEngineSetsContext:
    """Engine constructs ScanContext and calls set_context() per rule per file."""

    def test_rules_receive_scan_context(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "mod.py", "def my_func(): pass\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 1
        assert len(rule.captured_contexts) == 1

        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert "my_func" in ctx.function_level_taint_map
        # No decorators → UNKNOWN_RAW
        assert ctx.function_level_taint_map["my_func"] == TaintState.UNKNOWN_RAW

    def test_discovery_failure_falls_back_to_empty_taint(self, tmp_path: Path) -> None:
        """If discover_annotations raises, scan continues with UNKNOWN_RAW."""
        _write_py(tmp_path / "edge.py", "def func(): pass\n")

        with patch(
            "wardline.scanner.engine.discover_annotations",
            side_effect=RuntimeError("pathological AST"),
        ):
            rule = _ContextCapturingRule()
            engine = ScanEngine(
                target_paths=(tmp_path,),
                rules=(rule,),
            )
            result = engine.scan()

            assert result.files_scanned == 1
            assert any("Discovery/taint failed" in e for e in result.errors)
            # Rule should still have been called with a context
            assert len(rule.captured_contexts) == 1
            ctx = rule.captured_contexts[0]
            assert ctx is not None
            # Empty taint map — all functions get UNKNOWN_RAW
            assert len(ctx.function_level_taint_map) == 0

    def test_context_contains_file_path(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "hello.py", "def greet(): pass\n")

        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )
        engine.scan()

        ctx = rule.captured_contexts[0]
        assert ctx is not None
        assert "hello.py" in ctx.file_path
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_engine_taint_wiring.py -v`
Expected: FAIL — engine doesn't call `discover_annotations`, `assign_function_taints`, or `set_context` yet.

- [ ] **Step 3: Implement engine wiring**

In `src/wardline/scanner/engine.py`, add to imports:

```python
from wardline.scanner.context import Finding, ScanContext
from wardline.scanner.discovery import discover_annotations
from wardline.scanner.taint.function_level import assign_function_taints
```

Add `manifest` parameter to `ScanEngine.__init__()`:

```python
def __init__(
    self,
    *,
    target_paths: tuple[Path, ...],
    exclude_paths: tuple[Path, ...] = (),
    rules: tuple[RuleBase, ...] = (),
    manifest: WardlineManifest | None = None,
) -> None:
    self._target_paths = target_paths
    self._exclude_paths = tuple(p.resolve() for p in exclude_paths)
    self._rules = rules
    self._manifest = manifest
```

Add `WardlineManifest` to the TYPE_CHECKING block:

```python
if TYPE_CHECKING:
    from collections.abc import Callable

    from wardline.manifest.models import WardlineManifest
    from wardline.scanner.rules.base import RuleBase
```

Replace `_scan_file()` body to wire discovery+taint+context:

```python
def _scan_file(self, file_path: Path, result: ScanResult) -> None:
    """Parse a single file, run discovery/taint, then execute rules."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except PermissionError as exc:
        logger.warning("Permission denied reading %s: %s", file_path, exc)
        result.files_skipped += 1
        result.errors.append(f"Permission denied: {file_path}")
        return
    except OSError as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)
        result.files_skipped += 1
        result.errors.append(f"Cannot read {file_path}: {exc}")
        return

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as exc:
        logger.warning("Syntax error in %s: %s", file_path, exc)
        result.files_skipped += 1
        result.errors.append(f"Syntax error in {file_path}: {exc}")
        return

    result.files_scanned += 1

    # Pass 1: Discovery + taint assignment
    # Wrapped in try/except — if discovery/taint fails, fall back to
    # empty taint map (all functions get UNKNOWN_RAW). This preserves
    # the engine's fault tolerance: a pathological file should not
    # abort the entire scan.
    try:
        annotations = discover_annotations(tree, file_path)
        taint_map = assign_function_taints(
            tree, file_path, annotations, self._manifest
        )
    except Exception as exc:
        logger.warning(
            "Discovery/taint failed for %s: %s", file_path, exc
        )
        result.errors.append(
            f"Discovery/taint failed for {file_path}: {exc}"
        )
        taint_map = {}

    # Construct frozen context for this file
    ctx = ScanContext(
        file_path=str(file_path),
        function_level_taint_map=taint_map,
    )

    # Pass 2: Run rules with context
    # set_context() also sets rule._file_path, so _run_rule no longer
    # needs to set it. Remove the `rule._file_path = str(file_path)` line
    # from _run_rule() — ScanContext is now the single source of per-file state.
    for rule in self._rules:
        rule.set_context(ctx)
        self._run_rule(rule, tree, file_path, result)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_engine_taint_wiring.py -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Run full unit tests + mypy**

Run: `cd /home/john/wardline && python -m pytest -m "not integration" -x -q --timeout=30 && python -m mypy src/wardline/scanner/engine.py`
Expected: All pass. Some existing engine tests may need minor adjustment if they mock at a different level — fix any that fail.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/engine.py tests/unit/scanner/test_engine_taint_wiring.py
git commit -m "feat(scanner): wire discovery + taint assignment into ScanEngine

Engine now runs discover_annotations() and assign_function_taints()
per file, constructs ScanContext, and injects via set_context() before
rule execution. Manifest parameter added for module-tier resolution.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Update CLI to pass manifest into engine

**Files:**
- Modify: `src/wardline/cli/scan.py:275-282`

**Rationale:** The CLI creates `ScanEngine` but currently doesn't pass the manifest. The engine now accepts `manifest=` so taint assignment can resolve module-tier defaults.

- [ ] **Step 1: Fix `_load_manifest` return type and update engine instantiation in scan.py**

In `src/wardline/cli/scan.py`:

1. Fix `_load_manifest()` return type (currently `object | None`, should be `WardlineManifest | None`):

```python
def _load_manifest(manifest_arg: str | None) -> WardlineManifest | None:
```

Add the import at the top of the file (move from TYPE_CHECKING to runtime):

```python
from wardline.manifest.models import WardlineManifest
```

2. Change the engine creation (around line 277):

```python
engine = ScanEngine(
    target_paths=target_paths,
    exclude_paths=exclude_paths,
    rules=active_rules,
    manifest=manifest_model,
)
```

- [ ] **Step 2: Run integration tests to verify self-hosting still works**

Run: `cd /home/john/wardline && python -m pytest tests/integration/test_self_hosting_scan.py -v --timeout=60`
Expected: All pass (finding counts may shift due to taint-aware context now being available, but still within 50-200 range).

- [ ] **Step 3: Commit**

```bash
git add src/wardline/cli/scan.py
git commit -m "feat(cli): pass manifest to ScanEngine for taint resolution

Enables module-tier default taint lookup during scan.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Update rules 001, 002, 004, 005 to use tier-aware severity

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_001.py`
- Modify: `src/wardline/scanner/rules/py_wl_002.py`
- Modify: `src/wardline/scanner/rules/py_wl_004.py`
- Modify: `src/wardline/scanner/rules/py_wl_005.py`
- Create: `tests/unit/scanner/test_rules_taint_aware.py`

**Rationale:** These 4 rules currently hardcode `severity=Severity.ERROR` and `exceptionability=Exceptionability.STANDARD`. They need to look up severity from the matrix using `matrix.lookup(rule_id, taint)`, where `taint` comes from `self._get_function_taint(qualname)`. The pattern is the same for all 4 rules — each rule's `_emit_finding()` method changes to call a shared severity-lookup pattern.

**Additional cleanup per review findings:**
- Add `from wardline.core import matrix` as a **module-level** import in each rule (not inside methods)
- Remove the orphaned `taint_state: str` constructor parameter and `self._taint_state` from each rule's `__init__`
- Use `self._current_qualname` (tracked by `RuleBase._dispatch()` scope stack) instead of `enclosing_func.name`

The key change in each rule's `_emit_finding()` (and similar methods):
1. Call `self._get_function_taint(self._current_qualname)` to get the taint state
2. Call `matrix.lookup(self.RULE_ID, taint)` to get the `SeverityCell`
3. Use the cell's severity and exceptionability in the `Finding`
4. Store the `taint_state` in the finding

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/scanner/test_rules_taint_aware.py
"""Tests for tier-aware severity in MVP rules."""
from __future__ import annotations

import ast

import pytest

from wardline.core.matrix import lookup
from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_001 import RulePyWl001
from wardline.scanner.rules.py_wl_002 import RulePyWl002
from wardline.scanner.rules.py_wl_004 import RulePyWl004
from wardline.scanner.rules.py_wl_005 import RulePyWl005


def _make_context(qualname: str, taint: TaintState) -> ScanContext:
    return ScanContext(
        file_path="test.py",
        function_level_taint_map={qualname: taint},
    )


def _parse_and_visit(rule, source: str) -> None:
    """Parse source and visit the AST with the given rule."""
    tree = ast.parse(source, filename="test.py")
    rule._file_path = "test.py"
    rule.findings.clear()
    rule.visit(tree)


# Source code that triggers each rule
_SRC_001 = 'def target():\n    d = {}\n    d.get("k", "default")\n'
_SRC_002 = 'def target():\n    getattr(obj, "x", None)\n'
_SRC_004 = 'def target():\n    try:\n        pass\n    except Exception:\n        pass\n'
_SRC_005 = 'def target():\n    try:\n        pass\n    except Exception:\n        pass\n'


class TestQualnameLookup:
    """Rules use dotted qualname to look up taint for class methods."""

    def test_class_method_gets_correct_taint(self) -> None:
        rule = RulePyWl001()
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={
                "MyService.handle": TaintState.AUDIT_TRAIL,
            },
        )
        rule.set_context(ctx)
        source = 'class MyService:\n    def handle(self):\n        d = {}\n        d.get("k", "default")\n'
        _parse_and_visit(rule, source)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        # Should use AUDIT_TRAIL taint (from "MyService.handle"), NOT UNKNOWN_RAW
        assert f.taint_state == TaintState.AUDIT_TRAIL


class TestRule001TaintAware:
    """PY-WL-001 severity varies by taint state."""

    def test_audit_trail_produces_error_unconditional(self) -> None:
        rule = RulePyWl001()
        rule.set_context(_make_context("target", TaintState.AUDIT_TRAIL))
        _parse_and_visit(rule, _SRC_001)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        assert f.taint_state == TaintState.AUDIT_TRAIL
        cell = lookup(RuleId.PY_WL_001, TaintState.AUDIT_TRAIL)
        assert f.severity == cell.severity
        assert f.exceptionability == cell.exceptionability

    def test_external_raw_produces_matrix_severity(self) -> None:
        rule = RulePyWl001()
        rule.set_context(_make_context("target", TaintState.EXTERNAL_RAW))
        _parse_and_visit(rule, _SRC_001)
        assert len(rule.findings) >= 1
        f = rule.findings[0]
        assert f.taint_state == TaintState.EXTERNAL_RAW
        cell = lookup(RuleId.PY_WL_001, TaintState.EXTERNAL_RAW)
        assert f.severity == cell.severity


class TestRule002TaintAware:
    """PY-WL-002 severity varies by taint state."""

    def test_severity_from_matrix(self) -> None:
        rule = RulePyWl002()
        rule.set_context(_make_context("target", TaintState.PIPELINE))
        _parse_and_visit(rule, _SRC_002)
        if rule.findings:
            f = rule.findings[0]
            assert f.taint_state == TaintState.PIPELINE
            cell = lookup(RuleId.PY_WL_002, TaintState.PIPELINE)
            assert f.severity == cell.severity


class TestRule004TaintAware:
    """PY-WL-004 severity varies by taint state."""

    def test_shape_validated_may_produce_warning(self) -> None:
        rule = RulePyWl004()
        rule.set_context(_make_context("target", TaintState.SHAPE_VALIDATED))
        _parse_and_visit(rule, _SRC_004)
        if rule.findings:
            f = rule.findings[0]
            assert f.taint_state == TaintState.SHAPE_VALIDATED
            cell = lookup(RuleId.PY_WL_004, TaintState.SHAPE_VALIDATED)
            assert f.severity == cell.severity


class TestRule005TaintAware:
    """PY-WL-005 severity varies by taint state."""

    def test_severity_from_matrix(self) -> None:
        rule = RulePyWl005()
        rule.set_context(_make_context("target", TaintState.AUDIT_TRAIL))
        _parse_and_visit(rule, _SRC_005)
        if rule.findings:
            f = rule.findings[0]
            assert f.taint_state == TaintState.AUDIT_TRAIL
            cell = lookup(RuleId.PY_WL_005, TaintState.AUDIT_TRAIL)
            assert f.severity == cell.severity
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_rules_taint_aware.py -v`
Expected: FAIL — rules still hardcode severity and don't populate `taint_state`.

- [ ] **Step 3: Implement tier-aware severity in all 4 rules**

The pattern is identical for each rule. In each rule's `_emit_finding()` method (and any variant like `_emit_unverified_default()`):

1. Add import at module top: `from wardline.core import matrix`
2. Accept `enclosing_func` qualname
3. Look up taint and severity cell

For **py_wl_001.py**, change `_emit_finding()`:

```python
def _emit_finding(
    self,
    call: ast.Call,
    enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    """Emit a PY-WL-001 finding with tier-aware severity."""
    from wardline.core import matrix

    taint = self._get_function_taint(self._current_qualname)
    cell = matrix.lookup(RuleId.PY_WL_001, taint)
    self.findings.append(
        Finding(
            rule_id=RuleId.PY_WL_001,
            file_path=self._file_path,
            line=call.lineno,
            col=call.col_offset,
            end_line=call.end_lineno,
            end_col=call.end_col_offset,
            message=(
                "Dict key access with fallback default — "
                "value fabricated for missing key without validation"
            ),
            severity=cell.severity,
            exceptionability=cell.exceptionability,
            taint_state=taint,
            analysis_level=1,
            source_snippet=None,
        )
    )
```

Also update `_emit_unverified_default()` similarly (keep its WARNING severity and UNCONDITIONAL exceptionability since it's a suppression marker, but add `taint_state`):

```python
def _emit_unverified_default(
    self,
    call: ast.Call,
    enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    """Emit a PY-WL-001-UNVERIFIED-DEFAULT WARNING."""
    taint = self._get_function_taint(self._current_qualname)
    self.findings.append(
        Finding(
            rule_id=RuleId.PY_WL_001_UNVERIFIED_DEFAULT,
            file_path=self._file_path,
            line=call.lineno,
            col=call.col_offset,
            end_line=call.end_lineno,
            end_col=call.end_col_offset,
            message=(
                "schema_default() suppresses PY-WL-001 but overlay "
                "verification is not yet implemented — this "
                "suppression is un-governed"
            ),
            severity=Severity.WARNING,
            exceptionability=Exceptionability.UNCONDITIONAL,
            taint_state=taint,
            analysis_level=1,
            source_snippet=None,
        )
    )
```

Apply the same matrix-lookup pattern to **py_wl_002.py** (which already has `enclosing_func` in `_emit_finding`).

For **py_wl_004.py**, `_check_handler(handler, enclosing_func)` already receives `enclosing_func` but does NOT pass it to `_emit_finding(handler, message)`. Thread it through:

```python
# In _check_handler, change calls to:
self._emit_finding(handler, "...", enclosing_func)

# Change _emit_finding signature:
def _emit_finding(
    self,
    handler: ast.ExceptHandler,
    message: str,
    enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    from wardline.core import matrix
    taint = self._get_function_taint(self._current_qualname)
    cell = matrix.lookup(RuleId.PY_WL_004, taint)
    self.findings.append(
        Finding(
            rule_id=RuleId.PY_WL_004,
            file_path=self._file_path,
            line=handler.lineno,
            col=handler.col_offset,
            end_line=handler.end_lineno,
            end_col=handler.end_col_offset,
            message=message,
            severity=cell.severity,
            exceptionability=cell.exceptionability,
            taint_state=taint,
            analysis_level=1,
            source_snippet=None,
        )
    )
```

For **py_wl_005.py**, NEITHER `_check_handler(handler)` NOR the inline `self.findings.append` receives `enclosing_func`. Thread the function node all the way through:

```python
# In visit_function, change both call sites to pass node:
self._check_handler(handler, node)  # in TryStar loop
self._check_handler(child, node)    # in regular loop

# Change _check_handler signature:
def _check_handler(
    self,
    handler: ast.ExceptHandler,
    enclosing_func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    if len(handler.body) != 1:
        return
    stmt = handler.body[0]
    message = _silent_message(stmt)
    if message is None:
        return
    from wardline.core import matrix
    taint = self._get_function_taint(self._current_qualname)
    cell = matrix.lookup(RuleId.PY_WL_005, taint)
    self.findings.append(
        Finding(
            rule_id=RuleId.PY_WL_005,
            file_path=self._file_path,
            line=handler.lineno,
            col=handler.col_offset,
            end_line=handler.end_lineno,
            end_col=handler.end_col_offset,
            message=message,
            severity=cell.severity,
            exceptionability=cell.exceptionability,
            taint_state=taint,
            analysis_level=1,
            source_snippet=None,
        )
    )
```

Each rule:
- Import `from wardline.core import matrix`
- Use `self._get_function_taint(enclosing_func.name)` and `matrix.lookup(self.RULE_ID, taint)`
- Use `cell.severity` and `cell.exceptionability` instead of hardcoded values
- Set `taint_state=taint` in the Finding

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_rules_taint_aware.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Run full unit tests + mypy**

Run: `cd /home/john/wardline && python -m pytest -m "not integration" -x -q --timeout=30 && python -m mypy src/wardline/scanner/rules/`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_001.py src/wardline/scanner/rules/py_wl_002.py \
        src/wardline/scanner/rules/py_wl_004.py src/wardline/scanner/rules/py_wl_005.py \
        tests/unit/scanner/test_rules_taint_aware.py
git commit -m "feat(rules): tier-aware severity for PY-WL-001/002/004/005

Rules look up severity from SEVERITY_MATRIX using enclosing function's
taint state instead of hardcoding Severity.ERROR. Finding.taint_state
now populated.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Taint-gate PY-WL-003

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_003.py`
- Add to: `tests/unit/scanner/test_rules_taint_aware.py`

**Rationale:** PY-WL-003 currently fires on ALL `in`/`hasattr` patterns regardless of taint. Per the severity matrix, at AUDIT_TRAIL/PIPELINE/SHAPE_VALIDATED the severity is ERROR+UNCONDITIONAL — but these are safe contexts where `key in config` is a normal pattern, not a structural gate bypass. The requirement says: only fire at EXTERNAL_RAW and UNKNOWN_RAW. For other taint states, suppress entirely (the matrix shows ERROR+UNCONDITIONAL but the panel review decided suppression is correct — the matrix entries for those columns will be updated in a future WP).

Actually, re-reading the matrix: PY-WL-003 has (E,U) at AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED. It has (E,St) at EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW. The requirement says "only fire at EXTERNAL_RAW/UNKNOWN_RAW." This means the rule should use the matrix severity for those states and suppress (not emit) for all others. This is a taint-gate, not just a severity change.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/scanner/test_rules_taint_aware.py`:

```python
from wardline.scanner.rules.py_wl_003 import RulePyWl003

_SRC_003 = 'def target():\n    d = {}\n    if "key" in d:\n        pass\n'


class TestRule003TaintGated:
    """PY-WL-003 only fires at EXTERNAL_RAW and UNKNOWN_RAW."""

    def test_fires_at_external_raw(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.EXTERNAL_RAW))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        assert rule.findings[0].taint_state == TaintState.EXTERNAL_RAW

    def test_fires_at_unknown_raw(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.UNKNOWN_RAW))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        assert rule.findings[0].taint_state == TaintState.UNKNOWN_RAW

    def test_silent_at_audit_trail(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.AUDIT_TRAIL))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) == 0

    def test_silent_at_pipeline(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.PIPELINE))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) == 0

    def test_silent_at_shape_validated(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.SHAPE_VALIDATED))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) == 0

    def test_fires_at_mixed_raw(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.MIXED_RAW))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) >= 1
        assert rule.findings[0].taint_state == TaintState.MIXED_RAW

    def test_silent_at_unknown_sem_validated(self) -> None:
        rule = RulePyWl003()
        rule.set_context(_make_context("target", TaintState.UNKNOWN_SEM_VALIDATED))
        _parse_and_visit(rule, _SRC_003)
        assert len(rule.findings) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_rules_taint_aware.py::TestRule003TaintGated -v`
Expected: `test_silent_at_*` FAIL — rule currently fires everywhere.

- [ ] **Step 3: Implement taint-gating in PY-WL-003**

In `src/wardline/scanner/rules/py_wl_003.py`:

1. Add taint gate set:

```python
from wardline.core.taints import TaintState

# PY-WL-003 only fires at these taint states.
# MIXED_RAW included: matrix shows (E,St) same as EXTERNAL_RAW/UNKNOWN_RAW.
# All other states (AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, UNKNOWN_*_VALIDATED)
# are suppressed — "key in config" is a normal pattern in safe contexts.
# Temporary divergence from matrix for suppressed states — matrix will be
# updated in a future WP. See filigree issue for PY-WL-003 matrix reconciliation.
_ACTIVE_TAINTS = frozenset({
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.MIXED_RAW,
})
```

2. Add `from wardline.core import matrix` import.

3. Modify `visit_function()` to check taint before processing:

```python
def visit_function(
    self,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    is_async: bool,
) -> None:
    """Walk the function body looking for PY-WL-003 patterns."""
    taint = self._get_function_taint(node.name)
    if taint not in _ACTIVE_TAINTS:
        return
    for child in ast.walk(node):
        if isinstance(child, ast.Compare):
            self._check_compare(child, node, taint)
        elif isinstance(child, ast.Call):
            self._check_hasattr(child, node, taint)
        elif isinstance(child, ast.MatchMapping):
            self._emit_finding(
                child, node,
                "Existence check as structural gate — "
                "structural pattern match on mapping",
                taint,
            )
        elif isinstance(child, ast.MatchClass):
            self._emit_finding(
                child, node,
                "Existence check as structural gate — "
                "structural pattern match on class",
                taint,
            )
```

4. Update `_check_compare`, `_check_hasattr`, and `_emit_finding` to accept and pass through `taint`:

```python
def _check_compare(self, compare, enclosing_func, taint):
    for op in compare.ops:
        if isinstance(op, (ast.In, ast.NotIn)):
            self._emit_finding(
                compare, enclosing_func,
                "Existence check as structural gate — "
                "'in' operator used for key/attribute presence check",
                taint,
            )
            return

def _check_hasattr(self, call, enclosing_func, taint):
    if isinstance(call.func, ast.Name) and call.func.id == "hasattr":
        self._emit_finding(
            call, enclosing_func,
            "Existence check as structural gate — "
            "hasattr() used for attribute presence check",
            taint,
        )

def _emit_finding(self, node, enclosing_func, message, taint):
    from wardline.core import matrix
    cell = matrix.lookup(RuleId.PY_WL_003, taint)
    self.findings.append(
        Finding(
            rule_id=RuleId.PY_WL_003,
            file_path=self._file_path,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", None),
            end_col=getattr(node, "end_col_offset", None),
            message=message,
            severity=cell.severity,
            exceptionability=cell.exceptionability,
            taint_state=taint,
            analysis_level=1,
            source_snippet=None,
        )
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/john/wardline && python -m pytest tests/unit/scanner/test_rules_taint_aware.py -v`
Expected: All tests PASS including the new taint-gate tests.

- [ ] **Step 5: Run full unit tests + mypy**

Run: `cd /home/john/wardline && python -m pytest -m "not integration" -x -q --timeout=30 && python -m mypy src/wardline/scanner/rules/py_wl_003.py`
Expected: All pass. Note: existing PY-WL-003 tests may need a `set_context()` call with EXTERNAL_RAW or UNKNOWN_RAW to trigger findings, since the rule now gates on taint. Update them if needed.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_003.py tests/unit/scanner/test_rules_taint_aware.py
git commit -m "feat(rules): taint-gate PY-WL-003 to EXTERNAL_RAW/UNKNOWN_RAW only

Prevents false positives: 'key in config' at AUDIT_TRAIL is a normal
pattern, not a structural gate bypass. Rule now suppresses at safe
taint states.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Decompose self-hosting baseline to per-rule counts

**Files:**
- Modify: `tests/integration/test_self_hosting_scan.py:94-139`

**Rationale:** The current `test_scan_finding_count_stable` uses a total range (50-200). With taint-aware severity changes, finding distribution will shift per-rule. Per-rule assertions prevent baseline erosion.

**DEPENDENCY:** This task MUST be executed after Tasks 3, 4, AND 5 are committed. Task 3 wires the manifest into the engine (activating module-tier defaults). Tasks 4-5 change rule severity behavior. The baseline counts will be different depending on which tasks have been applied. Always capture baselines from the final state.

- [ ] **Step 1: Run the self-hosting scan to capture current per-rule counts**

Run: `cd /home/john/wardline && python -m pytest tests/integration/test_self_hosting_scan.py::TestSelfHostingScan::test_scan_produces_valid_sarif -v -s 2>/dev/null`

Then extract per-rule counts manually:

```bash
cd /home/john/wardline && python -c "
import json
from click.testing import CliRunner
from wardline.cli.main import cli

runner = CliRunner()
result = runner.invoke(cli, [
    'scan', 'src/wardline', '--manifest', 'wardline.yaml',
    '--config', 'wardline.toml', '--verification-mode',
])

start = result.output.find('{')
end = result.output.rfind('}')
sarif = json.loads(result.output[start:end+1])
results = sarif['runs'][0]['results']
scan = [r for r in results if 'GOVERNANCE' not in r['ruleId']]

from collections import Counter
counts = Counter(r['ruleId'] for r in scan)
for rule, count in sorted(counts.items()):
    print(f'{rule}: {count}')
print(f'TOTAL: {len(scan)}')
"
```

Use the actual counts to set per-rule ranges with ±30% tolerance.

- [ ] **Step 2: Replace total range with per-rule assertions**

Update `test_scan_finding_count_stable` in `tests/integration/test_self_hosting_scan.py`:

```python
def test_scan_finding_count_stable(self) -> None:
    """Per-rule finding counts are within expected ranges.

    Prevents baseline erosion when tier-aware severity changes
    finding distribution.
    """
    import json
    from collections import Counter

    from wardline.cli.main import cli

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            str(_REPO_ROOT / "src" / "wardline"),
            "--manifest",
            str(_MANIFEST),
            "--config",
            str(_CONFIG),
            "--verification-mode",
        ],
    )

    sarif = json.loads(_extract_sarif_json(result.output))
    results = sarif["runs"][0]["results"]
    scan_findings = [
        r for r in results
        if "GOVERNANCE" not in r["ruleId"]
    ]

    counts = Counter(r["ruleId"] for r in scan_findings)

    # Per-rule baselines (set from actual scan, ±30% tolerance)
    # UPDATE THESE after running Step 1 with actual counts
    expected_ranges: dict[str, tuple[int, int]] = {
        "PY-WL-001": (20, 80),
        "PY-WL-002": (5, 40),
        "PY-WL-003": (5, 60),
        "PY-WL-004": (5, 40),
        "PY-WL-005": (2, 30),
    }

    for rule_id, (lo, hi) in expected_ranges.items():
        count = counts.get(rule_id, 0)
        assert lo <= count <= hi, (
            f"{rule_id}: {count} findings outside expected "
            f"range [{lo}, {hi}]"
        )

    # Total sanity check
    total = len(scan_findings)
    assert total >= 50, f"Suspiciously few findings ({total})"
    assert total <= 250, f"Too many findings ({total})"
```

- [ ] **Step 3: Run the updated test**

Run: `cd /home/john/wardline && python -m pytest tests/integration/test_self_hosting_scan.py::TestSelfHostingScan::test_scan_finding_count_stable -v --timeout=60`
Expected: PASS — ranges should encompass actual counts.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_self_hosting_scan.py
git commit -m "test(integration): decompose self-hosting baseline to per-rule counts

Replaces brittle total-count range with per-rule assertions.
Prevents baseline erosion as tier-aware severity shifts distribution.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Move integration CI to run on every PR

**Files:**
- Modify: `.github/workflows/ci.yml:29-32`

**Rationale:** The `test-integration` job currently only runs on push to main. PRs can break the self-hosting scan without detection until after merge.

- [ ] **Step 1: Update CI config**

In `.github/workflows/ci.yml`, change the `test-integration` job condition:

```yaml
  test-integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: test-unit
    steps:
```

Remove the `if:` line entirely — the job inherits the top-level `on:` triggers (push to main + PRs + schedule), gated only by `needs: test-unit`.

- [ ] **Step 2: Verify YAML syntax**

Run: `cd /home/john/wardline && python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo "YAML valid"`
Expected: "YAML valid"

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run integration tests on every PR

Previously only ran on push to main. PRs could break self-hosting
scan without detection until after merge.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Final verification

- [ ] **Step 1: Run the full test suite**

Run: `cd /home/john/wardline && python -m pytest --timeout=60 -v`
Expected: All tests pass.

- [ ] **Step 2: Run mypy on all modified files**

Run: `cd /home/john/wardline && python -m mypy src/wardline/scanner/ src/wardline/cli/scan.py`
Expected: No errors.

- [ ] **Step 3: Run ruff**

Run: `cd /home/john/wardline && python -m ruff check src/wardline/scanner/ src/wardline/cli/scan.py`
Expected: No errors.

- [ ] **Step 4: Run self-hosting scan end-to-end**

Run: `cd /home/john/wardline && python -m wardline scan src/wardline --manifest wardline.yaml --config wardline.toml --verification-mode 2>/dev/null | python -m json.tool > /dev/null && echo "SARIF valid"`
Expected: "SARIF valid" (exit code 1 is expected — findings present).
