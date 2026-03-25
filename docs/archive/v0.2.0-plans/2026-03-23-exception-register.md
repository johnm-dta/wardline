# WP 1.4: Exception Register — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the exception register: loading, AST fingerprint matching, finding suppression with governance controls, and CLI commands for exception lifecycle.

**Architecture:** Ten tasks layered bottom-up: (1) model + schema, (2) scope-stack extraction, (3) fingerprint computation, (4) Finding field additions + qualname backfill, (5) exception loading, (6) RuleId enum + SARIF, (7) exception matching, (8) CLI commands, (9) scan pipeline wiring, (10) integration verification. Each task is independently testable and committable.

**Tech Stack:** Python 3.9+, frozen dataclasses, `ast` module, `hashlib`, Click CLI, `pytest`, SARIF v2.1.0

**Spec:** `docs/superpowers/specs/2026-03-23-exception-register-design.md`

**Errata from WP 1.3 (apply these lessons):**
- Always use absolute paths for scope matching (WP 1.3 F1)
- `except` clauses must be specific, never bare `Exception` (WP 1.3 E2)
- Test with production-realistic paths, not synthetic relative paths (WP 1.3 F2)

---

### Task 1: ExceptionEntry Model + Schema Updates

**Files:**
- Modify: `src/wardline/manifest/models.py:20-35`
- Modify: `src/wardline/manifest/schemas/exceptions.schema.json`
- Modify: `src/wardline/core/severity.py` (add `GovernancePath` enum)
- Test: `tests/unit/manifest/test_models.py`
- Test: `tests/unit/core/test_severity.py`

- [ ] **Step 1: Write tests for new ExceptionEntry fields**

In `tests/unit/manifest/test_models.py`, add:

```python
class TestExceptionEntryNewFields:
    def test_ast_fingerprint_defaults_empty(self) -> None:
        e = ExceptionEntry(
            id="EXC-001", rule="PY-WL-001", taint_state="EXTERNAL_RAW",
            location="src/x.py::fn", exceptionability="STANDARD",
            severity_at_grant="ERROR", rationale="test", reviewer="test",
        )
        assert e.ast_fingerprint == ""

    def test_recurrence_count_defaults_zero(self) -> None:
        e = ExceptionEntry(
            id="EXC-001", rule="PY-WL-001", taint_state="EXTERNAL_RAW",
            location="src/x.py::fn", exceptionability="STANDARD",
            severity_at_grant="ERROR", rationale="test", reviewer="test",
        )
        assert e.recurrence_count == 0

    def test_governance_path_defaults_standard(self) -> None:
        e = ExceptionEntry(
            id="EXC-001", rule="PY-WL-001", taint_state="EXTERNAL_RAW",
            location="src/x.py::fn", exceptionability="STANDARD",
            severity_at_grant="ERROR", rationale="test", reviewer="test",
        )
        assert e.governance_path == "standard"

    def test_refresh_fields_default_none(self) -> None:
        e = ExceptionEntry(
            id="EXC-001", rule="PY-WL-001", taint_state="EXTERNAL_RAW",
            location="src/x.py::fn", exceptionability="STANDARD",
            severity_at_grant="ERROR", rationale="test", reviewer="test",
        )
        assert e.last_refreshed_by is None
        assert e.last_refresh_rationale is None
        assert e.last_refreshed_at is None
```

- [ ] **Step 2: Run tests — verify fail**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestExceptionEntryNewFields -v`
Expected: FAIL (fields don't exist yet)

- [ ] **Step 3: Add fields to ExceptionEntry**

In `src/wardline/manifest/models.py`, add after `agent_originated` (line 35):

```python
    ast_fingerprint: str = ""
    recurrence_count: int = 0
    governance_path: str = "standard"
    last_refreshed_by: str | None = None
    last_refresh_rationale: str | None = None
    last_refreshed_at: str | None = None
```

- [ ] **Step 4: Add GovernancePath enum**

In `src/wardline/core/severity.py`, after `Exceptionability`:

```python
class GovernancePath(StrEnum):
    """Governance path for exception grants."""
    STANDARD = "standard"
    EXPEDITED = "expedited"
```

- [ ] **Step 5: Update exceptions schema**

In `src/wardline/manifest/schemas/exceptions.schema.json`, add `ast_fingerprint` property (NOT in required array) after `governance_path`:

```json
"ast_fingerprint": {
    "type": "string",
    "description": "16-char hex SHA-256 fingerprint of the function AST. Empty = always stale."
},
"last_refreshed_by": {
    "type": ["string", "null"],
    "description": "Who last refreshed this exception's fingerprint."
},
"last_refresh_rationale": {
    "type": ["string", "null"],
    "description": "Rationale for the last fingerprint refresh."
},
"last_refreshed_at": {
    "type": ["string", "null"],
    "format": "date",
    "description": "When the fingerprint was last refreshed (ISO 8601)."
}
```

- [ ] **Step 6: Run tests — verify pass**

Run: `uv run pytest tests/unit/manifest/test_models.py tests/unit/core/test_severity.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/wardline/manifest/models.py src/wardline/core/severity.py src/wardline/manifest/schemas/exceptions.schema.json tests/unit/manifest/test_models.py
git commit -m "feat(models): add ast_fingerprint, governance fields to ExceptionEntry"
```

---

### Task 2: Extract Scope-Stack Utility

**Files:**
- Create: `src/wardline/scanner/_scope.py`
- Modify: `src/wardline/scanner/rules/base.py`
- Test: `tests/unit/scanner/test_scope.py` (new)

**Context:** `RuleBase._dispatch` builds qualnames via a scope stack. The fingerprint module needs the same logic. Extract it into a shared utility to avoid duplication.

- [ ] **Step 1: Write tests for the scope utility**

Create `tests/unit/scanner/test_scope.py`:

```python
"""Tests for wardline.scanner._scope — qualname resolution from AST."""

from __future__ import annotations

import ast
from pathlib import Path

from wardline.scanner._scope import find_function_node, resolve_qualname_at_line


class TestFindFunctionNode:
    def test_top_level_function(self) -> None:
        source = "def foo():\n    pass\n"
        tree = ast.parse(source)
        node = find_function_node(tree, "foo")
        assert node is not None
        assert node.name == "foo"

    def test_class_method(self) -> None:
        source = "class MyClass:\n    def handle(self):\n        pass\n"
        tree = ast.parse(source)
        node = find_function_node(tree, "MyClass.handle")
        assert node is not None
        assert node.name == "handle"

    def test_nested_function(self) -> None:
        source = "def outer():\n    def inner():\n        pass\n"
        tree = ast.parse(source)
        node = find_function_node(tree, "outer.inner")
        assert node is not None
        assert node.name == "inner"

    def test_async_function(self) -> None:
        source = "async def fetch():\n    pass\n"
        tree = ast.parse(source)
        node = find_function_node(tree, "fetch")
        assert node is not None

    def test_nonexistent_returns_none(self) -> None:
        source = "def foo():\n    pass\n"
        tree = ast.parse(source)
        assert find_function_node(tree, "bar") is None

    def test_class_not_found_returns_none(self) -> None:
        source = "class A:\n    def m(self):\n        pass\n"
        tree = ast.parse(source)
        assert find_function_node(tree, "B.m") is None
```

- [ ] **Step 2: Run tests — verify fail**

Run: `uv run pytest tests/unit/scanner/test_scope.py -v`
Expected: FAIL (module doesn't exist)

- [ ] **Step 3: Implement `_scope.py`**

Create `src/wardline/scanner/_scope.py`:

```python
"""Shared qualname resolution from AST — used by RuleBase and fingerprint.

The scope-stack walk mirrors the logic in RuleBase._dispatch and
visit_ClassDef: function/class names are pushed onto a stack, producing
dotted qualnames like "ClassName.method_name".
"""

from __future__ import annotations

import ast


def find_function_node(
    tree: ast.Module,
    qualname: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find a function/method node in *tree* by dotted qualname.

    Walks the AST using a scope stack to match ``qualname`` (e.g.,
    ``"MyClass.handle"``). Returns the first matching node, or None.
    """
    parts = qualname.split(".")
    return _search(tree, parts, 0)


def _search(
    node: ast.AST,
    parts: list[str],
    depth: int,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Recursively search for the function matching parts[depth:]."""
    if depth >= len(parts):
        return None

    target = parts[depth]
    is_final = depth == len(parts) - 1

    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if child.name == target:
                if is_final:
                    return child
                # Search inside function for nested functions
                result = _search(child, parts, depth + 1)
                if result is not None:
                    return result
        elif isinstance(child, ast.ClassDef):
            if child.name == target:
                result = _search(child, parts, depth + 1)
                if result is not None:
                    return result

    return None
```

- [ ] **Step 4: Run tests — verify pass**

Run: `uv run pytest tests/unit/scanner/test_scope.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/_scope.py tests/unit/scanner/test_scope.py
git commit -m "feat(scanner): extract shared scope-stack qualname resolution"
```

---

### Task 3: AST Fingerprint Computation

**Files:**
- Create: `src/wardline/scanner/fingerprint.py`
- Test: `tests/unit/scanner/test_fingerprint.py` (new)

- [ ] **Step 1: Write tests**

Create `tests/unit/scanner/test_fingerprint.py`:

```python
"""Tests for wardline.scanner.fingerprint — AST fingerprint computation."""

from __future__ import annotations

import re
from pathlib import Path

from wardline.scanner.fingerprint import compute_ast_fingerprint


class TestComputeAstFingerprint:
    def test_returns_16_char_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "foo")
        assert result is not None
        assert len(result) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", result)

    def test_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        a = compute_ast_fingerprint(f, "foo")
        b = compute_ast_fingerprint(f, "foo")
        assert a == b

    def test_whitespace_change_same_fingerprint(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        fp1 = compute_ast_fingerprint(f, "foo")

        f.write_text("def foo():\n\n    return 1\n\n", encoding="utf-8")
        fp2 = compute_ast_fingerprint(f, "foo")
        assert fp1 == fp2

    def test_structural_change_different_fingerprint(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        fp1 = compute_ast_fingerprint(f, "foo")

        f.write_text("def foo():\n    x = 1\n    return x\n", encoding="utf-8")
        fp2 = compute_ast_fingerprint(f, "foo")
        assert fp1 != fp2

    def test_nonexistent_file_returns_none(self, tmp_path: Path) -> None:
        assert compute_ast_fingerprint(tmp_path / "nope.py", "foo") is None

    def test_nonexistent_qualname_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    pass\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "bar") is None

    def test_class_method(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("class C:\n    def m(self):\n        pass\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "C.m")
        assert result is not None
        assert len(result) == 16

    def test_nested_function(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def outer():\n    def inner():\n        pass\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "outer.inner")
        assert result is not None

    def test_syntax_error_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "broken") is None
```

- [ ] **Step 2: Run tests — verify fail**

Run: `uv run pytest tests/unit/scanner/test_fingerprint.py -v`

- [ ] **Step 3: Implement**

Create `src/wardline/scanner/fingerprint.py`:

```python
"""AST fingerprint computation for exception staleness detection.

Produces a 16-char hex SHA-256 fingerprint of a function's AST structure.
The fingerprint is rule-independent — any structural change to the function
invalidates ALL exceptions targeting it.
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

from wardline.scanner._scope import find_function_node


def compute_ast_fingerprint(file_path: Path, qualname: str) -> str | None:
    """Compute 16-char hex fingerprint for a function's AST structure.

    Includes Python version in the hash because ``ast.dump()`` output can
    change between minor versions. Python upgrades require
    ``wardline exception refresh --all``.

    Returns None if the file can't be parsed or *qualname* is not found.
    """
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError):
        return None

    func_node = find_function_node(tree, qualname)
    if func_node is None:
        return None

    dump = ast.dump(func_node, include_attributes=False, annotate_fields=True)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    payload = f"{version}|{file_path}|{qualname}|{dump}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
```

- [ ] **Step 4: Run tests — verify pass**

Run: `uv run pytest tests/unit/scanner/test_fingerprint.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/fingerprint.py tests/unit/scanner/test_fingerprint.py
git commit -m "feat(scanner): AST fingerprint computation for exception staleness"
```

---

### Task 4: Finding Field Additions + Qualname Backfill

**Files:**
- Modify: `src/wardline/scanner/context.py:18-37` (Finding dataclass)
- Modify: `src/wardline/scanner/rules/py_wl_001.py` (3 Finding constructions)
- Modify: `src/wardline/scanner/rules/py_wl_002.py` (1 Finding construction)
- Modify: `src/wardline/scanner/rules/py_wl_003.py` (1 Finding construction)
- Modify: `src/wardline/scanner/rules/py_wl_004.py` (1 Finding construction)
- Modify: `src/wardline/scanner/rules/py_wl_005.py` (1 Finding construction)
- Modify: `src/wardline/scanner/engine.py` (TOOL-ERROR Finding construction)
- Test: existing tests must continue passing

**Context:** Add `qualname`, `exception_id`, `exception_expires` to Finding with `kw_only=True`. Then backfill `qualname=self._current_qualname` in every rule's Finding construction. This is a wide but mechanical change.

- [ ] **Step 1: Add fields to Finding**

In `src/wardline/scanner/context.py`, change Finding's decorator:

```python
@dataclass(frozen=True, kw_only=True)
```

Add after `source_snippet` field:

```python
    qualname: str | None = None
    exception_id: str | None = None
    exception_expires: str | None = None
```

- [ ] **Step 2: Run existing tests — check for breakage**

Run: `uv run pytest --tb=short -q`

With `kw_only=True`, all existing Finding constructions that use keyword args will still work. The engine's TOOL-ERROR construction (engine.py) must also use keyword args — check and fix if needed.

- [ ] **Step 3: Backfill qualname in all rule files**

In each rule file, add `qualname=self._current_qualname` to every `Finding(...)` construction:

- `py_wl_001.py`: 3 sites (`_emit_finding`, `_emit_unverified_default` governed path, ungoverned path)
- `py_wl_002.py`: 1 site
- `py_wl_003.py`: 1 site
- `py_wl_004.py`: 1 site
- `py_wl_005.py`: 1 site

Read each file first to find the exact locations. The pattern is adding `qualname=self._current_qualname,` after `source_snippet=...,` in each Finding construction.

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest --tb=short -q`
Expected: All PASS (kw_only + defaults = backward compatible)

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/context.py src/wardline/scanner/rules/ src/wardline/scanner/engine.py
git commit -m "feat(context): add qualname + exception fields to Finding, kw_only=True"
```

---

### Task 5: Exception Loading

**Files:**
- Create: `src/wardline/manifest/exceptions.py`
- Test: `tests/unit/manifest/test_exceptions.py` (new)

- [ ] **Step 1: Write tests**

Create `tests/unit/manifest/test_exceptions.py`:

```python
"""Tests for wardline.manifest.exceptions — exception register loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wardline.manifest.exceptions import load_exceptions
from wardline.manifest.loader import ManifestLoadError


def _write_exceptions(path: Path, entries: list[dict]) -> None:
    data = {
        "$id": "https://wardline.dev/schemas/0.1/exceptions.schema.json",
        "exceptions": entries,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _valid_entry(**overrides) -> dict:
    base = {
        "id": "EXC-001",
        "rule": "PY-WL-001",
        "taint_state": "EXTERNAL_RAW",
        "location": "src/adapters/client.py::Client.handle",
        "exceptionability": "STANDARD",
        "severity_at_grant": "ERROR",
        "rationale": "Schema fallback approved",
        "reviewer": "jsmith",
    }
    base.update(overrides)
    return base


class TestLoadExceptions:
    def test_file_not_found_returns_empty(self, tmp_path: Path) -> None:
        result = load_exceptions(tmp_path)
        assert result == ()

    def test_valid_file_returns_entries(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert len(result) == 1
        assert result[0].id == "EXC-001"
        assert result[0].rule == "PY-WL-001"

    def test_missing_ast_fingerprint_defaults_empty(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert result[0].ast_fingerprint == ""

    def test_ast_fingerprint_preserved(self, tmp_path: Path) -> None:
        entry = _valid_entry(ast_fingerprint="abcdef0123456789")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        result = load_exceptions(tmp_path)
        assert result[0].ast_fingerprint == "abcdef0123456789"

    def test_invalid_schema_raises(self, tmp_path: Path) -> None:
        bad = {"$id": "https://wardline.dev/schemas/0.1/exceptions.schema.json", "exceptions": [{"bad": True}]}
        (tmp_path / "wardline.exceptions.json").write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ManifestLoadError):
            load_exceptions(tmp_path)

    def test_unconditional_cell_raises(self, tmp_path: Path) -> None:
        """Exception targeting UNCONDITIONAL (rule, taint) cell is rejected."""
        # PY-WL-001 with AUDIT_TRAIL is UNCONDITIONAL in the severity matrix
        entry = _valid_entry(rule="PY-WL-001", taint_state="AUDIT_TRAIL")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        with pytest.raises(ManifestLoadError, match="UNCONDITIONAL"):
            load_exceptions(tmp_path)

    def test_optional_fields_default(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert result[0].recurrence_count == 0
        assert result[0].governance_path == "standard"
        assert result[0].expires is None
```

- [ ] **Step 2: Implement `load_exceptions()`**

Create `src/wardline/manifest/exceptions.py`:

```python
"""Exception register loading and validation.

Loads ``wardline.exceptions.json`` from the manifest directory, validates
against the JSON schema, and performs load-time UNCONDITIONAL re-validation
against the severity matrix.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId
from wardline.core.taints import TaintState
from wardline.manifest.loader import ManifestLoadError
from wardline.manifest.models import ExceptionEntry

_SCHEMA_DIR = Path(__file__).parent / "schemas"
_EXCEPTIONS_FILENAME = "wardline.exceptions.json"


def load_exceptions(manifest_dir: Path) -> tuple[ExceptionEntry, ...]:
    """Load and validate wardline.exceptions.json from *manifest_dir*.

    Returns empty tuple if the file does not exist.
    Raises ManifestLoadError on schema or governance validation failure.
    """
    path = manifest_dir / _EXCEPTIONS_FILENAME
    if not path.exists():
        return ()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ManifestLoadError(f"Cannot read {path}: {exc}") from exc

    # Schema validation
    schema_path = _SCHEMA_DIR / "exceptions.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise ManifestLoadError(
            f"Exception register schema validation failed: {exc.message}"
        ) from exc

    # Build entries
    entries: list[ExceptionEntry] = []
    for raw in data.get("exceptions", []):
        entry = ExceptionEntry(
            id=raw["id"],
            rule=raw["rule"],
            taint_state=raw["taint_state"],
            location=raw["location"],
            exceptionability=raw["exceptionability"],
            severity_at_grant=raw["severity_at_grant"],
            rationale=raw["rationale"],
            reviewer=raw["reviewer"],
            expires=raw.get("expires"),
            provenance=raw.get("provenance"),
            agent_originated=raw.get("agent_originated"),
            ast_fingerprint=raw.get("ast_fingerprint", ""),
            recurrence_count=raw.get("recurrence_count", 0),
            governance_path=raw.get("governance_path", "standard"),
            last_refreshed_by=raw.get("last_refreshed_by"),
            last_refresh_rationale=raw.get("last_refresh_rationale"),
            last_refreshed_at=raw.get("last_refreshed_at"),
        )

        # UNCONDITIONAL re-validation
        _validate_not_unconditional(entry, path)

        entries.append(entry)

    return tuple(entries)


def _validate_not_unconditional(entry: ExceptionEntry, path: Path) -> None:
    """Reject exceptions targeting UNCONDITIONAL severity matrix cells."""
    try:
        rule_id = RuleId(entry.rule)
        taint = TaintState(entry.taint_state)
    except ValueError:
        return  # Unknown rule/taint — can't validate, let it through

    cell = matrix.lookup(rule_id, taint)
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        raise ManifestLoadError(
            f"Exception '{entry.id}' targets UNCONDITIONAL cell "
            f"({entry.rule}, {entry.taint_state}) in {path}. "
            f"UNCONDITIONAL findings cannot be excepted."
        )
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/unit/manifest/test_exceptions.py -v`

- [ ] **Step 4: Commit**

```bash
git add src/wardline/manifest/exceptions.py tests/unit/manifest/test_exceptions.py
git commit -m "feat(manifest): exception register loading with UNCONDITIONAL validation"
```

---

### Task 6: RuleId Enum + SARIF Updates

**Files:**
- Modify: `src/wardline/core/severity.py:42-48`
- Modify: `src/wardline/scanner/sarif.py:31-62`
- Test: `tests/unit/core/test_severity.py`
- Test: `tests/unit/scanner/test_sarif.py`

- [ ] **Step 1: Add 5 governance pseudo-rule IDs to RuleId**

In `src/wardline/core/severity.py`, add after existing pseudo-rules:

```python
    GOVERNANCE_STALE_EXCEPTION = "GOVERNANCE-STALE-EXCEPTION"
    GOVERNANCE_UNKNOWN_PROVENANCE = "GOVERNANCE-UNKNOWN-PROVENANCE"
    GOVERNANCE_RECURRING_EXCEPTION = "GOVERNANCE-RECURRING-EXCEPTION"
    GOVERNANCE_BATCH_REFRESH = "GOVERNANCE-BATCH-REFRESH"
    GOVERNANCE_NO_EXPIRY_EXCEPTION = "GOVERNANCE-NO-EXPIRY-EXCEPTION"
```

- [ ] **Step 2: Update SARIF descriptors and pseudo-rule set**

In `src/wardline/scanner/sarif.py`, add to `_RULE_SHORT_DESCRIPTIONS`:

```python
    RuleId.GOVERNANCE_STALE_EXCEPTION: "Stale exception — AST fingerprint mismatch (governance)",
    RuleId.GOVERNANCE_UNKNOWN_PROVENANCE: "Unknown agent provenance on exception (governance)",
    RuleId.GOVERNANCE_RECURRING_EXCEPTION: "Recurring exception — multiple renewals (governance)",
    RuleId.GOVERNANCE_BATCH_REFRESH: "Batch exception refresh performed (governance)",
    RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION: "Exception has no expiry date (governance)",
```

Add all 5 to `_PSEUDO_RULE_IDS` frozenset.

- [ ] **Step 3: Update test_severity.py**

Update `test_canonical_count` to `len(RuleId) == 20`.
Add the 5 new IDs to `test_all_pseudo_rules_are_members`.

- [ ] **Step 4: Add SARIF exclusion test**

In `tests/unit/scanner/test_sarif.py`, add test asserting none of the 5 governance IDs appear in `wardline.implementedRules`.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/unit/core/test_severity.py tests/unit/scanner/test_sarif.py -v`

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/severity.py src/wardline/scanner/sarif.py tests/unit/core/test_severity.py tests/unit/scanner/test_sarif.py
git commit -m "feat(severity): add 5 governance pseudo-rule IDs for exception register"
```

---

### Task 7: Exception Matching + Suppression

**Files:**
- Create: `src/wardline/scanner/exceptions.py`
- Test: `tests/unit/scanner/test_exception_matching.py` (new)

**Context:** This is the core matching logic. For each finding, check for a matching active exception using the four-tuple key. Build an index for O(n+m) matching.

- [ ] **Step 1: Write tests**

Create `tests/unit/scanner/test_exception_matching.py` with tests for:
- Finding with matching active exception → SUPPRESS + exception_id set
- Finding with expired exception → not suppressed
- Finding with fingerprint mismatch → not suppressed + GOVERNANCE-STALE-EXCEPTION
- Finding with UNCONDITIONAL exceptionability → not suppressed
- Finding with no matching exception → unchanged
- Exception with `agent_originated=None` → GOVERNANCE-UNKNOWN-PROVENANCE
- Exception with `recurrence_count >= 2` → GOVERNANCE-RECURRING-EXCEPTION
- Exception with `expires: null` → GOVERNANCE-NO-EXPIRY-EXCEPTION
- `recurrence_count == 1` → no governance finding (boundary test)
- Multiple findings, some matched, some not → correct partition

Use `tmp_path` to create real Python files for fingerprint verification.
Use `datetime.date` injection for expiry testing (add `now` parameter to `apply_exceptions`).

- [ ] **Step 2: Implement `apply_exceptions()`**

Create `src/wardline/scanner/exceptions.py`:

The function should:
1. Build index: `dict[tuple[str, str, str], list[ExceptionEntry]]` keyed on `(rule, taint_state, location)`
2. Cache parsed ASTs per file
3. For each finding with qualname: construct location key `f"{finding.file_path}::{finding.qualname}"`
4. Look up in index
5. For each candidate exception: check expiry, check fingerprint, check exceptionability
6. On match: `dataclasses.replace(finding, severity=SUPPRESS, exceptionability=TRANSPARENT, exception_id=..., exception_expires=...)`
7. Emit governance findings for stale, unknown provenance, recurring, no-expiry
8. Return `(processed_findings, governance_findings)`

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/unit/scanner/test_exception_matching.py -v`

- [ ] **Step 4: Commit**

```bash
git add src/wardline/scanner/exceptions.py tests/unit/scanner/test_exception_matching.py
git commit -m "feat(scanner): exception matching with fingerprint verification"
```

---

### Task 8: CLI Exception Commands

**Files:**
- Create: `src/wardline/cli/exception_cmds.py`
- Modify: `src/wardline/cli/main.py`
- Test: `tests/integration/test_exception_cmds.py` (new)

**Context:** Four Click commands: `add`, `refresh`, `expire`, `review`. The `refresh` command is the most complex — it requires `--actor` and `--rationale`, displays rule context, and has a `--dry-run` mode.

- [ ] **Step 1: Create the command group**

Create `src/wardline/cli/exception_cmds.py` with Click group `exception` and four subcommands.

Key implementation notes:
- `add`: compute fingerprint, validate UNCONDITIONAL, generate UUID, write JSON
- `refresh`: require `--actor` + `--rationale`, display rule context (`_RULE_GOVERNANCE_CONTEXT` dict), recompute fingerprint, do NOT increment `recurrence_count`
- `expire`: set `expires` to today's date
- `review`: scan entries for stale/expired/approaching/provenance/recurring/ratio
- All commands support `--json`
- `refresh --all` requires `--confirm`

- [ ] **Step 2: Register in main.py**

Add to `src/wardline/cli/main.py`:

```python
from wardline.cli.exception_cmds import exception  # noqa: E402
cli.add_command(exception)
```

- [ ] **Step 3: Write integration tests**

Create `tests/integration/test_exception_cmds.py` with Click test runner tests:
- `add` creates valid entry with computed fingerprint
- `add` with UNCONDITIONAL rule → refused
- `refresh` without `--actor` → error
- `refresh` without `--rationale` → error
- `refresh --all` without `--confirm` → error
- `expire` sets expiry date
- `review` lists stale entries
- `add` → code change → `refresh` updates fingerprint (does NOT increment recurrence)
- `expire` → `add` (renewal) increments `recurrence_count`
- `--json` output is valid JSON

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/integration/test_exception_cmds.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/exception_cmds.py src/wardline/cli/main.py tests/integration/test_exception_cmds.py
git commit -m "feat(cli): exception add/refresh/expire/review commands"
```

---

### Task 9: Scan Pipeline Wiring

**Files:**
- Modify: `src/wardline/cli/scan.py`
- Modify: `src/wardline/scanner/sarif.py` (exception property bags)

- [ ] **Step 1: Wire exception loading + matching into scan pipeline**

In `src/wardline/cli/scan.py`, after the engine scan completes (after `result: ScanResult = engine.scan()`), add:

```python
    # --- Apply exception register ---
    from wardline.manifest.exceptions import load_exceptions
    from wardline.scanner.exceptions import apply_exceptions

    exceptions = load_exceptions(manifest_path.parent)
    if exceptions:
        processed, governance = apply_exceptions(
            result.findings, exceptions, project_root=manifest_path.parent
        )
        result.findings = processed + governance
```

`ManifestLoadError` from `load_exceptions` should propagate (abort scan).

- [ ] **Step 2: Update SARIF serialization for exception metadata**

In `src/wardline/scanner/sarif.py`, update `_make_result()` to include `wardline.exceptionId` and `wardline.exceptionExpires` in the result property bag when they are set on the Finding.

Add run-level properties for exception stats.

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest --tb=short -q`

- [ ] **Step 4: Commit**

```bash
git add src/wardline/cli/scan.py src/wardline/scanner/sarif.py
git commit -m "feat(cli): wire exception register into scan pipeline"
```

---

### Task 10: Integration Verification

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest -v --tb=short`
Expected: All PASS

- [ ] **Step 2: Check for stale references**

Run: `grep -rn "UNVERIFIED_DEFAULT" src/ tests/ --include="*.py"` — should be minimal (docs only)

- [ ] **Step 3: Verify enum count**

Run: `uv run pytest tests/unit/core/test_severity.py -v`
Expected: count == 20

- [ ] **Step 4: Run self-hosting scan**

Run: `uv run wardline scan src/wardline/ --json 2>/dev/null | python -m json.tool | head -20`
Expected: Clean run, no crashes

- [ ] **Step 5: Final commit if needed**

```bash
git add -A && git commit -m "test(integration): final verification for WP 1.4"
```
