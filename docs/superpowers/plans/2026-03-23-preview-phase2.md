# `--preview-phase2` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `wardline scan --preview-phase2` flag that outputs a JSON migration impact report showing ungoverned `schema_default()` calls and exception register entries needing re-review.

**Architecture:** Thin post-processing layer. The full scan pipeline runs normally, then a pure function (`build_preview_report`) filters findings into the impact JSON. Three small changes to existing code: new pseudo-rule ID in severity.py, rule ID swap in py_wl_001.py, and `exception_id`/`original_rule` on governance findings in exceptions.py.

**Tech Stack:** Python, Click CLI, frozen dataclasses, JSON serialization.

**Spec:** `docs/superpowers/specs/2026-03-23-preview-phase2-design.md`

---

### File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `src/wardline/core/severity.py:48-60` | Add `PY_WL_001_UNGOVERNED_DEFAULT` to `RuleId` enum |
| Modify | `src/wardline/scanner/sarif.py:31-73` | Add new ID to `_RULE_SHORT_DESCRIPTIONS` and `_PSEUDO_RULE_IDS` |
| Modify | `src/wardline/scanner/rules/py_wl_001.py:177` | Emit new rule ID for ungoverned path |
| Modify | `src/wardline/scanner/context.py:91-120` | Add `exception_id` and `original_rule` params to `make_governance_finding` |
| Modify | `src/wardline/scanner/exceptions.py:160-222` | Pass `exception_id` and `original_rule` through governance finding creation |
| Create | `src/wardline/cli/preview.py` | `build_preview_report()` pure function |
| Modify | `src/wardline/cli/scan.py:149-178,368-419` | Add `--preview-phase2` flag, wire output + exit codes |
| Modify | `tests/unit/core/test_severity.py:43-69` | Bump count 20→21, add new pseudo-rule to membership list |
| Modify | `tests/unit/scanner/test_py_wl_001.py:228-317` | Update 7 assertions to new rule ID |
| Create | `tests/unit/cli/test_preview.py` | Unit tests for `build_preview_report` |
| Create | `tests/integration/test_preview_phase2.py` | Integration tests for `--preview-phase2` CLI flag |

---

### Task 1: Add `PY_WL_001_UNGOVERNED_DEFAULT` to `RuleId` enum

**Files:**
- Modify: `src/wardline/core/severity.py:48-60`
- Modify: `tests/unit/core/test_severity.py:43-69`

- [ ] **Step 1: Update the RuleId count test**

In `tests/unit/core/test_severity.py`, update `test_canonical_count`:

```python
def test_canonical_count(self) -> None:
    """9 canonical rules + 12 pseudo-rule-IDs = 21 total."""
    assert len(RuleId) == 21
```

And add `"PY-WL-001-UNGOVERNED-DEFAULT"` to the `pseudo_ids` list in `test_all_pseudo_rules_are_members`:

```python
pseudo_ids = [
    "PY-WL-001-GOVERNED-DEFAULT",
    "PY-WL-001-UNGOVERNED-DEFAULT",
    "WARDLINE-UNRESOLVED-DECORATOR",
    # ... rest unchanged
]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/core/test_severity.py -v -k "test_canonical_count or test_all_pseudo_rules_are_members"`
Expected: Both FAIL — count is 20, new string not in enum.

- [ ] **Step 3: Add the enum member**

In `src/wardline/core/severity.py`, after line 49 (`PY_WL_001_GOVERNED_DEFAULT`), add:

```python
PY_WL_001_UNGOVERNED_DEFAULT = "PY-WL-001-UNGOVERNED-DEFAULT"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/core/test_severity.py -v -k "test_canonical_count or test_all_pseudo_rules_are_members"`
Expected: Both PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/severity.py tests/unit/core/test_severity.py
git commit -m "feat: add PY_WL_001_UNGOVERNED_DEFAULT pseudo-rule ID to RuleId enum"
```

---

### Task 2: Register new pseudo-rule in SARIF module

**Files:**
- Modify: `src/wardline/scanner/sarif.py:31-73`

- [ ] **Step 1: Add to `_RULE_SHORT_DESCRIPTIONS`**

In `src/wardline/scanner/sarif.py`, after the `PY_WL_001_GOVERNED_DEFAULT` entry in `_RULE_SHORT_DESCRIPTIONS` (around line 41), add:

```python
RuleId.PY_WL_001_UNGOVERNED_DEFAULT: "Ungoverned schema_default() — no overlay boundary (diagnostic)",
```

- [ ] **Step 2: Add to `_PSEUDO_RULE_IDS`**

In the `_PSEUDO_RULE_IDS` frozenset (around line 62), after `RuleId.PY_WL_001_GOVERNED_DEFAULT`, add:

```python
RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
```

- [ ] **Step 3: Run existing tests to verify nothing breaks**

Run: `pytest tests/unit/scanner/test_sarif.py -v`
Expected: All PASS. (Registry sync tests should still pass because the new ID is pseudo, not canonical.)

- [ ] **Step 4: Commit**

```bash
git add src/wardline/scanner/sarif.py
git commit -m "feat: register PY_WL_001_UNGOVERNED_DEFAULT in SARIF pseudo-rule sets"
```

---

### Task 3: Emit new rule ID for ungoverned `schema_default()`

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_001.py:177`
- Modify: `tests/unit/scanner/test_py_wl_001.py:228-317`

- [ ] **Step 1: Update the 7 test assertions**

In `tests/unit/scanner/test_py_wl_001.py`, in the `TestSchemaDefaultUngoverned` class, change all 7 assertions from `RuleId.PY_WL_001` to `RuleId.PY_WL_001_UNGOVERNED_DEFAULT`. The tests are at approximately these lines:

- Line 237: `assert f.rule_id == RuleId.PY_WL_001` → `assert f.rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT`
- Line 251: same change
- Line 264: same change
- Line 278: same change
- Line 292: same change
- Line 303: same change
- Line 317: same change

Ensure `RuleId` import at the top of the test file already includes the enum (it should — just verify `PY_WL_001_UNGOVERNED_DEFAULT` is accessible via `RuleId.PY_WL_001_UNGOVERNED_DEFAULT`).

**IMPORTANT:** Do NOT change any tests outside `TestSchemaDefaultUngoverned`. In particular, `test_non_schema_default_unchanged` (if it exists in the class or a sibling class) must remain `RuleId.PY_WL_001` — it tests the `.get()`/`setdefault` path which still emits the original rule ID.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/scanner/test_py_wl_001.py -v -k "TestSchemaDefaultUngoverned"`
Expected: All 7 FAIL — rule still emits `PY_WL_001`.

- [ ] **Step 3: Change the rule emission**

In `src/wardline/scanner/rules/py_wl_001.py`, line 177, change:

```python
rule_id=RuleId.PY_WL_001,
```

to:

```python
rule_id=RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
```

This is the only line that changes. The message, severity, exceptionability, and all other fields stay the same.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/scanner/test_py_wl_001.py -v -k "TestSchemaDefaultUngoverned"`
Expected: All 7 PASS.

- [ ] **Step 5: Run the full PY-WL-001 test suite to check for collateral**

Run: `pytest tests/unit/scanner/test_py_wl_001.py -v`
Expected: All PASS. The governed-default tests (`TestSchemaDefaultGoverned`) and regular dict-access tests should be unaffected.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_001.py tests/unit/scanner/test_py_wl_001.py
git commit -m "feat: emit PY_WL_001_UNGOVERNED_DEFAULT for ungoverned schema_default()"
```

---

### Task 4: Add `exception_id` and `original_rule` to governance findings

**Files:**
- Modify: `src/wardline/scanner/context.py:91-120`
- Modify: `src/wardline/scanner/exceptions.py:160-222`

- [ ] **Step 1: Write a test for `make_governance_finding` with `exception_id`**

Append to the existing `tests/unit/scanner/test_context.py` (do NOT overwrite — it already contains `TestFinding`, `TestScanContext`, and `TestWardlineAnnotation` suites):

```python
from wardline.core.severity import RuleId, Severity
from wardline.scanner.context import make_governance_finding


def test_make_governance_finding_with_exception_id():
    f = make_governance_finding(
        RuleId.GOVERNANCE_STALE_EXCEPTION,
        "test message",
        exception_id="EXC-abc12345",
        original_rule="PY-WL-001",
    )
    assert f.exception_id == "EXC-abc12345"
    assert f.original_rule == "PY-WL-001"


def test_make_governance_finding_defaults_none():
    f = make_governance_finding(
        RuleId.GOVERNANCE_STALE_EXCEPTION,
        "test message",
    )
    assert f.exception_id is None
    assert f.original_rule is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/scanner/test_context.py -v -k "test_make_governance_finding"`
Expected: FAIL — `make_governance_finding` doesn't accept `exception_id` or `original_rule`; `Finding` has no `original_rule` field.

- [ ] **Step 3: Add `original_rule` field to `Finding` dataclass**

In `src/wardline/scanner/context.py`, after line 42 (`exception_expires`), add:

```python
original_rule: str | None = None
```

- [ ] **Step 4: Add params to `make_governance_finding`**

In `src/wardline/scanner/context.py`, update the `make_governance_finding` signature (lines 91-99) to accept the new params:

```python
def make_governance_finding(
    rule_id: RuleId,
    message: str,
    *,
    file_path: str = "<governance>",
    line: int = 1,
    severity: Severity = Severity.WARNING,
    qualname: str | None = None,
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
```

And in the `Finding(...)` constructor call (lines 106-120), add after `qualname=qualname,`:

```python
exception_id=exception_id,
original_rule=original_rule,
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/unit/scanner/test_context.py -v -k "test_make_governance_finding"`
Expected: Both PASS.

- [ ] **Step 6: Update `_governance_finding` helper in exceptions.py**

In `src/wardline/scanner/exceptions.py`, update the `_governance_finding` helper (lines 207-222) to accept and forward the new params:

```python
def _governance_finding(
    rule_id: RuleId,
    file_path: str,
    line: int,
    message: str,
    *,
    qualname: str | None = None,
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
    """Create a governance pseudo-rule finding (delegates to shared factory)."""
    return make_governance_finding(
        rule_id,
        message,
        file_path=file_path,
        line=line,
        qualname=qualname,
        exception_id=exception_id,
        original_rule=original_rule,
    )
```

- [ ] **Step 7: Pass `exception_id` and `original_rule` at all call sites**

In `_emit_register_governance` (lines 178-204), update all three `_governance_finding` calls to include the new params. For example, the first call (lines 179-186):

```python
governance.append(_governance_finding(
    RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
    exc_file,
    1,
    f"Exception '{exc.id}' has unknown agent provenance "
    f"(agent_originated is null)",
    qualname=exc_qualname,
    exception_id=exc.id,
    original_rule=exc.rule,
))
```

Apply the same pattern to the `GOVERNANCE_RECURRING_EXCEPTION` call (lines 189-195) and `GOVERNANCE_NO_EXPIRY_EXCEPTION` call (lines 198-204).

Also update the two `GOVERNANCE_STALE_EXCEPTION` calls in `apply_exceptions` (lines 120-127 and 132-140):

```python
governance.append(_governance_finding(
    RuleId.GOVERNANCE_STALE_EXCEPTION,
    finding.file_path,
    finding.line,
    f"Exception '{exc.id}' has stale AST fingerprint "
    f"(expected {exc.ast_fingerprint}, got {current_fp})",
    qualname=finding.qualname,
    exception_id=exc.id,
    original_rule=exc.rule,
))
```

And the empty-fingerprint stale call (lines 132-140) — same pattern.

- [ ] **Step 8: Write call-site verification tests**

Add to `tests/unit/scanner/test_context.py` (or the existing exception matching test file):

```python
import datetime
from wardline.manifest.models import ExceptionEntry
from wardline.scanner.exceptions import apply_exceptions


def _make_exception(**overrides) -> ExceptionEntry:
    # NOTE: Cross-reference the existing _make_exception helper in
    # test_exception_matching.py for the full set of required fields.
    # ExceptionEntry may have fields beyond what's listed here
    # (e.g., exceptionability, severity_at_grant, rationale, reviewer).
    # Copy the existing helper's defaults and override as needed.
    defaults = dict(
        id="EXC-test0001",
        rule="PY-WL-001",
        taint_state="UNKNOWN_RAW",
        location="src/app.py::App.handle",
        ast_fingerprint="",
        expires=None,
        recurrence_count=0,
        governance_path="standard",
        agent_originated=None,
        last_refreshed_by=None,
        last_refresh_rationale=None,
        last_refreshed_at=None,
    )
    defaults.update(overrides)
    return ExceptionEntry(**defaults)


def test_governance_findings_carry_exception_id_and_original_rule():
    """Verify _emit_register_governance forwards exception_id and original_rule."""
    exc = _make_exception(
        agent_originated=None,  # triggers UNKNOWN_PROVENANCE
        expires=None,           # triggers NO_EXPIRY
    )
    _, governance = apply_exceptions(
        [],
        (exc,),
        project_root=Path("."),
        now=datetime.date(2026, 3, 23),
    )
    for gf in governance:
        assert gf.exception_id == "EXC-test0001", f"{gf.rule_id} missing exception_id"
        assert gf.original_rule == "PY-WL-001", f"{gf.rule_id} missing original_rule"
```

- [ ] **Step 9: Run the new call-site test to verify it passes**

Run: `pytest tests/unit/scanner/test_context.py -v -k "test_governance_findings_carry"`
Expected: PASS — all governance findings carry `exception_id` and `original_rule`.

- [ ] **Step 10: Run full exception tests**

Run: `pytest tests/unit/scanner/test_exceptions.py -v`
Expected: All PASS.

- [ ] **Step 11: Run full test suite to check for collateral**

Run: `pytest tests/ -x -q`
Expected: All PASS. The `original_rule` field on `Finding` defaults to `None`, so no existing code breaks.

- [ ] **Step 12: Commit**

```bash
git add src/wardline/scanner/context.py src/wardline/scanner/exceptions.py tests/unit/scanner/test_context.py
git commit -m "feat: add exception_id and original_rule to governance findings"
```

---

### Task 5: Implement `build_preview_report`

**Files:**
- Create: `src/wardline/cli/preview.py`
- Create: `tests/unit/cli/test_preview.py`

- [ ] **Step 1: Create test directory and write unit tests**

Create `tests/unit/cli/__init__.py` (empty file — follows project convention for test subdirectories).

Create `tests/unit/cli/test_preview.py`:

```python
"""Tests for build_preview_report."""

from __future__ import annotations

from wardline.cli.preview import build_preview_report
from wardline.core.severity import (
    Exceptionability,
    RuleId,
    Severity,
)
from wardline.scanner.context import Finding


def _finding(
    rule_id: RuleId = RuleId.PY_WL_001,
    *,
    file_path: str = "src/app.py",
    line: int = 10,
    severity: Severity = Severity.ERROR,
    qualname: str | None = "App.handle",
    message: str = "test finding",
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=0,
        end_line=None,
        end_col=None,
        message=message,
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        source_snippet=None,
        qualname=qualname,
        exception_id=exception_id,
        original_rule=original_rule,
    )


class TestBuildPreviewReport:
    def test_empty(self) -> None:
        report = build_preview_report([], [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 0
        assert report["exception_rereview_count"] == 0
        assert report["total_phase2_impact"] == 0
        assert report["details"]["unverified_defaults"] == []
        assert report["details"]["exceptions_needing_rereview"] == []
        assert report["scan_metadata"]["scanned_path"] == "/tmp"
        assert report["scan_metadata"]["wardline_version"] == "0.2.0"
        assert "timestamp" in report["scan_metadata"]
        assert report["version"] == "1.0"

    def test_unverified_defaults(self) -> None:
        findings = [
            _finding(
                rule_id=RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
                file_path="src/a.py",
                line=42,
                qualname="Foo.bar",
                message="schema_default() without overlay boundary",
            ),
        ]
        report = build_preview_report(findings, [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 1
        assert report["total_phase2_impact"] == 1
        detail = report["details"]["unverified_defaults"][0]
        assert detail["file"] == "src/a.py"
        assert detail["line"] == 42
        assert detail["qualname"] == "Foo.bar"

    def test_governance_findings(self) -> None:
        gov = [
            _finding(
                rule_id=RuleId.GOVERNANCE_STALE_EXCEPTION,
                exception_id="EXC-aaa",
                original_rule="PY-WL-001",
                message="stale",
            ),
        ]
        report = build_preview_report([], gov, scanned_path="/tmp", wardline_version="0.2.0")
        assert report["exception_rereview_count"] == 1
        entry = report["details"]["exceptions_needing_rereview"][0]
        assert entry["exception_id"] == "EXC-aaa"
        assert entry["rule"] == "PY-WL-001"
        assert entry["reasons"] == ["stale_fingerprint"]

    def test_mixed(self) -> None:
        findings = [
            _finding(rule_id=RuleId.PY_WL_001_UNGOVERNED_DEFAULT),
        ]
        gov = [
            _finding(
                rule_id=RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
                exception_id="EXC-bbb",
                original_rule="PY-WL-002",
            ),
        ]
        report = build_preview_report(findings, gov, scanned_path="/tmp", wardline_version="0.2.0")
        assert report["total_phase2_impact"] == 2

    def test_ignores_governed_defaults(self) -> None:
        findings = [
            _finding(rule_id=RuleId.PY_WL_001_GOVERNED_DEFAULT, severity=Severity.SUPPRESS),
        ]
        report = build_preview_report(findings, [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 0

    def test_ignores_regular_py_wl_001(self) -> None:
        findings = [
            _finding(rule_id=RuleId.PY_WL_001, severity=Severity.ERROR),
        ]
        report = build_preview_report(findings, [], scanned_path="/tmp", wardline_version="0.2.0")
        assert report["unverified_default_count"] == 0

    def test_deduplicates_exceptions(self) -> None:
        gov = [
            _finding(
                rule_id=RuleId.GOVERNANCE_STALE_EXCEPTION,
                exception_id="EXC-ccc",
                original_rule="PY-WL-001",
            ),
            _finding(
                rule_id=RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
                exception_id="EXC-ccc",
                original_rule="PY-WL-001",
            ),
            _finding(
                rule_id=RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
                exception_id="EXC-ccc",
                original_rule="PY-WL-001",
            ),
        ]
        report = build_preview_report([], gov, scanned_path="/tmp", wardline_version="0.2.0")
        assert report["exception_rereview_count"] == 1
        entry = report["details"]["exceptions_needing_rereview"][0]
        assert sorted(entry["reasons"]) == ["no_expiry", "stale_fingerprint", "unknown_provenance"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/cli/test_preview.py -v`
Expected: FAIL — `wardline.cli.preview` does not exist.

- [ ] **Step 3: Implement `build_preview_report`**

Create `src/wardline/cli/preview.py`:

```python
"""Preview Phase 2 migration impact report."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from wardline.core.severity import RuleId

if TYPE_CHECKING:
    from wardline.scanner.context import Finding

_GOVERNANCE_REASON_MAP: dict[RuleId, str] = {
    RuleId.GOVERNANCE_STALE_EXCEPTION: "stale_fingerprint",
    RuleId.GOVERNANCE_UNKNOWN_PROVENANCE: "unknown_provenance",
    RuleId.GOVERNANCE_RECURRING_EXCEPTION: "recurring",
    RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION: "no_expiry",
}


def build_preview_report(
    findings: list[Finding],
    governance_findings: list[Finding],
    *,
    scanned_path: str,
    wardline_version: str,
) -> dict:
    """Build the --preview-phase2 impact report.

    Pure function: filters findings and governance findings into
    a JSON-serializable dict.
    """
    # Ungoverned schema_default() calls
    unverified = [
        f for f in findings
        if f.rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
    ]

    # Group governance findings by exception ID, aggregate reasons
    exc_map: dict[str, dict] = {}
    for gf in governance_findings:
        reason = _GOVERNANCE_REASON_MAP.get(gf.rule_id)
        if reason is None or gf.exception_id is None:
            continue
        if gf.exception_id not in exc_map:
            exc_map[gf.exception_id] = {
                "exception_id": gf.exception_id,
                "rule": gf.original_rule or "",
                "location": (
                    f"{gf.file_path}::{gf.qualname}"
                    if gf.qualname
                    else gf.file_path
                ),
                "reasons": [],
            }
        exc_map[gf.exception_id]["reasons"].append(reason)

    return {
        "version": "1.0",
        "scan_metadata": {
            "wardline_version": wardline_version,
            "scanned_path": scanned_path,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        "unverified_default_count": len(unverified),
        "exception_rereview_count": len(exc_map),
        "total_phase2_impact": len(unverified) + len(exc_map),
        "details": {
            "unverified_defaults": [
                {
                    "file": f.file_path,
                    "line": f.line,
                    "qualname": f.qualname,
                    "message": f.message,
                }
                for f in unverified
            ],
            "exceptions_needing_rereview": list(exc_map.values()),
        },
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/cli/test_preview.py -v`
Expected: All 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/preview.py tests/unit/cli/test_preview.py
git commit -m "feat: implement build_preview_report for --preview-phase2"
```

---

### Task 6: Wire `--preview-phase2` into `scan` command

**Files:**
- Modify: `src/wardline/cli/scan.py:149-178,368-419`

- [ ] **Step 1: Add the Click option**

In `src/wardline/cli/scan.py`, add a new option after `--allow-permissive-distribution` (around line 172):

```python
@click.option("--preview-phase2", is_flag=True, default=False,
              help="Output Phase 2 migration impact report (JSON) instead of SARIF.")
```

And add `preview_phase2: bool` to the `scan()` function signature.

- [ ] **Step 2: Add the preview branch after exception matching**

In `scan.py`, insert **after line 367** (after `exceeded_pct` is computed) and **before line 368** (the `# --- Build SARIF output ---` comment). The preview branch needs `exceeded_pct` for normal exit code logic, so it must come after that variable is set. Add:

```python
# --- Preview Phase 2 report ---
if preview_phase2:
    from wardline.cli.preview import build_preview_report
    import wardline

    report = build_preview_report(
        result.findings,
        governance_findings,
        scanned_path=str(Path(path).resolve()),
        wardline_version=wardline.__version__,
    )
    import json
    report_text = json.dumps(report, indent=2) + "\n"

    if output is not None:
        try:
            Path(output).write_text(report_text, encoding="utf-8")
        except OSError as exc:
            click.echo(f"error: cannot write to '{output}': {exc}", err=True)
            sys.exit(EXIT_CONFIG_ERROR)
    else:
        click.echo(report_text, nl=False)

    # Normal exit code rules apply — preview changes format, not enforcement
    has_tool_error = any(
        f.rule_id == RuleId.TOOL_ERROR for f in result.findings
    )
    scan_finding_count = len(result.findings)
    if has_tool_error:
        sys.exit(EXIT_TOOL_ERROR)
    elif exceeded_pct or scan_finding_count > 0:
        sys.exit(EXIT_FINDINGS)
    else:
        sys.exit(EXIT_CLEAN)
```

Note: No stderr summary line in this branch (suppressed per spec). The `exceeded_pct` variable is computed earlier in the function and is available here.

- [ ] **Step 3: Write a CLI smoke test**

Add to the existing scan CLI test file (find via `pytest --collect-only -q | grep test_scan`):

```python
from click.testing import CliRunner
from wardline.cli.scan import scan


def test_preview_phase2_flag_produces_json(tmp_path):
    """Smoke test: --preview-phase2 produces JSON output, not SARIF."""
    # Minimal fixture: empty Python file + wardline.yaml
    (tmp_path / "wardline.yaml").write_text("version: '1.0'\nmodule_tiers: []\n")
    (tmp_path / "empty.py").write_text("")
    runner = CliRunner()
    result = runner.invoke(scan, [str(tmp_path), "--preview-phase2"])
    assert result.exit_code == 0  # no findings in empty file
    import json
    report = json.loads(result.output)
    assert "version" in report
    assert "scan_metadata" in report
    assert report["unverified_default_count"] == 0
```

- [ ] **Step 4: Run the smoke test**

Run: `pytest tests/unit/cli/test_scan.py -v -k "test_preview_phase2_flag_produces_json"` (adjust path to match where the test was added)
Expected: PASS.

- [ ] **Step 5: Run existing scan tests to check for collateral**

Run: `pytest tests/ -x -q -k "scan"`
Expected: All PASS. The new flag defaults to `False`, so existing behavior is unchanged.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/scan.py tests/
git commit -m "feat: wire --preview-phase2 flag into wardline scan command"
```

---

### Task 7: Integration tests

**Files:**
- Create: `tests/integration/test_preview_phase2.py`

This task requires test fixtures. Check the existing integration test structure to follow conventions.

- [ ] **Step 1: Identify fixture conventions**

Run: `ls tests/integration/` and examine an existing integration test to understand how fixtures (wardline.yaml, Python source files, wardline.exceptions.json) are set up. Look for `tmp_path` usage or fixture directories.

- [ ] **Step 2: Write the integration test**

Create `tests/integration/test_preview_phase2.py`. The test must set up:

1. A minimal `wardline.yaml` manifest with module tiers.
2. A Python source file with:
   - An ungoverned `schema_default()` call (no overlay boundary).
   - A governed `schema_default()` call (with overlay boundary declared).
   - A `.get(key, default)` call (must NOT appear in report).
3. An overlay file declaring a boundary for the governed call.
4. A `wardline.exceptions.json` with:
   - Exception A: targeting a real function, stale fingerprint (`ast_fingerprint` set to a wrong value), `expires=None`, `agent_originated=True`, `recurrence_count=0`.
   - Exception B: targeting a real function, correct fingerprint, `expires=None` (doesn't matter for governance), `agent_originated=None`, `recurrence_count=3`.

Use `click.testing.CliRunner` to invoke the scan command, following existing integration test patterns.

Assert:
- Exit code: 1 (findings present → normal enforcement).
- JSON output is valid, has `version`, `scan_metadata`.
- `unverified_default_count == 1`.
- `exception_rereview_count == 2`.
- Exception A reasons include `stale_fingerprint` and `no_expiry`.
- Exception B reasons include `unknown_provenance` and `recurring`.
- The `.get()` call does NOT appear in `unverified_defaults`.

Also test `--output` writes to a file:
- Pass `--output` pointing to a temp file.
- Assert file exists and contains valid JSON.

- [ ] **Step 3: Run the integration test**

Run: `pytest tests/integration/test_preview_phase2.py -v`
Expected: All PASS.

- [ ] **Step 4: Run the full test suite**

Run: `pytest tests/ -x -q`
Expected: All PASS. No regressions.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_preview_phase2.py
git commit -m "test: add integration tests for wardline scan --preview-phase2"
```

---

### Task 8: Final verification

- [ ] **Step 1: Run the full test suite one final time**

Run: `pytest tests/ -v --tb=short`
Expected: All PASS, test count should be approximately 755 + new tests (≈770+).

- [ ] **Step 2: Manual smoke test**

Run: `wardline scan . --preview-phase2` from the project root.
Expected: JSON output to stdout with `scan_metadata`, counts, and details.

- [ ] **Step 3: Test with --output flag**

Run: `wardline scan . --preview-phase2 --output /tmp/preview.json && cat /tmp/preview.json | python -m json.tool`
Expected: Valid JSON written to file.
