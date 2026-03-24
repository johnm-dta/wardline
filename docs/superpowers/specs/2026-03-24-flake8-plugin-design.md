# flake8 Plugin Design + Implementation Plan — WP 3.1

**Date:** 2026-03-24
**Status:** Draft
**Scope:** Separate `wardline-flake8` package implementing PY-WL-001–005 as flake8 AST checkers
**Target release:** v0.4.0
**Dependencies:** None (reimplements patterns in flake8's framework, no wardline import)

## Design

### What It Is

A standalone flake8 plugin (`pip install wardline-flake8`) that fires advisory warnings in IDE and CI for the 5 core wardline patterns. Per-file AST matching only — no manifest, no taint context, no tier-graded severity. Every match is a WARNING. This is the "zero-config immediate feedback" path.

### What It Is NOT

- Not a substitute for `wardline scan` (which has taint context, severity grading, exception register)
- Not a runtime of the full rule engine (no `RuleBase`, no `ScanContext`)
- Does not import from `wardline` at all — fully self-contained

### Error Codes

| Code | Maps to | Pattern |
|---|---|---|
| `WL001` | PY-WL-001 | `dict.get(key, default)` — fallback default on dict access |
| `WL002` | PY-WL-002 | `getattr(obj, name, default)` — fallback default on attribute access |
| `WL003` | PY-WL-003 | `key in dict` / `hasattr()` — existence checking as structural gate |
| `WL004` | PY-WL-004 | `except Exception` / `except BaseException` — broad exception handlers |
| `WL005` | PY-WL-005 | `except X: pass` — silent exception handlers |

### Package Structure

```
wardline-flake8/
├── pyproject.toml          # separate package, depends only on flake8
├── src/
│   └── wardline_flake8/
│       ├── __init__.py     # WardlineChecker class (flake8 entry point)
│       ├── wl001.py        # dict.get pattern detection
│       ├── wl002.py        # getattr pattern detection
│       ├── wl003.py        # existence check detection
│       ├── wl004.py        # broad handler detection
│       └── wl005.py        # silent handler detection
└── tests/
    ├── test_wl001.py
    ├── test_wl002.py
    ├── test_wl003.py
    ├── test_wl004.py
    └── test_wl005.py
```

### flake8 Plugin API

flake8 plugins use the `ast_tree` checker interface:

```python
class WardlineChecker:
    name = "wardline"
    version = "0.1.0"

    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree

    def run(self) -> Iterator[tuple[int, int, str, type]]:
        """Yield (line, col, message, cls) for each finding."""
        yield from check_wl001(self._tree)
        yield from check_wl002(self._tree)
        yield from check_wl003(self._tree)
        yield from check_wl004(self._tree)
        yield from check_wl005(self._tree)
```

Registered via `pyproject.toml` entry point:
```toml
[project.entry-points."flake8.extension"]
WL = "wardline_flake8:WardlineChecker"
```

### Pattern Detection (simplified from full rules)

Each `check_wlNNN` function walks the AST and yields `(line, col, message, type)` tuples. The detection is simplified from the full wardline rules:

- **No taint gating** — fires on every match (no `_ACTIVE_TAINTS` filtering like PY-WL-003)
- **No severity grading** — everything is a flake8 warning
- **No `ScanContext`** — pure AST pattern matching
- **No `walk_skip_nested_defs`** — use `ast.walk` (simpler, acceptable for advisory)

This means the flake8 plugin will have **more false positives** than `wardline scan` (which uses taint context to suppress). This is by design — advisory, not authoritative.

### Known Limitation

The flake8 plugin will contradict `wardline scan` results for findings that the scanner suppresses via taint context (e.g., `key in config` at AUDIT_TRAIL taint — scanner suppresses, flake8 fires). This is documented as a known limitation per roadmap panel review I7.

### pyproject.toml

```toml
[project]
name = "wardline-flake8"
version = "0.1.0"
description = "Wardline advisory rules for flake8"
requires-python = ">=3.9"
dependencies = ["flake8>=5.0"]

[project.entry-points."flake8.extension"]
WL = "wardline_flake8:WardlineChecker"

[build-system]
requires = ["setuptools>=64"]
build-backend = "setuptools.backends._legacy:_Backend"
```

**Python >=3.9** floor (not 3.12 like the main package) — the flake8 plugin should work wherever flake8 works.

### Testing

Each rule gets a test file with positive (fires) and negative (doesn't fire) cases. Tests use flake8's test utilities or direct AST parsing + `list(WardlineChecker(tree).run())`.

~25 tests total (5 per rule).

## Implementation Plan

### Task 1: Package Scaffold

Create `wardline-flake8/` directory with `pyproject.toml`, `src/wardline_flake8/__init__.py`, empty rule modules, and test scaffold.

### Task 2: WL001 — dict.get Pattern

Implement `check_wl001(tree)`: detect `x.get(key, default)` calls where the method name is `get` and there are exactly 2 arguments. Yield `(line, col, "WL001 dict.get() with fallback default", type)`.

Tests: dict.get with default (fires), dict.get without default (doesn't fire), nested dict.get, non-dict .get() (fires — advisory, no type resolution).

### Task 3: WL002 — getattr Pattern

Implement `check_wl002(tree)`: detect `getattr(obj, name, default)` calls with 3 arguments.

Tests: 3-arg getattr (fires), 2-arg getattr (doesn't fire).

### Task 4: WL003 — Existence Checking

Implement `check_wl003(tree)`: detect `key in dict`, `hasattr(obj, name)`, `match/case` with `MatchMapping`/`MatchClass`.

Tests: `in` operator, `hasattr`, pattern matching, `not in`.

### Task 5: WL004 — Broad Exception Handlers

Implement `check_wl004(tree)`: detect `except Exception`, `except BaseException`, bare `except:`.

Tests: broad handler (fires), specific handler like `except ValueError` (doesn't fire), multiple handlers.

### Task 6: WL005 — Silent Exception Handlers

Implement `check_wl005(tree)`: detect `except X: pass` where the handler body is a single `pass` statement (or `...`).

Tests: `except: pass` (fires), `except: log.error()` (doesn't fire), `except: ...` (fires).

### Task 7: Integration Test

Install the plugin via `pip install -e wardline-flake8/` and run `flake8 --select=WL` against a test file. Verify all 5 codes fire correctly through flake8's runner.

### Task 8: Documentation

README with installation, usage (`pip install wardline-flake8`, then `flake8 --select=WL`), error code table, and known limitations (no taint context, more FPs than `wardline scan`).

### Dependency Graph

```
Task 1 (scaffold) → Tasks 2-6 (parallel, one per rule) → Task 7 (integration) → Task 8 (docs)
```
