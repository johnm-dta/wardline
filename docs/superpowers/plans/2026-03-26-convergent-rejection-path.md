# Rejection Path Extraction + Configurable Expansion Depth

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the rejection path expansion loop into a testable function. Default to `max_rounds=1` (preserving spec-compliant two-hop behavior). Make deeper expansion opt-in via `max_expansion_rounds` in `wardline.toml`.

**Architecture:** Extract the expansion loop from `_build_project_indexes` into a module-level `expand_rejection_index()` that returns `(index, converged)`. The caller passes `max_rounds` from config (default 1). Add try/except fault boundary. Emit a SARIF `Finding` if the bound is hit without convergence.

**Tech Stack:** Python 3.12+, ast module, wardline scanner framework

**Spec compliance:** Default `max_rounds=1` preserves the spec's two-hop limit. Deeper expansion is an explicit opt-in that projects choose knowingly.

**Benchmarks (measured, for reference):**
- wardline (83 files, 409 functions): converges in 3 rounds, ~52ms total
- elspeth (923 files, 15k functions): converges in 5 rounds, ~3s total

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `src/wardline/scanner/engine.py` | Extract `expand_rejection_index`, wire `max_rounds` from config, add fault boundary |
| Modify | `src/wardline/manifest/models.py` | Add `max_expansion_rounds` to `_KNOWN_KEYS` + `ScannerConfig` |
| Modify | `src/wardline/cli/scan.py` | Pass `max_expansion_rounds` from config to `ScanEngine` |
| Create | `tests/unit/scanner/test_rejection_path_convergence.py` | Tests: multi-hop chains, fixed point, safety bound, diamond graph, fault tolerance |

---

### Task 1: Add `max_expansion_rounds` config + engine parameter

**Files:**
- Modify: `src/wardline/manifest/models.py`
- Modify: `src/wardline/scanner/engine.py`
- Modify: `src/wardline/cli/scan.py`

- [ ] **Step 1: Add config key to models.py**

Add `"max_expansion_rounds"` to `_KNOWN_KEYS` frozenset in `src/wardline/manifest/models.py`.

Add field to `ScannerConfig`:
```python
max_expansion_rounds: int = 1
```

Add parsing in `ScannerConfig.from_toml()`:
```python
max_expansion_rounds = int(wardline_section.get("max_expansion_rounds", 1))
if max_expansion_rounds < 1:
    raise ScannerConfigError("max_expansion_rounds must be >= 1")
```

Pass `max_expansion_rounds=max_expansion_rounds` to the constructor.

- [ ] **Step 2: Add `max_expansion_rounds` to ScanEngine constructor**

In `src/wardline/scanner/engine.py`, add parameter to `__init__`:
```python
max_expansion_rounds: int = 1,
```
Store as `self._max_expansion_rounds = max_expansion_rounds`.

- [ ] **Step 3: Wire config through scan CLI**

In `src/wardline/cli/scan.py`, find where `ScanEngine` is constructed and pass:
```python
max_expansion_rounds=cfg.max_expansion_rounds if cfg is not None else 1,
```

- [ ] **Step 4: Run existing tests**

Run: `python -m pytest --tb=short -q`
Expected: all pass (new parameter has default, backward compatible)

- [ ] **Step 5: Commit**

```bash
git add src/wardline/manifest/models.py src/wardline/scanner/engine.py src/wardline/cli/scan.py
git commit -m "feat(config): add max_expansion_rounds to wardline.toml + ScanEngine

Default 1 preserves spec-compliant two-hop behavior.
Deeper expansion is opt-in via wardline.toml."
```

---

### Task 2: Write tests for `expand_rejection_index`

**Files:**
- Create: `tests/unit/scanner/test_rejection_path_convergence.py`

- [ ] **Step 1: Write the test file**

Create `tests/unit/scanner/test_rejection_path_convergence.py`:

```python
"""Tests for rejection path index expansion.

Exercises expand_rejection_index with various chain depths,
topologies, and safety bounds.
"""
from __future__ import annotations

import ast

from wardline.scanner._qualnames import build_qualname_map
from wardline.scanner.engine import expand_rejection_index
from wardline.scanner.import_resolver import build_import_alias_map


def _file_data(source: str, module_name: str) -> tuple:
    """Build a file_data tuple from source for testing."""
    tree = ast.parse(source)
    alias_map = build_import_alias_map(tree)
    qualname_map = build_qualname_map(tree)
    return (tree, alias_map, qualname_map, module_name)


class TestSingleRoundExpansion:
    """Default max_rounds=1 preserves two-hop behavior."""

    def test_two_hop_chain(self) -> None:
        """a() calls b() which has raise → both in index."""
        source = "def a():\n    b()\n\ndef b():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.b"}), max_rounds=1)
        assert "mod.a" in result
        assert "mod.b" in result
        assert converged  # two-hop converges in 1 round for direct callers

    def test_three_hop_limited_to_two(self) -> None:
        """a→b→c (c raises), max_rounds=1 → b enters, a does NOT."""
        source = "def a():\n    b()\n\ndef b():\n    c()\n\ndef c():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.c"}), max_rounds=1)
        assert "mod.b" in result
        assert "mod.a" not in result
        assert not converged

    def test_empty_seed(self) -> None:
        """No seed → no expansion, converged immediately."""
        source = "def a():\n    b()\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset(), max_rounds=1)
        assert result == frozenset()
        assert converged


class TestMultiRoundConvergence:
    """Deeper expansion when max_rounds > 1."""

    def test_three_hop_with_two_rounds(self) -> None:
        """a→b→c (c raises), max_rounds=2 → all three in index."""
        source = "def a():\n    b()\n\ndef b():\n    c()\n\ndef c():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.c"}), max_rounds=2)
        assert result == frozenset({"mod.a", "mod.b", "mod.c"})
        assert converged

    def test_four_hop_chain(self) -> None:
        """a→b→c→d (d raises), max_rounds=10 → all four."""
        source = (
            "def a():\n    b()\n\ndef b():\n    c()\n\n"
            "def c():\n    d()\n\ndef d():\n    raise ValueError('bad')\n"
        )
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.d"}), max_rounds=10)
        assert result == frozenset({"mod.a", "mod.b", "mod.c", "mod.d"})
        assert converged

    def test_converges_at_fixed_point(self) -> None:
        """Unreachable function c stays out of index."""
        source = "def a():\n    b()\n\ndef b():\n    raise ValueError('bad')\n\ndef c():\n    pass\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.b"}), max_rounds=100)
        assert "mod.c" not in result
        assert result == frozenset({"mod.a", "mod.b"})
        assert converged

    def test_circular_calls_no_raise(self) -> None:
        """a↔b mutual recursion, neither raises → neither in index."""
        source = "def a():\n    b()\n\ndef b():\n    a()\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset(), max_rounds=10)
        assert result == frozenset()
        assert converged

    def test_diamond_call_graph(self) -> None:
        """a→b, a→c, b→d (raises), c→d → all four in index."""
        source = (
            "def a():\n    b()\n    c()\n\ndef b():\n    d()\n\n"
            "def c():\n    d()\n\ndef d():\n    raise ValueError('bad')\n"
        )
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.d"}), max_rounds=10)
        assert result == frozenset({"mod.a", "mod.b", "mod.c", "mod.d"})
        assert converged

    def test_cross_file_with_imports(self) -> None:
        """Functions across files with import statements resolve transitively."""
        source_a = "from app.validators import validate\n\ndef handler():\n    validate()\n"
        source_b = "from app.checks import check\n\ndef validate():\n    check()\n"
        source_c = "def check():\n    raise ValueError('bad')\n"
        fd_a = _file_data(source_a, "app.views")
        fd_b = _file_data(source_b, "app.validators")
        fd_c = _file_data(source_c, "app.checks")
        result, converged = expand_rejection_index(
            [fd_a, fd_b, fd_c], frozenset({"app.checks.check"}), max_rounds=10
        )
        assert "app.validators.validate" in result
        assert "app.views.handler" in result
        assert converged

    def test_known_validator_as_seed_root(self) -> None:
        """External FQN in seed → project callers expand from it."""
        source = "import jsonschema\n\ndef validate(data):\n    jsonschema.validate(data, {})\n"
        fd = _file_data(source, "myproject.validators")
        result, converged = expand_rejection_index(
            [fd], frozenset({"jsonschema.validate"}), max_rounds=10
        )
        assert "myproject.validators.validate" in result
        assert converged

    def test_bound_exceeded_returns_not_converged(self) -> None:
        """Chain of 12 hops, max_rounds=3 → converged=False."""
        lines = []
        for i in range(12):
            if i < 11:
                lines.append(f"def f{i}():\n    f{i+1}()\n")
            else:
                lines.append(f"def f{i}():\n    raise ValueError('bad')\n")
        source = "\n".join(lines)
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.f11"}), max_rounds=3)
        assert not converged
        # f11 (seed) + f10, f9, f8 (3 rounds) should be in
        assert "mod.f11" in result
        assert "mod.f10" in result
        # f0 through f7 should NOT be in (would need more rounds)
        assert "mod.f0" not in result

    def test_empty_file_data(self) -> None:
        """No files → seed returned unchanged."""
        result, converged = expand_rejection_index([], frozenset({"ext.validate"}), max_rounds=10)
        assert result == frozenset({"ext.validate"})
        assert converged
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/scanner/test_rejection_path_convergence.py -v --tb=short`
Expected: ImportError (`expand_rejection_index` doesn't exist yet)

- [ ] **Step 3: Commit**

```bash
git add tests/unit/scanner/test_rejection_path_convergence.py
git commit -m "test(scanner): add expansion tests for rejection path index

14 tests covering single-round (two-hop default), multi-round
convergence, diamond graphs, cross-file with imports, known
validators as seed, bound exceeded, and empty inputs."
```

---

### Task 3: Extract `expand_rejection_index` and wire max_rounds

**Files:**
- Modify: `src/wardline/scanner/engine.py`

- [ ] **Step 1: Add `expand_rejection_index` function**

Add after the `ProjectIndex` dataclass, before `class ScanEngine`:

```python
def expand_rejection_index(
    file_data: list[tuple[ast.Module, dict[str, str], dict[int, str], str]],
    seed: frozenset[str],
    *,
    max_rounds: int = 1,
) -> tuple[frozenset[str], bool]:
    """Expand a rejection path seed to transitive callers.

    Each round adds functions that call any function already in the index.
    Iteration stops when no new entries are added or ``max_rounds`` is
    reached.  Default ``max_rounds=1`` preserves spec-compliant two-hop
    behavior.

    Returns:
        Tuple of (expanded_index, converged). ``converged`` is True if
        expansion reached fixed point; False if ``max_rounds`` was hit.
    """
    index = set(seed)
    for _round in range(max_rounds):
        new_entries: set[str] = set()
        for tree, alias_map, qualname_map, module_name in file_data:
            local_fqns = frozenset(
                f"{module_name}.{qn}" for qn in qualname_map.values()
            )
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                qualname = qualname_map.get(id(node))
                if qualname is None:
                    continue
                fqn = f"{module_name}.{qualname}"
                if fqn in index:
                    continue
                for child in walk_skip_nested_defs(node):
                    if not isinstance(child, ast.Call):
                        continue
                    callee_fqn = resolve_call_fqn(
                        child, alias_map, local_fqns, module_name
                    )
                    if callee_fqn is not None and callee_fqn in index:
                        new_entries.add(fqn)
                        break
        if not new_entries:
            return frozenset(index), True
        index.update(new_entries)
    return frozenset(index), False
```

- [ ] **Step 2: Replace the expansion in `_build_project_indexes`**

Replace lines 326-355 (the "Expansion: one round" block through the return) with:

```python
        # Expansion: configurable depth (default 1 = two-hop per spec)
        try:
            rejection_path_index, converged = expand_rejection_index(
                file_data, frozenset(rejection_seed),
                max_rounds=self._max_expansion_rounds,
            )
        except Exception as exc:
            logger.warning(
                "Rejection path expansion failed: %s — falling back to seed",
                exc,
            )
            rejection_path_index = frozenset(rejection_seed)
            converged = True  # not meaningful, but prevents spurious warning

        if not converged:
            logger.warning(
                "Rejection path expansion hit max_rounds=%d "
                "(%d entries in index)",
                self._max_expansion_rounds, len(rejection_path_index),
            )

        return ProjectIndex(
            annotations=MappingProxyType(all_annotations),
            module_file_map=MappingProxyType(module_file_map),
            string_literal_counts=MappingProxyType(string_literal_counts),
            rejection_path_index=rejection_path_index,
        )
```

Update the docstring at line 260-262 to:
```
        Also computes the rejection path index:
        1. Seed: project functions with direct rejection paths + known_validators
        2. Expand: iterate up to max_expansion_rounds (default 1 = two-hop per spec)
```

- [ ] **Step 3: Run convergence tests**

Run: `python -m pytest tests/unit/scanner/test_rejection_path_convergence.py -v --tb=short`
Expected: all pass

- [ ] **Step 4: Run full test suite**

Run: `python -m pytest --tb=short -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/engine.py
git commit -m "refactor(scanner): extract expand_rejection_index with configurable depth

Module-level function for testability. Default max_rounds=1
preserves spec-compliant two-hop behavior. Deeper expansion
opt-in via max_expansion_rounds in wardline.toml.

Includes try/except fault boundary — falls back to seed on
unexpected errors, matching engine error-handling philosophy."
```

---

### Task 4: Final verification

- [ ] **Step 1: Run full test suite**

Run: `python -m pytest --tb=short -q`
Expected: all pass

- [ ] **Step 2: Run integration tests**

Run: `python -m pytest -m "integration" --tb=short -q`
Expected: all pass

- [ ] **Step 3: Run linter**

Run: `ruff check src/wardline/scanner/engine.py src/wardline/manifest/models.py src/wardline/cli/scan.py`
Expected: clean

- [ ] **Step 4: Verify success criteria**

- [ ] `max_rounds=1` reproduces two-hop behavior (three-hop chain: b enters, a does NOT)
- [ ] `max_rounds=2` on three-hop chain: all enter
- [ ] Fixed-point convergence (no infinite loop)
- [ ] Diamond call graph handled correctly
- [ ] Cross-file with imports resolves transitively
- [ ] `known_validators` as seed root expands project callers
- [ ] Circular calls without raise produce empty index
- [ ] Bound exceeded returns `converged=False`
- [ ] Existing PY-WL-008 tests unchanged
- [ ] Existing delegated rejection tests unchanged
- [ ] `expand_rejection_index` crash falls back to seed (fault boundary)
