# Quality Assessment: WP 1.5 (Rules 006-009) and WP 1.6 (Level 2 Taint)

**Assessed:** 2026-03-24
**Branch:** main (post-merge of feature/wp-0.1-engine-taint-wiring)
**Assessor:** Architecture Critic Agent

---

## Confidence Assessment

**Confidence: HIGH** -- Read all source files, all test files, the base class, two existing rules (003, 005) for pattern comparison, the engine, context, CLI registration, and the L1 taint module. Full coverage of the changed surface.

## Risk Assessment

| Area | Risk Level |
|------|------------|
| WP 1.5 (Rules 006-009) | **Low** -- clean pattern adherence, minor issues only |
| WP 1.6 (L2 Variable Taint) | **Medium** -- good module, but engine integration has a correctness bug |
| Coupling WP 1.5 / WP 1.6 | **Low** -- clean separation, rules use L1 only |

---

## WP 1.5: Rules 006-009

### Overall

**Quality Score:** 4 / 5
**Critical Issues:** 0
**High Issues:** 0

All four rules follow the established pattern correctly:
- Subclass `RuleBase`, set `RULE_ID` class variable
- Implement `visit_function(node, *, is_async)`, never override `visit_FunctionDef`/`visit_AsyncFunctionDef`
- Use `walk_skip_nested_defs` for AST traversal
- Use `matrix.lookup(self.RULE_ID, taint)` for severity resolution
- Use `self._get_function_taint(self._current_qualname)` for taint lookup
- Emit frozen `Finding` dataclass instances via `self.findings.append()`
- Constructor signature `__init__(self, *, file_path: str = "")` matches existing rules
- Tests cover positive cases, negative cases, async, nested functions, and edge cases

This is pattern-adherent code. The issues below are minor.

---

### PY-WL-006: Audit Writes in Broad Handlers

**Quality Score:** 4 / 5
**Critical Issues:** 0
**High Issues:** 0

**Findings:**

1. **`_AUDIT_ATTR_PREFIXES` uses startswith matching that can false-positive** - Low
   - **Evidence:** `src/wardline/scanner/rules/py_wl_006.py:78` -- `attr == prefix or attr.startswith(prefix + "_")` matches `store_something()` via the `"store"` prefix, which is intentional. But `"info"` prefix would match `obj.information()` via `attr.startswith("info_")` -- wait, no, the `+ "_"` suffix prevents that. This is actually correct. No issue here. Withdrawn.

**Strengths:**
- Clear decomposition: `_is_broad_handler` and `_is_audit_call` are well-separated helper functions, each with a single responsibility.
- Handles all broad-handler forms: bare `except:`, `except Exception`, `except BaseException`, tuple with broad member, dotted `except module.Exception`.
- Test coverage is thorough: 14 test cases covering loggers, db writes, multiple writes, tuple handlers, async, bare functions, specific handlers (negative), non-audit calls (negative), nested functions.

---

### PY-WL-007: Runtime Type-Checking on Internal Data

**Quality Score:** 4 / 5
**Critical Issues:** 0
**High Issues:** 0

**Findings:**

1. **Dead code: `_SUPPRESS_TAINTS` and `Severity` import are unused** - Low
   - **Evidence:** `src/wardline/scanner/rules/py_wl_007.py:18` -- `Severity` imported but never referenced. `src/wardline/scanner/rules/py_wl_007.py:24-27` -- `_SUPPRESS_TAINTS` frozenset defined but never used in the rule class. The docstring (line 8-9) mentions SUPPRESS behavior, and the tests verify it (`test_external_raw_is_suppress`), but the suppression is handled by `matrix.lookup` returning `Severity.SUPPRESS`, not by `_SUPPRESS_TAINTS`.
   - **Impact:** Dead code clutters the module and misleads readers into thinking there is a local taint gate (like PY-WL-003's `_ACTIVE_TAINTS`). No runtime impact.
   - **Recommendation:** Remove `_SUPPRESS_TAINTS` and the `Severity` import. The matrix handles suppression.

2. **`TaintState` import is also unused at runtime** - Low
   - **Evidence:** `src/wardline/scanner/rules/py_wl_007.py:19` -- `TaintState` imported for `_SUPPRESS_TAINTS`. If `_SUPPRESS_TAINTS` is removed, `TaintState` import becomes dead too.
   - **Impact:** None.
   - **Recommendation:** Remove with `_SUPPRESS_TAINTS`.

**Strengths:**
- Taint-gated severity via matrix.lookup works correctly -- tests prove SUPPRESS for EXTERNAL_RAW/UNKNOWN_RAW, WARNING for MIXED_RAW/PIPELINE, ERROR for AUDIT_TRAIL.
- Catches both `isinstance()` and `type() == T` / `type() is T` patterns.
- Clean `_is_type_call` static method factored out.

---

### PY-WL-008: Validation With No Rejection Path

**Quality Score:** 4 / 5
**Critical Issues:** 0
**High Issues:** 0

**Findings:**

1. **Validation-call detection is name-based and will miss aliased validators** - Low
   - **Evidence:** `src/wardline/scanner/rules/py_wl_008.py:24-32` -- `_VALIDATION_SUBSTRINGS` matches function names containing "valid", "check", etc. A function named `ensure_format()` or `assert_schema()` would not fire.
   - **Impact:** False negatives on non-standard naming. This is an inherent limitation of AST-only analysis and consistent with how other rules work (PY-WL-006 also uses name patterns). Acceptable.
   - **Recommendation:** Document the naming convention dependency. Consider adding "ensure" and "assert_" to `_VALIDATION_SUBSTRINGS` in a future pass.

**Strengths:**
- Structural-conditional definition (rejection path = if/assert/raise referencing the variable) is well-specified and implemented.
- Handles both `ast.Assign` and `ast.AnnAssign` forms.
- Rejection via function call (`abort_if_invalid(result)`) is detected -- this is a thoughtful addition over the simple if/assert/raise check.
- Test at line 263-273 explicitly verifies that using a *different* variable in the conditional does not suppress. Good edge-case discipline.

---

### PY-WL-009: Semantic Without Shape Validation

**Quality Score:** 3 / 5
**Critical Issues:** 0
**High Issues:** 1

**Findings:**

1. **`_has_subscript_or_attr_access` function name is misleading -- only checks subscripts** - Medium
   - **Evidence:** `src/wardline/scanner/rules/py_wl_009.py:90-95` -- Function name says "or attr access" but the body only checks `isinstance(child, ast.Subscript)`. Never checks `ast.Attribute`.
   - **Impact:** Either the function does less than its name promises (misleading to maintainers), or attribute access was intended but forgotten (missed detection). If `if obj.status == "active"` should fire, it currently does not.
   - **Recommendation:** Either rename to `_has_subscript_access` to match behavior, or add `ast.Attribute` detection if the design intent includes attribute access on unvalidated data.

2. **`_has_shape_check_before` uses `ast.walk` over all statements, ignoring control flow** - Medium
   - **Evidence:** `src/wardline/scanner/rules/py_wl_009.py:52-53` -- `ast.walk(ast.Module(body=stmts, type_ignores=[]))` walks the entire function body flattened. A shape check inside an `else` branch (line 5) would suppress a semantic check in the `if` branch (line 10) even though the shape check is unreachable on that path.
   - **Impact:** False negatives in branching code. A function could have `isinstance()` in a dead branch and skip the finding. This is a known limitation of flat-walk analysis and is acceptable at L1, but should be documented.
   - **Recommendation:** Add a comment acknowledging the control-flow-insensitive nature of the check. Consider L2 integration in a future pass for path-sensitive analysis.

3. **`_SHAPE_VALIDATION_NAMES` and `_SHAPE_VALIDATION_SUBSTRINGS` overlap** - Low
   - **Evidence:** `src/wardline/scanner/rules/py_wl_009.py:23-36` -- `_SHAPE_VALIDATION_NAMES` contains e.g. `"validate_schema"`, and `_SHAPE_VALIDATION_SUBSTRINGS` contains `"schema"`. The function `_is_shape_validation_call` checks both (lines 70-74, 78-81), so the exact-name set is redundant -- the substring check already matches.
   - **Impact:** No functional impact. Minor code bloat.
   - **Recommendation:** Either drop `_SHAPE_VALIDATION_NAMES` (substrings subsume it) or document that exact names exist for clarity/performance.

**Strengths:**
- The conceptual rule (semantic before shape) is architecturally valuable. It catches a real class of bugs where business logic runs on structurally unvalidated data.
- Line-number ordering for "before" check is a pragmatic approximation that works for the common top-to-bottom function pattern.

---

## WP 1.6: Level 2 Variable-Level Taint

### `variable_level.py`

**Quality Score:** 4 / 5
**Critical Issues:** 0
**High Issues:** 0

**Findings:**

1. **`_handle_try` does not merge exception-handler branches -- it applies them sequentially** - Medium
   - **Evidence:** `src/wardline/scanner/taint/variable_level.py:450-473` -- `_handle_try` walks the try body, then walks each handler body sequentially into the *same* `var_taints` dict. If handler A sets `x = AUDIT_TRAIL` and handler B sets `x = EXTERNAL_RAW`, the final state of `x` is whatever handler B wrote, not `taint_join(AUDIT_TRAIL, EXTERNAL_RAW)`. Contrast with `_handle_if` (lines 343-376) which correctly snapshots, walks branches separately, and merges.
   - **Impact:** Incorrect variable taint when multiple exception handlers assign the same variable differently. The last handler wins instead of the join. In practice, exception handlers rarely reassign the same variable, so this is unlikely to cause real-world bugs today, but it is a correctness defect in the taint lattice semantics.
   - **Recommendation:** Apply the same snapshot-and-merge pattern used in `_handle_if`. Snapshot before handlers, walk each handler into a copy, merge all copies via `taint_join`.

2. **`except ... as e` assigns AUDIT_TRAIL unconditionally** - Low
   - **Evidence:** `src/wardline/scanner/taint/variable_level.py:464` -- `var_taints[handler.name] = TaintState.AUDIT_TRAIL`. The comment says "runtime-constructed" but exception objects can carry arbitrary attacker-controlled data (e.g., `except ValueError as e` where the ValueError was raised with user-supplied message).
   - **Impact:** Potential taint under-approximation. An exception caught at a boundary could carry external data, but the variable gets AUDIT_TRAIL. At L2, this is a conservative-in-the-wrong-direction choice. However, fixing this requires knowing whether the exception was raised internally or externally, which L2 cannot determine from the local AST.
   - **Recommendation:** Document this as a known limitation. Consider making the exception variable inherit the function's taint rather than hardcoding AUDIT_TRAIL.

3. **Unused `TYPE_CHECKING` import block** - Low
   - **Evidence:** `src/wardline/scanner/taint/variable_level.py:29-30` -- `if TYPE_CHECKING: pass`. Empty TYPE_CHECKING block.
   - **Impact:** Dead code.
   - **Recommendation:** Remove.

**Strengths:**
- Pure function design: `compute_variable_taints` takes inputs, returns a new dict, has no side effects. This is the correct architecture for a composable analysis pass.
- Comprehensive assignment form handling: simple, augmented, tuple unpacking with starred, for-loop targets, with-as, except-as, walrus operators. All 7 forms listed in the docstring are implemented.
- Control flow merging for if/else and loops uses proper snapshot-and-merge with `taint_join`. The for-loop correctly merges body state with pre-loop state (loop may not execute).
- Expression resolution handles all common forms: constants, names, calls, binary ops, collection literals, NamedExpr, IfExp, UnaryOp.
- Test suite covers all assignment forms, control flow merges, parameters, async functions, and nested constructs. 20 test methods.

---

### Engine Integration (`engine.py`)

**Quality Score:** 3 / 5
**Critical Issues:** 0
**High Issues:** 1

**Findings:**

1. **`_find_qualname` has ambiguous suffix matching for same-named functions** - High
   - **Evidence:** `src/wardline/scanner/engine.py:231-244` -- `_find_qualname` first tries exact match, then falls back to suffix match: `key.endswith(f".{name}")`. If a module has `ClassA.process` and `ClassB.process`, calling `_find_qualname("process", taint_map)` returns whichever one dict iteration encounters first. The wrong function gets the wrong taint, and all its variable taints are computed from the wrong L1 base.
   - **Impact:** Silent incorrect taint assignment for any module with two classes that have a method with the same name. This is common in real codebases (e.g., multiple classes with `__init__`, `process`, `validate`, `handle`).
   - **Recommendation:** Pass the full qualname from the AST walk context instead of just `node.name`. The engine already tracks qualnames in the L1 taint pass (`_walk_and_assign` in `function_level.py`). Mirror that approach: walk the AST with scope tracking to build qualnames, then look up in `taint_map` by exact qualname.

2. **Type annotation mismatch on `variable_taint_map` local variable** - Low
   - **Evidence:** `src/wardline/scanner/engine.py:173` -- `variable_taint_map: dict[str, dict[str, object]] | None = None` uses `object` as the inner value type. The actual return type of `_run_variable_taint` at line 197 is `dict[str, dict[str, TaintState]] | None`. `ScanContext.variable_taint_map` expects `TaintState`.
   - **Impact:** No runtime impact (duck typing), but misleads type checkers and readers.
   - **Recommendation:** Change `object` to `TaintState` on line 173 (requires importing or using the existing `TYPE_CHECKING` import).

3. **L2 gating is correct but no CLI override exists** - Low
   - **Evidence:** `src/wardline/cli/scan.py:285` -- `analysis_level = cfg.analysis_level if cfg is not None else 1`. L2 requires a `wardline.toml` config file with `analysis_level = 2`. There is no `--analysis-level` CLI flag.
   - **Impact:** Users cannot test L2 without creating a config file. This is a usability gap, not a correctness issue.
   - **Recommendation:** Add `--analysis-level` CLI option with default 1, following the pattern of other CLI-overrides-config options (e.g., `--max-unknown-raw-percent`).

4. **L2 fault tolerance is correct** - (Strength, not issue)
   - **Evidence:** `src/wardline/scanner/engine.py:219-226` -- `_run_variable_taint` wraps the entire L2 pass in try/except, logs warning, appends error, returns None. Engine continues with L1-only context. Test at `test_engine_taint_wiring.py:256` verifies this.

**Strengths:**
- L1 default, L2 opt-in gating at `engine.py:174` is clean and correct.
- L2 failure is fault-tolerant: caught, logged, and the scan continues with L1-only context.
- Engine test coverage for L2 gating includes: L1 does not populate variable_taint_map, L2 does populate it, L2 failure is handled gracefully.

---

### ScanContext (`context.py`)

**Quality Score:** 5 / 5
**Critical Issues:** 0
**High Issues:** 0

**Findings:** None.

**Strengths:**
- `variable_taint_map` field added cleanly with `None` default (backward compatible).
- `__post_init__` deep-freezes the variable taint map via `MappingProxyType`, consistent with the existing `function_level_taint_map` freezing pattern.
- Type annotation correctly allows both `dict` input (for construction) and `MappingProxyType` (after freezing).

---

### CLI Registration (`scan.py`)

**Quality Score:** 5 / 5
**Critical Issues:** 0
**High Issues:** 0

**Findings:** None.

**Strengths:**
- All four new rules (006-009) registered in `_make_rules()` at lines 57-60, maintaining import-and-tuple pattern.
- `analysis_level` threaded from config to engine at line 285-292.
- Registry sync check will catch if any rule is added to `RuleId` enum but not instantiated here.

---

## Coupling Assessment: WP 1.5 / WP 1.6

**Coupling Risk: Low**

The two WPs are cleanly separated:
- Rules 006-009 use `self._get_function_taint()` which reads from `function_level_taint_map` (L1). None of the four rules reads `variable_taint_map` (L2).
- L2 taint populates `variable_taint_map` on `ScanContext` but no rule currently consumes it.
- The engine runs L2 in "Pass 1.5" before rules execute in "Pass 2", so the data is available when rules need it in future.
- No shared mutable state between the two WPs.

The only coupling point is the `ScanContext` dataclass, which is the correct architectural seam for this data.

---

## Information Gaps

1. **Matrix entries for rules 006-009**: I did not read the severity matrix definition to verify that `matrix.lookup` returns correct values for all taint states. The tests for PY-WL-007 verify specific severity values, which provides indirect evidence the matrix is wired correctly.
2. **Integration test coverage**: I checked unit tests only. The integration test baseline decomposition (commit `7a85738`) may cover these rules end-to-end but I did not verify.
3. **`ScannerConfig.analysis_level` validation**: I did not check if `analysis_level` is validated (e.g., must be 1 or 2, not 0 or 99).

## Caveats

- This assessment is based on static code review. I did not execute the test suite.
- The "High" rating on `_find_qualname` assumes modules with same-named methods across classes exist in the target codebase. If the scanner is currently only used on codebases without name collisions, the bug is latent rather than active.

---

## Summary

| Component | Score | Critical | High | Medium | Low |
|-----------|-------|----------|------|--------|-----|
| PY-WL-006 | 4/5 | 0 | 0 | 0 | 0 |
| PY-WL-007 | 4/5 | 0 | 0 | 0 | 2 |
| PY-WL-008 | 4/5 | 0 | 0 | 0 | 1 |
| PY-WL-009 | 3/5 | 0 | 1 | 2 | 1 |
| variable_level.py | 4/5 | 0 | 0 | 2 | 1 |
| engine.py (L2 integration) | 3/5 | 0 | 1 | 0 | 2 |
| context.py | 5/5 | 0 | 0 | 0 | 0 |
| scan.py (CLI) | 5/5 | 0 | 0 | 0 | 0 |
| **Totals** | | **0** | **2** | **4** | **7** |

**Top priority fixes:**
1. `engine.py:231-244` -- `_find_qualname` suffix-match ambiguity (High)
2. `py_wl_009.py:90-95` -- Function name/behavior mismatch on attr access (High via PY-WL-009 score, Medium severity)
3. `variable_level.py:450-473` -- `_handle_try` sequential vs. merge semantics (Medium)
