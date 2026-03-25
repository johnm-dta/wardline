# Rule Conformance Audit — 2026-03-25

**Scope:** All 9 PY-WL rules against Wardline Specification v0.2.0 DRAFT
**Method:** Three-phase systematic audit (pre-sweep, per-rule deep audit, reconciliation)
**Auditor:** Claude Opus 4.6 (automated, human-supervised)

---

## Executive Summary

All 9 scanner rules correctly use the severity matrix infrastructure — 72/72 cells
match the spec. The conformance issues are in three areas:

1. **Detection surface gaps** — rules miss semantic equivalents or over-detect
2. **SARIF metadata bug** — all 9 rule short descriptions are wrong
3. **Corpus quality** — broken specimens, missing adversarial coverage

Two rules need significant work (PY-WL-004, PY-WL-006). Five are medium
conformance. Two are high conformance (PY-WL-001, PY-WL-007).

---

## Phase 1: Systemic Pre-Sweep Results

All 9 rules share the same correct pattern:
- Call `matrix.lookup(self.RULE_ID, taint)` for severity grading
- Acquire taint via `self._get_function_taint(self._current_qualname)`
- Emit `Finding` objects with all 5 mandatory SARIF properties

No hardcoded taint gates preempt the matrix in any rule.

---

## Cross-Cutting Issues

### X-1: SARIF `_RULE_SHORT_DESCRIPTIONS` wrong for all rules (P1)

The `_RULE_SHORT_DESCRIPTIONS` dict in `sarif.py` contains incorrect descriptions
for at least PY-WL-002 ("Missing shape validation on external input"), PY-WL-005
("Unsafe type coercion on tainted data"), and PY-WL-007 ("Pipeline stage ordering
violation"). These appear to be placeholder/copy-paste errors from an earlier
iteration. All 9 entries should be audited and corrected.

**Decision:** fix-code

### X-2: SARIF `wardline.taintState` conditionally dropped (P2)

The `_clean_none` helper strips None-valued keys. If `taint_state` is None, the
mandatory `wardline.taintState` property is omitted. In practice, `_get_function_taint()`
defaults to `UNKNOWN_RAW` so this never triggers, but the pattern is fragile.

**Decision:** fix-code (defensive)

### X-3: Missing SARIF result-level properties (P2)

Spec section 10.1 defines additional result-level properties (`wardline.enclosingTier`,
`wardline.annotationGroups`, `wardline.excepted`, `wardline.dataSource`,
`wardline.retroactiveScan`) that are not emitted. These require infrastructure
(tier mapping, annotation group tracking, exception register integration).

**Decision:** document — track as separate work item

### X-4: Corpus negative specimens broken across multiple rules (P1)

PY-WL-006 positive specimens contain `logger.error("failed")` instead of
`audit.emit("failed")` — scanner produces zero findings on them. PY-WL-005
negative specimens contain silent handler code (true positives, not true negatives).

**Decision:** fix-corpus — audit all specimen directories for correctness

### X-5: No rules use L2 variable-level taint (P2)

The `variable_taint_map` is available in `ScanContext` but unused by all rules.
This limits PY-WL-009 (can't trace data-flow from shape boundary outputs) and
PY-WL-006 (can't distinguish audit-tainted variables from regular ones).

**Decision:** document — prerequisite for several P2 detection improvements

---

## Per-Rule Audit Summaries

### PY-WL-001: Dict key access with fallback default — HIGH conformance

**Matrix:** 8/8 cells match. schema_default governance correctly bypasses matrix.
**Detection:** 3/3 listed patterns implemented (.get, .setdefault, defaultdict).
`d.pop(key, default)` is a spec gap — not listed in binding table but has identical risk.
**Suppression:** schema_default three-condition governance is correctly implemented.
**Corpus:** 8/8 taint states covered. Missing schema_default specimens.
**SARIF:** All 3 finding types emit correct properties.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 001-D1 | `d.pop(key, default)` not detected | fix-spec (add to binding table), then fix-code | P3 |
| 001-D2 | No schema_default corpus specimens | fix-corpus | P2 |
| 001-D3 | Aliased schema_default imports not tracked | document (known, deferred to L3) | — |

### PY-WL-002: Attribute access with fallback default — MEDIUM conformance

**Matrix:** 8/8 cells match.
**Detection:** Only 3-arg `getattr()`. Missing `obj.attr or default` semantic equivalent.
**Suppression:** None exist, none needed per current spec.
**Corpus:** 8/8 states covered but thin.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 002-D1 | hasattr() listed in both PY-WL-002 and PY-WL-003 | fix-spec (remove from PY-WL-002 row) | P1 |
| 002-D2 | `obj.attr or default` not detected | fix-code | P2 |
| 002-D4 | No schema_default equivalent for attributes | fix-spec (design decision) | P3 |
| 002-D5 | SARIF shortDescription wrong | fix-code (covered by X-1) | P1 |

### PY-WL-003: Existence-checking as structural gate — MEDIUM conformance

**Matrix:** 8/8 cells match. Old `_ACTIVE_TAINTS` gate confirmed removed (commit 1ea08d1).
**Detection:** 5 patterns implemented. `in`/`not in` over-detects on value-membership.
**Suppression:** Boundary suppression (shape/combined) is correct per spec.
**Corpus:** 8/8 states covered. No boundary-suppression negative specimen.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 003-D1 | `in`/`not in` fires on value-membership checks | fix-code (precision heuristic) | P1 |
| 003-D2 | hasattr() dual-listing in binding table | fix-spec | P1 |
| 003-G3 | No boundary-suppression negative specimen | fix-corpus | P2 |

### PY-WL-004: Broad exception handlers — NEEDS WORK

**Matrix:** 8/8 cells match (mixed WARNING/ERROR correctly graded).
**Detection:** Core patterns correct. Missing re-raise suppression and contextlib.suppress.
**Suppression:** Zero suppression logic — every broad handler fires unconditionally.
**Corpus:** 26 specimens, good coverage. No re-raise adversarial specimen.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 004-D4 | `except Exception: raise` fires (spec says it should not) | fix-code | P1 |
| 004-D5 | `contextlib.suppress(Exception)` not detected | fix-code | P2 |
| 004-G7 | No re-raise adversarial false-positive specimen | fix-corpus (blocked by 004-D4) | P2 |

### PY-WL-005: Silent exception handling — MEDIUM conformance

**Matrix:** 8/8 cells match.
**Detection:** 4 core patterns detected. Multi-statement silent bodies missed.
**Suppression:** `len(handler.body) != 1` guard is conservative but acceptable.
**Corpus:** Negative specimens broken (contain TP code).

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 005-D1 | Multi-statement silent bodies not detected | fix-code | P3 |
| 005-C1 | Negative specimens contain silent handler code | fix-corpus | P1 |
| 005-C2 | Missing TN YAML metadata for 6 taint states | fix-corpus | P2 |

### PY-WL-006: Audit writes in broad handlers — NEEDS WORK

**Matrix:** 8/8 cells match.
**Detection:** Heuristic name matching too broad. Cross-module decorated functions missed.
**Suppression:** None.
**Corpus:** All 8 positive specimen .py files contain wrong code (BLOCKING).

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 006-D5 | All 8 positive specimen .py files broken | fix-corpus | P0 |
| 006-D1 | Heuristic false positives (record_count, emit_metric) | fix-code | P2 |
| 006-D3 | Bare `record()`, `emit()` too generic | fix-code | P2 |
| 006-D2 | Cross-module @audit_writer not detected at L1 | document | — |
| 006-D4 | Dominance analysis assigned to PY-WL-006 | document | — |

### PY-WL-007: Runtime type-checking — HIGH conformance

**Matrix:** 8/8 cells match. SUPPRESS cells handled correctly.
**Detection:** isinstance() and type() comparison — the two primary Python idioms.
**Suppression:** All 4 suppressions well-justified (AST dispatch, dunder, frozen dc, boundary).
**Corpus:** Full 8x2 coverage. Missing suppression-pattern specimens.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 007-D1 | SARIF shortDescription wrong | fix-code (covered by X-1) | P1 |
| 007-G4 | No suppression-pattern corpus specimens | fix-corpus | P3 |
| 007-G2 | 3 taint states not unit-tested in TestTaintGating | fix-code (tests) | P3 |

### PY-WL-008: Boundary with no rejection path — MEDIUM conformance

**Matrix:** 8/8 cells match (E/U across all states).
**Detection:** Correct boundary set. Missing two-hop delegation and unreachable paths.
**Suppression:** Boundary identification correct.
**Corpus:** 16 specimens, no adversarial.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 008-D6 | `if False: raise` treated as valid rejection path | fix-code | P1 |
| 008-D3 | Two-hop call-graph delegation not implemented | document (needs L2/L3) | — |
| 008-D7 | Degenerate case (body that only raises) no advisory | document (SHOULD-level) | P3 |
| 008-A1-A8 | No adversarial corpus specimens | fix-corpus | P2 |

### PY-WL-009: Semantic validation without shape validation — MEDIUM conformance

**Matrix:** 8/8 cells match (E/U across all states).
**Detection:** Body heuristic instead of data-flow tracing. Not variable-scoped.
**Suppression:** Combined boundary exclusion correct. Attribute exclusion defensible.
**Corpus:** 16 specimens, all clones. No adversarial.

| ID | Issue | Decision | Priority |
|----|-------|----------|----------|
| 009-D3 | `_has_shape_check_before` not variable-scoped | fix-code | P2 |
| 009-D1 | Body heuristic vs data-flow tracing | document (needs L2 taint) | — |
| 009-D2 | Attribute access exclusion | document (binding deviation) | — |
| 009-D4 | All specimens are clones | fix-corpus (add adversarial) | P2 |

---

## Scorecard

| Rule | Matrix | Detection | Suppression | Corpus | SARIF | Overall |
|------|--------|-----------|-------------|--------|-------|---------|
| PY-WL-001 | 8/8 | good | correct | minor gaps | X-1 | **HIGH** |
| PY-WL-002 | 8/8 | narrow | N/A | thin | X-1 | **MEDIUM** |
| PY-WL-003 | 8/8 | over-broad | correct | no suppression TN | X-1 | **MEDIUM** |
| PY-WL-004 | 8/8 | re-raise FP | missing | no re-raise spec | X-1 | **NEEDS WORK** |
| PY-WL-005 | 8/8 | good | acceptable | broken negatives | X-1 | **MEDIUM** |
| PY-WL-006 | 8/8 | heuristic | N/A | broken positives | X-1 | **NEEDS WORK** |
| PY-WL-007 | 8/8 | good | well-justified | minor gaps | X-1 | **HIGH** |
| PY-WL-008 | 8/8 | unreachable gap | correct set | no adversarial | X-1 | **MEDIUM** |
| PY-WL-009 | 8/8 | body heuristic | not var-scoped | clones | X-1 | **MEDIUM** |
