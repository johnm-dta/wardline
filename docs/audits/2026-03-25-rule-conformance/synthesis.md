# Wardline Rule Conformance Audit — Final Synthesis

**Date:** 2026-03-25
**Total agents:** 35 independent specialists (24 Phase 1 + 11 Phase 2)
**Total artifacts:** 35 documents across `phase-1/` and `phase-2/`
**Methodology:** Each agent received only its role brief and files — no agent saw another's findings

---

## Executive Summary

The Wardline scanner's **core enforcement model is conformant**: all 72 severity matrix cells match the spec, the join lattice is correctly implemented, and the taint propagation engine is sound across 3 analysis levels.

However, the audit uncovered **4 critical findings** (must fix), **12 high-priority concerns** (should fix), and **17+ tracked debt items**. The most impactful finding is that validation boundary bodies evaluate at the wrong taint state (output tier instead of input tier), systematically producing false negatives inside validators.

---

## Discrepancy Resolution

**SARIF descriptions:** Phase 1 agents (B-SA, C-SA) reported wrong `_RULE_SHORT_DESCRIPTIONS` for PY-WL-004 through PY-WL-009. Phase 2 agent (F3-Manifest Consistency) reported all 27 entries are correct. **Resolution:** Direct inspection of `src/wardline/scanner/sarif.py` confirms all descriptions are correct in the current file (lines 31-56). The Phase 1 agents appear to have hallucinated the content of specific lines. **The SARIF descriptions are NOT a finding.** This demonstrates the value of independent corroboration — a finding reported by 2 agents but contradicted by a 3rd (plus direct verification) is correctly resolved as a false positive.

---

## Critical Findings (Must Fix)

### CF-1: Validation boundary bodies evaluate at OUTPUT tier, not INPUT tier [BUG]
**Source:** F2-Validation Boundary (FAIL), F1-Tier Consistency (CONCERN, independent confirmation)
**File:** `src/wardline/scanner/taint/function_level.py` — `DECORATOR_TAINT_MAP`
**Spec:** Part II-A §A.4.3 body evaluation context table
**Issue:** `@validates_shape` bodies evaluate at SHAPE_VALIDATED (output) instead of EXTERNAL_RAW (input). `@validates_semantic` evaluates at PIPELINE instead of SHAPE_VALIDATED. This means pattern rules inside validators fire at the wrong severity — existence checking in a shape validator should be expected (EXTERNAL_RAW → suppressed for PY-WL-003) but instead fires at SHAPE_VALIDATED severity.
**Impact:** Systematic false negatives for pattern rules inside validation boundary bodies. The current rules partially compensate with per-rule boundary suppression (PY-WL-003, PY-WL-007), but this creates a trap for future rules that lack explicit suppression.
**Fix:** Split `DECORATOR_TAINT_MAP` into two maps: `BODY_EVALUATION_TAINT` (input tier for rule severity) and `RETURN_VALUE_TAINT` (output tier for taint propagation).

### CF-2: SCN-021 test coverage at 14% — only FAIL verdict in audit
**Source:** D-Quality Engineer (FAIL), corroborated by D-SA, D-PE, D-SAS, D-SecA (all CONCERN)
**Issue:** 4 of 29 spec-mandated combinations tested. Zero exceptionability assertions. Only 1 negative test. The foundation rule that validates the decorator surface all other rules depend on has the thinnest coverage in the codebase.
**Fix:** Parametrized test across all 29 entries + negative cases. Straightforward given the table-driven design.

### CF-3: Bounded context enforcement entirely absent [ENFORCEMENT GAP]
**Source:** F1-Bounded Context (FAIL)
**Issue:** Data layer is complete (models, schema, loader all handle bounded contexts and contract bindings). But no scanner rule or coherence check verifies that Tier 2 boundaries carry `bounded_context` declarations. Contract bindings are parsed but never validated against the codebase. Stale and unmatched contract detection (§9.2 coherence conditions 4 and 5) not implemented.
**Spec:** §13.1.2 — "The tool presence-checks the bounded_context field — a boundary claiming Tier 2 semantics without a bounded_context declaration is a finding."

### CF-4: @restoration_boundary decorator not implemented [FEATURE GAP]
**Source:** F1-Evidence Restoration (FAIL)
**Issue:** Group 17 (Restoration Boundaries) has no decorator implementation. Not in registry, not exported. The overlay/manifest path works but the code-level annotation is absent. No evidence-to-tier demotion enforcement — a `restored_tier=1` claim with only structural evidence passes without findings.
**Spec:** §5.3, §6 Group 17, §A.4.2

---

## High-Priority Concerns (Should Fix)

### HC-1: Zero severity matrix cell tests across ALL rules [SYSTEMIC]
**Corroboration:** 4 independent Quality Engineers (A-QE, B-QE, C-QE, D-QE — unanimous)
**Issue:** No test injects a specific taint state and verifies severity AND exceptionability. The AUDIT_TRAIL UNCONDITIONAL cells and the governance-critical U/St distinction are entirely unverified by tests.
**Fix:** Parametrized matrix cell tests per rule using ScanContext taint injection.

### HC-2: Two-hop call-graph analysis not implemented for PY-WL-008 [SPEC MUST]
**Corroboration:** 5 independent agents (C-SA, C-ST, C-SAS, F1-Taint Propagation, F2-Validation Boundary)
**Spec:** §8.1 MUST language
**Issue:** Validators delegating to schema libraries produce false positives. Since E/U, cannot be governed. Creates declaration-avoidance pressure.
**Mitigation path:** Call-graph infrastructure in `scanner/taint/callgraph.py` already extracts edges.

### HC-3: Living pattern catalogue not implemented [SPEC MUST]
**Corroboration:** F3-Compliance Surface (FAIL on this item), 3 Phase 1 Static Analysis Specialists
**Spec:** §7 para 2 — "Language bindings MUST maintain version-tracked lists of semantic equivalents"
**Issue:** No rule has a formal catalogue. The A-SAS agent produced an initial catalogue of 27 equivalents.

### HC-4: Control law reporting absent from SARIF [SPEC MUST]
**Source:** F3-Compliance Surface (FAIL on this item)
**Spec:** §9.5 — `wardline.controlLaw` in SARIF run properties
**Issue:** No code determines or reports normal/alternate/direct law state.

### HC-5: SCN-021 alias pair #5/#19 produces duplicate findings
**Corroboration:** 4 independent agents (D-SA, D-PE, D-SAS, D-SecA)
**Fix:** Remove entry #19 or add deduplication.

### HC-6: PY-WL-009 dead-isinstance evasion
**Source:** C-Security Architect
**Issue:** Bare `isinstance(data, object)` (result discarded) suppresses the finding. Enables 3-rule simultaneous evasion of the structural verification chain.

### HC-7: severity_at_grant never compared during exception application [SPEC MUST]
**Source:** F3-Exception Governance
**Spec:** §13.1.3 — staleness detection when severity differs from grant time
**File:** `src/wardline/scanner/exceptions.py:apply_exceptions`

### HC-8: 3 of 5 coherence checks missing
**Source:** F3-Manifest Consistency
**Missing:** Tier-topology consistency, unmatched contracts, stale contract bindings (§9.2)

### HC-9: dependency_taint declarations completely absent
**Source:** F2-Semantic Boundary
**Spec:** §13.1.2, §5.5
**Issue:** No schema property, no model, no loader. Overlay schema would reject the field.

### HC-10: PY-WL-006 TryStar deduplication missing
**Source:** B-Python Engineer

### HC-11: wardline.governanceProfile missing from SARIF output
**Source:** F3-Compliance Surface

### HC-12: Ratification overdue produces no SARIF finding
**Source:** F3-Manifest Consistency
**Spec:** §13.1.1 MUST language

---

## Phase 2 Verdict Grid

| Cluster | Agent | Verdict |
|---------|-------|---------|
| **F1: Trust/Taint** | Tier Consistency | CONCERN |
| | Taint Propagation | CONCERN |
| | Evidence Restoration | **FAIL** |
| | Bounded Context | **FAIL** |
| **F2: Boundary/Perimeter** | Validation Boundary | **FAIL** |
| | Enforcement Perimeter | CONCERN |
| | Semantic Boundary | CONCERN |
| **F3: Governance/Compliance** | Exception Governance | CONCERN |
| | Manifest Consistency | CONCERN |
| | Fingerprint Baseline | PASS |
| | Compliance Surface | CONCERN |

**11 verdicts: 1 PASS, 7 CONCERN, 3 FAIL.**

---

## What Works Well

These areas received clean PASS verdicts or were highlighted as strengths:

1. **Severity matrix encoding** — 72/72 cells correct (4 independent Solution Architects)
2. **Join lattice** — all 36 state-pairs correct (F1-Taint Propagation)
3. **Taint propagation engine** — 3 analysis levels, SCC-based fixed-point, sound (F1-Taint Propagation)
4. **Fingerprint baseline** — fully working with correct hash scope, canonicalisation, coverage reporting (F3)
5. **Overlay merge** — narrowing-only enforced, widening rejected as error (F2-Semantic Boundary, F3-Manifest)
6. **UNCONDITIONAL cell protection** — triple enforcement via immutable matrix, exception rejection, merge guard (F3-Compliance)
7. **Inter-rule evasion dynamics** — bypassing one rule triggers another with stricter governance (A-ST, A-SecA, C-SecA)
8. **schema_default() three-condition gate** — sound suppression mechanism with abuse resistance (A-SA, A-SecA)
9. **SCN-021 completeness** — all 29 spec combinations present with correct severity (D-SA)
10. **"Both must agree" coherence** — orphaned annotations and undeclared boundaries detected (F2-Semantic Boundary)

---

## Tracked Debt

| ID | Finding | Source | P |
|----|---------|-------|---|
| TD-1 | `contextlib.suppress(Exception)` invisible to PY-WL-004/005/006 | B-SAS, B-SecA | P2 |
| TD-2 | `dict.pop(key, default)` missing from PY-WL-001 | A-SAS, A-SecA | P2 |
| TD-3 | `d.get("key") or default` evasion for PY-WL-001 | A-SAS | P2 |
| TD-4 | `in` operator false positives on non-dict containers (PY-WL-003) | A-SAS | P3 |
| TD-5 | PY-WL-006 `emit` prefix too broad in `_AUDIT_ATTR_PREFIXES` | B-SAS | P3 |
| TD-6 | PY-WL-006 dominance analysis guard-clause false positives | B-SAS | P3 |
| TD-7 | PY-WL-006 `_analyze_match` omits no-wildcard fall-through | B-PE | P3 |
| TD-8 | Constant-False guard detection for PY-WL-008 (spec SHOULD) | C-SA, C-SAS | P3 |
| TD-9 | Degenerate-body advisory for PY-WL-008 (spec SHOULD) | C-SA | P3 |
| TD-10 | SCN-021 no automated sync between registry and combination table | D-ST | P3 |
| TD-11 | SCN-021 suspicious combinations (#27-29) UNCONDITIONAL may be too strict | D-SecA | P4 |
| TD-12 | Dynamic import evasion produces no SARIF finding | D-SecA | P3 |
| TD-13 | PY-WL-002 `obj.attr or default` conflates absence with falsy value | A-SAS | P3 |
| TD-14 | PY-WL-008/009 `_decorator_name` duplicated (DRY violation) | C-PE | P4 |
| TD-15 | Include/exclude uses path prefixes not globs per spec | F2-Perimeter | P3 |
| TD-16 | `follow_symlinks` not configurable in wardline.toml | F2-Perimeter | P4 |
| TD-17 | Exception `elimination_path` and `elimination_cost` fields absent | F3-Exception Gov | P4 |
| TD-18 | Exception `grant_date`, `review_interval`, structured `reviewer` missing | F3-Exception Gov | P3 |
| TD-19 | Recurrence count not auto-incremented | F3-Exception Gov | P3 |
| TD-20 | 3 taint states unreachable at Level 1 via decorators | F1-Tier Consistency | P4 |
| TD-21 | `contextlib.suppress(ValueError)` (specific types) invisible to PY-WL-005 | B-SAS | P3 |
| TD-22 | Self-hosting gate tolerates exit code 1 | F3-Compliance | P3 |

---

## Conformance Assessment Summary

| Conformance Criterion (§14.2) | Status | Evidence |
|-------------------------------|--------|----------|
| 1. Annotation expressiveness (17 groups) | PARTIAL | Groups 1-15 expressed; Group 16 partial (no @data_flow); Group 17 absent (@restoration_boundary) |
| 2. Pattern rule detection (WL-001–006) | **PASS** | All 6 pattern rules implemented intraprocedurally |
| 3. Structural verification (WL-007, WL-008) | PARTIAL | WL-007 implemented; WL-008 ordering implemented; WL-007 missing two-hop |
| 4. Taint-flow tracking | **PASS** | Direct + two-hop + full transitive (3 levels) |
| 5. Precision/recall measured | NOT YET | No per-cell measurement published |
| 6. Golden corpus | PARTIAL | Specimens exist for Groups B; incomplete for others |
| 7. Self-hosting gate | PARTIAL | Integration tests exist but tolerate findings |
| 8. Deterministic SARIF | **PASS** | Verification mode implemented |
| 9. Governance model | PARTIAL | Exception register works; fingerprint works; control law missing; 3/5 coherence checks missing |
| 10. Manifest consumed/validated | **PASS** | Full validation pipeline |

**Current profile:** Wardline-Core partial conformance at Lite governance level. Missing: two-hop for criterion 3, precision measurement for criterion 5, full corpus for criterion 6, control law for criterion 9.

---

## Recommended Priority Order

1. **CF-1** Fix body evaluation taint map (most impactful — systematic false negatives)
2. **CF-2** Expand SCN-021 tests to all 29 combinations (foundation rule coverage)
3. **HC-1** Add parametrized matrix cell tests (systemic testing gap)
4. **HC-2** Implement two-hop rejection path resolution (spec MUST)
5. **HC-5** Remove SCN-021 duplicate entry #19
6. **HC-6** Require isinstance result consumption for PY-WL-009 shape evidence
7. **HC-3** Create initial semantic equivalent catalogues (spec MUST)
8. **HC-4** Implement control law reporting in SARIF
9. **CF-3** Add bounded-context presence check enforcement
10. **CF-4** Implement @restoration_boundary decorator (Group 17)
