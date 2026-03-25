# Wardline Rule Conformance Audit — Process Document

**Date:** 2026-03-25
**Scope:** PY-WL-001 through PY-WL-009 + SCN-021, plus supporting infrastructure
**Trigger:** Completion of wardline-watcher-8796953316 (Groups 7–15 decorator reconciliation)
**Outcome:** Conformance certification + implementation quality review

---

## 1. Audit Objective

This audit serves two audiences:

- **Assessors / governance reviewers:** A conformance record documenting whether each rule's implementation matches the Wardline specification's normative requirements — severity matrix cells, exceptionability classes, detection patterns, SARIF output, and interface contract (Part II-A §A.3).
- **Engineers:** A quality review surfacing bugs, precision/recall concerns, architectural debt, missing edge cases, and test gaps.

Each role's assessment is clearly separated so the artifact can be read by either audience independently.

---

## 2. Audit Structure

### Two Phases

| Phase | Purpose | Execution |
|-------|---------|-----------|
| **Phase 1: Per-Rule-Group Analysis** | Deep analysis of each rule's implementation against the spec, from 6 specialist perspectives | 4 parallel subagents, one per rule group |
| **Phase 2: Cross-Cutting Functional Assessment** | Systemic analysis that spans rules — taint propagation, boundary enforcement, governance surface | 3 parallel subagents, informed by Phase 1 synthesis |

### Phase 1 Rule Groups

| Group | Rules | Theme | Spec Lineage |
|-------|-------|-------|-------------|
| **A: Fallback Defaults** | PY-WL-001, PY-WL-002, PY-WL-003 | Is the code substituting policy decisions for data access? | WL-001 (split) + WL-002 |
| **B: Exception Handling** | PY-WL-004, PY-WL-005, PY-WL-006 | Is the code destroying evidence? | WL-003 + WL-004 + WL-005 |
| **C: Structural Verification** | PY-WL-007, PY-WL-008, PY-WL-009 | Does the code's structure match its declarations? | WL-006 + WL-007 + WL-008 |
| **D: Decorator Surface** | SCN-021 | Is the decorator vocabulary internally consistent? | Part II-A §A.4.3 |

**Grouping rationale:**

- **Group A:** PY-WL-001/002 are both WL-001 splits (dict vs attribute access). PY-WL-003 (WL-002, existence checking) shares the theme of structural trust assumptions. All three are pure AST pattern rules.
- **Group B:** PY-WL-004/005/006 all detect exception handling patterns that destroy diagnostic evidence. PY-WL-006 adds audit-path awareness but shares the exception-handler AST surface.
- **Group C:** PY-WL-007 (runtime type-checking), PY-WL-008 (no rejection path), PY-WL-009 (validation ordering) all require semantic context from the scanner engine — tier classification, boundary declarations, call-graph awareness. They share the deeper analysis path.
- **Group D:** SCN-021 (contradictory decorator combinations) was the centrepiece of the just-completed reconciliation. Isolating it lets the audit assess whether the reconciliation is complete before other rules depend on it.

### Phase 1 Scope Per Group

Each group's analysis covers:
- The rule implementation file(s) in `src/wardline/scanner/rules/`
- The corresponding test file(s) in `tests/unit/scanner/` and `tests/unit/decorators/`
- **One level of critical dependencies:** how the rule reads the severity matrix, resolves taint context, interacts with the scanner engine, and produces SARIF output

Infrastructure beyond one level of dependency is covered by Phase 2.

### Phase 2 Functional Assessment Clusters

| Cluster | Agents (from functional taxonomy) | Scope |
|---------|-----------------------------------|-------|
| **F1: Trust Topology & Taint Integrity** | Tier Consistency, Taint Propagation, Evidence Restoration, Bounded Context Completeness | `core/taints.py`, `core/tiers.py`, `core/matrix.py`, `scanner/context.py`, `scanner/engine.py`, `decorators/authority.py`, `decorators/boundaries.py`, manifest overlay consumption |
| **F2: Boundary & Perimeter Enforcement** | Validation Boundary, Normalisation Boundary, Enforcement Perimeter, Semantic Boundary | `scanner/discovery.py`, `scanner/engine.py`, `manifest/scope.py`, `manifest/loader.py`, `manifest/merge.py`, `manifest/coherence.py` |
| **F3: Governance & Compliance Surface** | Exception Governance, Fingerprint Baseline, Manifest/Overlay Consistency, Prohibited Pattern + Coding Posture (merged), Non-Normative Compliance | `manifest/exceptions.py`, `scanner/fingerprint.py`, `manifest/loader.py`, `manifest/merge.py`, `core/matrix.py`, `core/severity.py`, `scanner/sarif.py` |

**Dropped:** Cross-Language Consistency Agent (Python-only codebase).

**Merged:** Prohibited Pattern Agent and Coding Posture Agent (both assess severity matrix application from different angles — combined to avoid duplication).

---

## 3. Review Roles (Phase 1)

Six specialist perspectives are applied to each rule group:

| Role | Focus | Key Questions |
|------|-------|---------------|
| **Solution Architect** | Spec conformance + architectural fit | Does the implementation match §7 severity matrix and §A.3 interface contract? Does the rule's integration follow established engine patterns? |
| **Systems Thinker** | Interaction effects + feedback dynamics | How do these rules interact with each other and the taint model? Are there reinforcing loops (e.g., false positive pressure on governance)? |
| **Python Engineer** | Code quality + idiom correctness | Is the AST handling correct? Are Python edge cases covered? Is the code performant and idiomatic? |
| **Quality Engineer** | Test coverage + corpus alignment | Are all relevant severity matrix cells tested? Are there adversarial cases? Do tests align with §10 golden corpus requirements? |
| **Static Analysis Specialist** | Detection precision + recall | What are the false positive patterns? What's the evasion surface? Are semantic equivalents tracked per §7's living catalogue requirement? |
| **Security Architect** | Threat model alignment + evasion resistance | Does the rule address the ACF failure mode it claims to (§2 mapping)? How easily can it be bypassed? |

---

## 4. Artifact Templates

### Phase 1 Document Template

```markdown
# Group [X]: [Theme]

**Rules:** [list with binding rule → framework rule mapping]
**Files reviewed:** [rule files, test files, critical dependencies]
**Date:** 2026-03-25

## Rules Under Review

### [PY-WL-NNN]: [Description]
- **Framework rule:** WL-NNN
- **Implementation:** `src/wardline/scanner/rules/py_wl_nnn.py`
- **Tests:** `tests/unit/scanner/test_py_wl_nnn.py` (or equivalent)
- **Critical dependencies:** [list]

[Repeat per rule]

---

## Solution Architect Assessment

### Spec Conformance
[Per-rule: severity matrix cell coverage, exceptionability classes,
interface contract compliance, SARIF property bag correctness]

### Architectural Fit
[Integration with engine, pattern consistency with other rules,
separation of concerns]

### Verdict: PASS | CONCERN | FAIL
[Evidence for verdict]

---

## Systems Thinker Assessment

### Interaction Effects
[How rules in this group interact with each other, with the taint
model, and with rules in other groups]

### Feedback Loops
[Reinforcing/balancing dynamics — false positive pressure,
governance load, evasion surface evolution]

### Verdict: PASS | CONCERN | FAIL

---

## Python Engineer Assessment

### Code Quality
[AST handling correctness, edge cases, Python idiom adherence,
error handling, code clarity]

### Performance
[Scaling characteristics, unnecessary traversals, AST walk efficiency]

### Verdict: PASS | CONCERN | FAIL

---

## Quality Engineer Assessment

### Test Coverage
[Severity matrix cells tested, boundary conditions, negative cases,
error paths]

### Corpus Alignment
[Alignment with §10 golden corpus specimen requirements —
positive/negative per cell, adversarial specimens]

### Verdict: PASS | CONCERN | FAIL

---

## Static Analysis Specialist Assessment

### Detection Precision
[False positive patterns, AST pattern completeness, suppression
marker handling (e.g., schema_default for PY-WL-001)]

### Detection Recall
[Known false negatives, semantic equivalent coverage,
evasion variants per §7 living catalogue]

### Verdict: PASS | CONCERN | FAIL

---

## Security Architect Assessment

### Threat Model Alignment
[ACF failure mode mapping from §2, coverage completeness]

### Evasion Resistance
[Bypass difficulty, compensating controls, residual risk
alignment with §12]

### Verdict: PASS | CONCERN | FAIL

---

## Summary

| Role | Verdict | Critical Findings |
|------|---------|-------------------|
| Solution Architect | | |
| Systems Thinker | | |
| Python Engineer | | |
| Quality Engineer | | |
| Static Analysis Specialist | | |
| Security Architect | | |

### Actions
- **Must fix:** [list]
- **Should fix:** [list]
- **Track as debt:** [list]
```

### Phase 2 Document Template

```markdown
# Functional Cluster [FN]: [Name]

**Agents:** [list]
**Files reviewed:** [list]
**Date:** 2026-03-25
**Phase 1 inputs:** [findings consumed from synthesis]

## [Agent Name] Assessment

### Findings
[Structured findings with evidence — file paths, line numbers,
spec section references]

### Cross-References to Phase 1
[Where Phase 1 rule-level findings connect to this systemic concern]

### Verdict: PASS | CONCERN | FAIL

[Repeat per agent]

## Summary

| Agent | Verdict | Critical Findings |
|-------|---------|-------------------|
```

### Synthesis Document Template

```markdown
# Audit Synthesis

**Date:** 2026-03-25
**Documents reviewed:** [list all 7]

## Critical Findings (must fix before commit)
[Prioritized list with source document reference]

## Concerns (should fix or file as tracked debt)
[Prioritized list]

## Observations (informational)
[List]

## Conformance Summary

| Rule / Area | SA | ST | PE | QE | SAS | SecA | Overall |
|-------------|----|----|----|----|-----|------|---------|
| PY-WL-001 | | | | | | | |
| ... | | | | | | | |
| SCN-021 | | | | | | | |
| F1: Trust/Taint | — | — | — | — | — | — | |
| F2: Boundary | — | — | — | — | — | — | |
| F3: Governance | — | — | — | — | — | — | |

## Recommendations
[Ordered by priority]
```

---

## 5. Verdict Scale

| Verdict | Meaning | Required Action |
|---------|---------|-----------------|
| **PASS** | Implementation matches spec, no significant issues | None |
| **CONCERN** | Implementation works but has gaps, edge cases, or debt | File as tracked issue in Filigree |
| **FAIL** | Implementation contradicts spec or has a correctness bug | Must fix before merge |

---

## 6. Execution Sequence

```
Step 1: Write this process document (00-process.md)
         │
Step 2: Phase 1 — launch 4 parallel subagents
         │  ├── Group A: Fallback Defaults
         │  ├── Group B: Exception Handling
         │  ├── Group C: Structural Verification
         │  └── Group D: Decorator Surface
         │
Step 3: Phase 1 synthesis (phase-1-synthesis.md)
         │
Step 4: Phase 2 — launch 3 parallel subagents
         │  ├── F1: Trust Topology & Taint Integrity
         │  ├── F2: Boundary & Perimeter Enforcement
         │  └── F3: Governance & Compliance Surface
         │
Step 5: Final synthesis (synthesis.md)
```

### Subagent Inputs

Each Phase 1 subagent receives:
- The relevant spec sections (§4–§7 for all; §A.3–A.4 for Python binding specifics)
- Exact file paths for rule implementations, tests, and critical dependencies
- The artifact template from §4 above
- The verdict scale from §5 above

Each Phase 2 subagent receives:
- The Phase 1 synthesis document
- The relevant spec sections for its functional concern
- Exact file paths for its scope
- The Phase 2 artifact template

---

## 7. Quality Gates

- Every verdict must cite specific evidence (file path + line number or spec section)
- FAIL verdicts must include a concrete description of the gap
- CONCERN verdicts must include a recommendation (fix vs. track as debt)
- The synthesis document must account for every FAIL and CONCERN from all 7 source documents
