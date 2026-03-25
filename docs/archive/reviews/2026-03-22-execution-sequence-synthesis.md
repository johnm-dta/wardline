# Execution Sequence Review Synthesis

**Plan:** `docs/2026-03-22-execution-sequence.md`
**Reviewed:** 2026-03-22
**Reviewers:** Reality, Architecture, Quality, Systems, Python, Security, Leverage
**Verdict:** APPROVE WITH CONDITIONS

---

## 1. Unified Verdict

**APPROVE WITH CONDITIONS.** The execution sequence is structurally sound: 37 tasks across 6 phases with a well-defined critical path, meaningful parallelism windows, and a self-hosting gate that closes the loop. No reviewer recommended rejection. However, all seven reviewers independently found missing dependency edges, and six of seven found acceptance criteria weaker than the design document requires. The plan can proceed to execution after the conditions below are addressed.

The conditions fall into three tiers:
- **12 missing dependency edges** that will cause agent sessions to fail mid-task (must fix before execution)
- **4 missing or underspecified tasks** that drop design requirements (must fix before execution)
- **14 "done when" criteria** that are weaker than the design document requires (should fix, can be patched incrementally)

---

## 2. Cross-Reviewer Convergence

Issues flagged independently by 3 or more reviewers carry the highest confidence. These are not speculative concerns -- they are structural gaps that multiple analytical perspectives identified without coordination.

### Convergence A: T-5.4 missing dependency on T-3.3 (5 reviewers)

**Flagged by:** Reality (B-3), Architecture (Discrepancy 5, related), Quality (implicit in security section), Python (critical issue), Security (F-2)

T-5.4 (`wardline corpus verify`) names `WardlineSafeLoader` in its description but does not list T-3.3 (which produces it) as a dependency. An agent implementing T-5.4 will hit an import error. This is the single most-flagged issue across all reviewers.

### Convergence B: T-4.12 missing dependency on T-1.7 (3 reviewers)

**Flagged by:** Reality (D-7/W-B), Architecture (blocking issue 2), Python (related: T-2.1 needs T-1.7 for `__wrapped__` tests)

T-4.12's acceptance criteria require validating the `__wrapped__` chain traversal path in `WardlineBase`, which is produced by T-1.7. Without this edge, the `__wrapped__` path cannot be tested.

### Convergence C: T-6.2 TN specimens cannot be verified without rules + corpus verify (3 reviewers)

**Flagged by:** Architecture (blocking issue 3), Systems (blocking issue 3), Leverage (feedback delay analysis)

T-6.2 depends only on T-6.1, but its "Done when" criterion ("specimens authored and hashes computed") cannot be meaningfully satisfied without running the scanner to confirm true negatives are actually silent. Without T-4.7--T-4.11 and T-5.4, TN authoring is speculative.

### Convergence D: T-2.1 should depend on T-1.8 to enforce registry freeze (3 reviewers)

**Flagged by:** Systems (blocking issue 1), Leverage (feedback delay analysis), Python (related: registry contract validation)

The design document states the registry "MUST be frozen before parallel streams begin." The dependency graph allows T-2.1 to start in parallel with T-1.8, which exists specifically to validate the registry design. If T-1.8 discovers a flaw, T-2.1 work is invalidated.

### Convergence E: Missing intermediate integration checkpoint (3 reviewers)

**Flagged by:** Systems (warning 4), Leverage (Level 9 intervention), Architecture (related: T-4.3 oversized)

There is no task between Phase 4 (scanner) and Phase 5 (CLI) that runs the scanner library directly on a fixture file. T-5.2 is the first end-to-end integration point. Interface mismatches between manifest loading, taint assignment, and rule execution will surface there -- 10+ tasks after the components were built.

### Convergence F: `agent_originated: null` governance warning dropped (3 reviewers)

**Flagged by:** Reality (W-C/C-9), Quality (BLOCK-2), Security (Finding 7, related)

Design WP-3a RECOMMENDED: emit GOVERNANCE WARNING when scanning exception files with `agent_originated: null`. No task implements this.

### Convergence G: T-4.3 ScanEngine missing manifest system dependencies (3 reviewers)

**Flagged by:** Reality (B-1/D-3), Architecture (related via T-5.5 analysis), Systems (Phase 3/4 boundary analysis)

T-4.3 uses manifest enforcement perimeter filtering but lists no manifest-system dependency. Missing edges: T-3.3 and T-3.4 to T-4.3.

---

## 3. Consolidated Blocking Issues (Deduplicated)

Issues are scored using Priority = Severity x Likelihood x Reversibility, then sorted descending.

### B-01: T-5.4 missing T-3.3 dependency (Priority: 12)
- **Severity:** Critical (4) -- import failure blocks entire task
- **Likelihood:** Certain (3) -- `WardlineSafeLoader` literally does not exist without T-3.3
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Reality, Architecture, Quality, Python, Security
- **Resolution:** Add `T-3.3` to T-5.4's "Depends on" list. Add `T33 --> T54` to Mermaid graph.

### B-02: T-4.3 missing T-3.3 and T-3.4 dependencies (Priority: 12)
- **Severity:** Critical (4) -- ScanEngine cannot load manifests or discover files against perimeter
- **Likelihood:** Certain (3) -- manifest perimeter filtering is core to the engine
- **Reversibility:** Easy (1) -- add two edges
- **Sources:** Reality, Systems
- **Resolution:** Add `T-3.3` and `T-3.4` to T-4.3's "Depends on". Add `T33 --> T43` and `T34 --> T43` to Mermaid graph.

### B-03: T-2.1 should depend on T-1.8 (registry freeze enforcement) (Priority: 12)
- **Severity:** High (3) -- parallel decorator work against unfrozen registry may need full rework
- **Likelihood:** Likely (2) -- tracer bullet exists to find registry flaws; if it finds one, T-2.1 is invalidated
- **Reversibility:** Difficult (2) -- rework propagates into T-2.2, T-2.3
- **Sources:** Systems, Leverage, Python
- **Resolution:** Add `T-1.8` to T-2.1's "Depends on". Add `T18 --> T21` to Mermaid graph. This mechanically enforces the design doc's social "freeze" instruction.

### B-04: T-5.3 missing T-3.5 dependency (Priority: 9)
- **Severity:** High (3) -- baseline update silently omits overlay narrowings from committed baseline
- **Likelihood:** Certain (3) -- `ResolvedManifest` is produced by T-3.5's `merge()`
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Reality
- **Resolution:** Add `T-3.5` to T-5.3's "Depends on". Add `T35 --> T53` to Mermaid graph.

### B-05: T-5.5 missing T-3.3 dependency (Priority: 9)
- **Severity:** High (3) -- `wardline explain` cannot load manifest to show module-tier matches
- **Likelihood:** Certain (3) -- explain command must read manifest
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Architecture
- **Resolution:** Add `T-3.3` to T-5.5's "Depends on". Add `T33 --> T55` to Mermaid graph.

### B-06: T-4.12 missing T-1.7 dependency (Priority: 8)
- **Severity:** High (3) -- `__wrapped__` chain path cannot be validated without WardlineBase
- **Likelihood:** Certain (3) -- acceptance criterion explicitly requires both paths
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Reality, Architecture, Python
- **Resolution:** Add `T-1.7` to T-4.12's "Depends on". Add `T17 --> T412` to Mermaid graph.

### B-07: T-6.4 missing T-6.2 dependency (Priority: 8)
- **Severity:** High (3) -- corpus verify has incomplete coverage without TN specimens
- **Likelihood:** Certain (3) -- `wardline corpus verify` exercises both TN and TP
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Architecture
- **Resolution:** Add `T-6.2` to T-6.4's "Depends on". Add `T62 --> T64` to Mermaid graph.

### B-08: T-3.6 missing T-1.2 dependency (Priority: 6)
- **Severity:** Medium (2) -- orphaned annotation detection cannot enumerate wardline decorators
- **Likelihood:** Certain (3) -- coherence check needs registry to know what decorators look like
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Reality
- **Resolution:** Add `T-1.2` to T-3.6's "Depends on". Add `T12 --> T36` to Mermaid graph.

### B-09: Runtime registry sync check has no implementing task (Priority: 12)
- **Severity:** Critical (4) -- Risk Area 7 mitigation (silent enforcement decay) exists only as tests, not as runtime code
- **Likelihood:** Likely (2) -- design explicitly requires "bidirectional registry check at scan startup"
- **Reversibility:** Easy (1) -- add to T-4.3 or T-5.2
- **Sources:** Security (F-6)
- **Resolution:** Add runtime registry sync check to T-4.3 (ScanEngine startup) or T-5.2 (scan command pre-scan). T-4.12 then tests this runtime check rather than being the only place the check exists.

### B-10: T-3.1 has no test file or test command (Priority: 6)
- **Severity:** Medium (2) -- schemas are the contract for all downstream manifest tasks
- **Likelihood:** Certain (3) -- no mechanism verifies JSON Schema structural validity
- **Reversibility:** Easy (1) -- add one test file
- **Sources:** Quality (BLOCK-1)
- **Resolution:** Add `tests/unit/manifest/test_schemas.py` to T-3.1's "Produces" with parameterized `jsonschema.Draft7Validator.check_schema()` tests.

### B-11: T-6.4 regression baseline comparison semantics unspecified (Priority: 9)
- **Severity:** High (3) -- suppression regression (count-down) may slip through undetected
- **Likelihood:** Likely (2) -- design explicitly requires distinguishing count-up from count-down
- **Reversibility:** Difficult (2) -- wrong baseline comparison logic in CI must be rearchitected
- **Sources:** Quality (BLOCK-3)
- **Resolution:** Add to T-6.4's "Done when": "CI comparison distinguishes finding-count decrease (suppression regression, requires human sign-off) from finding-count increase (new findings)."

### B-12: T-4.6 taint precedence boundary condition unspecified (Priority: 8)
- **Severity:** High (3) -- wrong precedence silently corrupts all severity calculations
- **Likelihood:** Likely (2) -- the three-source priority chain is subtle
- **Reversibility:** Easy (1) -- add one test
- **Sources:** Systems, Leverage
- **Resolution:** Add to T-4.6's "Done when": "Test that decorator taint takes precedence over conflicting manifest `module_tiers` default for the same function."

---

## 4. Deduplicated List of New Tasks or Task Modifications

### New Tasks

| ID | Title | Rationale | Sources |
|----|-------|-----------|---------|
| NEW-1 | T-0.3: Initial CODEOWNERS + CI Pipeline | CODEOWNERS-protected files (`wardline.yaml`, baselines, corpus) are committed 36 tasks before protection exists. CI pipeline (ruff, mypy, pytest unit) should run from task 1, not task 37. | Security (F-1, F-10) |
| NEW-2 | T-4.3a/b split or integration checkpoint | Add lightweight integration test after first rule: run `ScanEngine` on a fixture file, validate SARIF output. Catches interface mismatches 10+ tasks before T-5.2. | Systems, Leverage, Architecture |
| NEW-3 | T-6.2 split: draft + verification | Split T-6.2 into "TN draft structure" (depends T-6.1) and "TN verification" (depends rules + T-5.4). Current formal dependency allows unverified specimens. | Systems, Architecture, Leverage |

### Task Modifications

| Task | Modification | Sources |
|------|-------------|---------|
| T-0.1 | Add note: CI grep for `yaml.load(` must exclude `.venv/` and handle `Loader=SafeLoader` on same line | Python |
| T-1.2 | Add implementation note: `object.__setattr__` pattern in `__post_init__` for frozen dataclass + `MappingProxyType`. Cross-reference to T-4.1 which uses identical pattern. | Python |
| T-1.3 | Add to "Done when": "Idempotency tested: `join(a, a) == a` for all taint states" | Reality (W-1) |
| T-1.8 | Add to "Produces": validate registry `attrs` dict contract pattern (not just name lookup). Clarify SARIF schema: either vendor it in T-1.8 or validate against locally downloaded copy. | Leverage, Quality (WARN-5) |
| T-2.1 | Add to "Done when": "Severed `__wrapped__` chain logs at WARNING level" | Quality (WARN-2) |
| T-2.3 | Consider merging into T-2.2 (one-decorator task below PR overhead threshold) | Architecture (R4) |
| T-3.2 | Add note: "Use `tomllib` from stdlib (Python 3.11+). Do not use `tomli` or `toml`." | Python |
| T-3.3 | Add to "Done when": exit code binding for alias bomb and 1MB limit errors; `$id` mismatch message content test | Quality (WARN-4), Reality (W-5) |
| T-3.7 | Add to "Done when": "Agent-originated policy change detection fires" (currently in Produces but not gated). Add synthetic baseline fixture to Produces. | Reality (W-12), Architecture (R5) |
| T-4.1 | Add `WardlineAnnotation` dataclass to "Produces" -- currently undefined but consumed by T-4.4. Add implementation note for `object.__setattr__` pattern (same as T-1.2). | Architecture (R3), Python |
| T-4.2 | Add to "Done when": "TypeError raised at subclass definition time by `__init_subclass__`, not by `@typing.final` (which is static-only)" | Python |
| T-4.4 | Move `TYPE_CHECKING` guard handling from T-4.5 into T-4.4 (must skip `if TYPE_CHECKING:` imports to avoid false positives in core tests) | Python |
| T-4.7--T-4.11 | Establish shared test fixture pattern in `tests/unit/scanner/conftest.py`. Give each rule its own test file (`test_py_wl_001.py` through `test_py_wl_005.py`) to enable actual parallel execution. | Systems, Python |
| T-4.13 | Add to "Done when": result-level property bag assertions (`wardline.rule`, `wardline.taintState`, `wardline.severity`, `wardline.exceptionability`, `wardline.analysisLevel`). Add T-1.1 as explicit dependency (enum serialization in `json.dumps`). | Quality (WARN-1), Python |
| T-5.1 | Add to "Done when": `--verbose` and `--debug` produce structured logging to stderr | Reality (C-13) |
| T-5.2 | Add to "Done when": `--max-unknown-raw-percent` ceiling enforcement test; CLI flags override `wardline.toml` test. Add runtime registry sync check or reference T-4.3. Add GOVERNANCE WARNING for disabled rules (THREAT-009). | Reality (W-F), Security (F-6, F-8) |
| T-5.4 | Add to "Done when": output says "Lite bootstrap: N specimens" NOT "Wardline-Core corpus conformant" | Quality (WARN-3) |
| T-6.3 | Add T-5.4 to "Depends on" (specimens must be verified against running scanner, not just authored) | Python |
| T-6.4 | Split into T-6.4a (scan passes, manifest + toml, coverage floor) and T-6.4b (baselines, integration tests, CI, CODEOWNERS). Current task is multi-session work mislabeled as single-session. Replace "All of Phase 4" with explicit task list. | Architecture, Systems, Quality |

---

## 5. Top 3 Highest-Leverage Interventions

Combining the Leverage analyst's Meadows hierarchy analysis with the structural findings from all reviewers:

### Intervention 1: Harden T-1.2 (Registry) and enforce freeze via T-1.8 dependency

**Meadows Level:** 5 (Rules) -- the registry IS the rule that governs how decorator library and scanner self-organize.

**Why this is highest leverage:** T-1.2 has 25+ transitive dependents. A wrong `attrs` contract silently corrupts both parallel development streams (Phase 2 decorators, Phase 4 scanner). The current plan allows T-2.1 to start before T-1.8 validates the registry, creating a window where parallel work builds against an unproven contract. Five reviewers identified consequences of this gap.

**Concrete actions:**
1. Add dependency edge `T-1.8 --> T-2.1` (and `T-1.8 --> T-4.4`)
2. Extend T-1.8 to validate the registry `attrs` dict contract pattern (not just name lookup)
3. Add implementation note to T-1.2 for the `object.__setattr__` / `MappingProxyType` pattern
4. Add `validate_entry()` classmethod consideration to T-1.2

### Intervention 2: Add intermediate integration checkpoint between Phase 4 and Phase 5

**Meadows Level:** 9 (Delays) -- shortens the 17-task feedback delay between first rule implementation and self-hosting validation.

**Why this is second highest leverage:** Three reviewers independently identified the integration cliff at T-5.2. Unit tests for T-4.6 (taint), T-4.7--T-4.11 (rules), and T-4.13 (SARIF) all use hand-constructed fixtures. The first time real manifests, real discovery, and real taint assignment flow through the pipeline is T-5.2. Any impedance mismatch between subsystems surfaces there -- 10+ tasks after the components were built. A lightweight checkpoint (run `ScanEngine` on one fixture file, validate SARIF) after the first rule catches mismatches early.

**Concrete actions:**
1. Add integration checkpoint task after T-4.7 (or as T-4.3 acceptance criterion extension)
2. Run engine with one rule on a small fixture, validate SARIF structure
3. This also addresses Architecture's concern that T-4.3 is oversized

### Intervention 3: Harden T-4.6 (Taint Assignment) with exhaustive priority-chain testing

**Meadows Level:** 6 (Information Flows) -- determines what the scanner can see. Wrong taint = wrong severity = wrong enforcement = silent failure.

**Why this is third highest leverage:** T-4.6 has the most dangerous silent failure mode in the plan. If taint assignment defaults to `UNKNOWN_RAW` too eagerly or gets the three-source priority wrong, the scanner produces findings at incorrect severity with no crash and no error. Two reviewers (Systems, Leverage) independently identified the missing precedence boundary test. The Leverage analyst rated this the most dangerous silent corruption path.

**Concrete actions:**
1. Add explicit precedence test to T-4.6 "Done when": decorator > module_tiers > UNKNOWN_RAW
2. Add "decorator present but unresolved" test (should be UNKNOWN_RAW, not module default)
3. Add async function taint assignment test
4. Consider property-based test for priority chain

---

## 6. Concrete Action List

### (a) Missing Dependency Edges to Add

| # | From | To | Mermaid Edge | Source |
|---|------|----|-------------|--------|
| 1 | T-3.3 | T-5.4 | `T33 --> T54` | Reality, Python, Security, Architecture, Quality |
| 2 | T-3.3 | T-4.3 | `T33 --> T43` | Reality, Systems |
| 3 | T-3.4 | T-4.3 | `T34 --> T43` | Reality, Systems |
| 4 | T-1.8 | T-2.1 | `T18 --> T21` | Systems, Leverage, Python |
| 5 | T-3.5 | T-5.3 | `T35 --> T53` | Reality |
| 6 | T-3.3 | T-5.5 | `T33 --> T55` | Architecture |
| 7 | T-1.7 | T-4.12 | `T17 --> T412` | Reality, Architecture, Python |
| 8 | T-6.2 | T-6.4 | `T62 --> T64` | Architecture |
| 9 | T-1.2 | T-3.6 | `T12 --> T36` | Reality |
| 10 | T-3.2 | T-3.6 | `T32 --> T36` | Architecture (Mermaid-only fix; text already correct) |
| 11 | T-1.1 | T-4.13 | `T11 --> T413` | Python |
| 12 | T-5.4 | T-6.3 | `T54 --> T63` | Python |

### (b) Missing Tasks to Create

| # | Task | Depends On | Produces | Done When |
|---|------|-----------|----------|-----------|
| 1 | T-0.3: Initial CODEOWNERS + CI | T-0.1 | `.github/CODEOWNERS` protecting `wardline.yaml`, `wardline.toml`, `corpus/`; CI pipeline with `ruff check`, `mypy`, `pytest -m "not integration"` | CODEOWNERS file exists; CI pipeline runs on push |
| 2 | Integration checkpoint (T-4.3 extension or new T-4.3b) | T-4.3, T-4.7 (first rule) | Run `ScanEngine` on fixture file with one rule; validate SARIF structure | SARIF validates against schema; finding has correct severity and property bags |
| 3 | T-6.2a: TN Draft Structure | T-6.1 | Directory structure, specimen templates, draft TN fragments | Templates valid against corpus specimen schema |
| 4 | T-6.2b: TN Verification | T-6.2a, T-4.7--T-4.11, T-5.4 | Verified TN + KFN specimens with computed hashes | `wardline corpus verify` passes; all TNs confirmed silent |

### (c) "Done When" Criteria to Strengthen

| # | Task | Add to "Done When" | Source |
|---|------|--------------------|--------|
| 1 | T-1.3 | "Idempotency tested: `join(a, a) == a` for all taint states" | Reality |
| 2 | T-2.1 | "Severed `__wrapped__` chain logs at WARNING level" | Quality |
| 3 | T-3.3 | "Alias bomb and 1MB file limit produce exit code 2. `$id` version mismatch structured error includes specific message format per design WP-3c." | Quality, Reality |
| 4 | T-3.7 | "Agent-originated policy change detection fires correctly" | Reality |
| 5 | T-4.2 | "TypeError raised at subclass definition time by `__init_subclass__`, confirmed not from `@typing.final`" | Python |
| 6 | T-4.6 | "Decorator taint takes precedence over conflicting manifest module_tiers default for same function" | Systems, Leverage |
| 7 | T-4.13 | "Result-level property bags present: `wardline.rule`, `wardline.taintState`, `wardline.severity`, `wardline.exceptionability`, `wardline.analysisLevel`. StrEnum/IntEnum members serialize correctly via `json.dumps`." | Quality, Python |
| 8 | T-5.1 | "`--verbose` and `--debug` produce structured logging to stderr" | Reality |
| 9 | T-5.2 | "`--max-unknown-raw-percent` ceiling enforced (exit 1 when exceeded). CLI flags override `wardline.toml` values." | Reality |
| 10 | T-5.4 | "Output says 'Lite bootstrap: N specimens' not 'Wardline-Core corpus conformant'" | Quality |
| 11 | T-6.4 | "CI comparison distinguishes finding-count decrease (suppression regression, human sign-off required) from finding-count increase. Replace 'All of Phase 4' with explicit task list in Depends on." | Quality |
| 12 | T-4.12 | "Strict-mode exit code integration tested (renamed attribute produces non-zero exit code)" | Reality |
| 13 | T-4.13 | "`manifestHash` key-order-independence tested (different YAML key order produces same hash)" | Reality |
| 14 | T-5.5 | "Explain output tested for decorated function, undeclared module function, and unresolved decorator" (add test file path) | Quality |

### (d) Task Sizing Changes

| Task | Current Size | Recommended Change | Source |
|------|-------------|-------------------|--------|
| T-6.4 | Oversized (multi-session) | Split into T-6.4a (scan passes, manifest, toml, coverage) and T-6.4b (baselines, integration tests, CI, CODEOWNERS) | Architecture, Systems |
| T-2.3 | Undersized (below PR overhead) | Merge into T-2.2 or justify separation | Architecture |
| T-4.8 + T-4.9 | Undersized individually | Consider combining into single task | Architecture |
| T-3.3 | Borderline oversized | Consider splitting into T-3.3a (loader + schema validation) and T-3.3b (alias bomb + coercion edge cases) | Architecture |
| T-4.7--T-4.11 | Correctly sized individually but share test file | Give each rule its own test file to enable actual parallelism | Systems, Python |

---

## 7. Warnings (Non-Blocking)

| ID | Issue | Source | Recommendation |
|----|-------|--------|---------------|
| W-01 | T-1.5 and T-1.6 are dead-end tasks (no downstream consumer in scanner/CLI path) | Architecture | Mark as "runtime library deliverables; not required for self-hosting gate" |
| W-02 | T-3.5 (Overlay Merge) has no downstream dependency | Architecture | Mark as "post-MVP; does not gate Phase 4 or T-6.4" |
| W-03 | T-1.3 and T-1.2 share write target `taints.py` -- cannot safely parallelize across agents | Systems | Sequence T-1.3 before T-1.2, or flag file-level merge coordination |
| W-04 | `explain_cmd.py` not in design source layout | Reality | Update design layout or rename to match existing convention |
| W-05 | `wardline.toml` not created until T-6.4 but validated at T-5.2 | Reality | T-5.2 tests need ad-hoc fixture; document this |
| W-06 | T-0.2 has no enforced "done when" gate but T-6.4 depends on its quality | Systems, Leverage | Add tier rationale review as a gate |
| W-07 | `WardlineAnnotation` type undefined in any preceding task | Architecture | Define in T-4.1 Produces section |
| W-08 | Alias limiter threshold hardcoded at 1000; design says "configurable" but no test verifies configurability | Quality | Clarify: constructor param, module constant, or ScannerConfig field? |
| W-09 | THREAT-009 (rule disablement governance signal) not implemented | Security | Add GOVERNANCE WARNING for disabled rules to T-5.2 |
| W-10 | Scanner deployable without corpus validation; uncalibrated state invisible | Security | Add GOVERNANCE WARNING to `wardline scan` when no corpus detected |
| W-11 | `max_exception_duration_days` date arithmetic dropped from all tasks | Reality, Quality | Assign to T-3.3 or create explicit task |
| W-12 | T-1.8 tracer bullet "Done when" references vendored SARIF schema, but vendoring is T-4.13 | Quality | Clarify: spike vendors schema locally, or validates against downloaded copy |

---

## 8. Reviewer Summaries

| Reviewer | Focus | Blocking | Warnings | Key Contribution |
|----------|-------|----------|----------|-----------------|
| Reality | Completeness, dependency accuracy, naming | 6 | 7 | Most thorough dependency edge audit (7 missing edges); caught 8 dropped requirements |
| Architecture | Blast radius, decomposition, parallelism, sizing | 4 | 6 | Identified orphan tasks (T-1.5, T-1.6, T-3.5), Mermaid graph discrepancies, T-6.4 oversizing |
| Quality | Testing, observability, edge cases, security | 3 | 5 | Found T-3.1 has no test mechanism; SARIF result-level property bags missing from criteria |
| Systems | Dependencies, feedback loops, timing, failure modes | 3 | 5 | Critical path analysis; hidden temporal dependencies; shared test file contention |
| Python | Language-specific patterns, implementation risks | 4 | 5 | `object.__setattr__` pattern risk; `TYPE_CHECKING` guard placement; `json.dumps` enum crash |
| Security | Threat model, task ordering security windows | 3 | 3 | CODEOWNERS temporal gap; runtime registry sync check missing; THREAT-009 unimplemented |
| Leverage | Meadows hierarchy, bottleneck mapping, feedback delays | 0 | 3 | Identified T-1.2, T-4.6, T-1.4 as highest-leverage tasks; 17-task feedback delay quantified |

---

## 9. Conflicts Resolved

| Issue | Conflicting Views | Resolution |
|-------|------------------|------------|
| T-2.1 dependency on T-1.7 | Python says T-2.1 needs T-1.7 for `__wrapped__` tests; Reality says T-4.12 needs T-1.7. Both are valid. | Add T-1.7 to T-4.12 (not T-2.1). Move `__wrapped__` chain traversal tests to T-4.12 where they belong per design. T-2.1 tests the factory's `__wrapped__` chain attribute survival (which does not require WardlineBase), while T-4.12 tests the runtime traversal path (which does). |
| T-3.5 criticality | Architecture says T-3.5 is an orphan with no downstream consumer; Reality says T-5.3 needs it for baseline update. | Reality is correct: T-5.3's `wardline manifest baseline update` writes resolved manifest, which requires overlay merge. Add `T-3.5 --> T-5.3`. T-3.5 is NOT orphaned -- it was just missing its consumer edge. |
| T-3.6 scope | Systems questions whether T-3.6 is manifest-only or cross-references code; Reality says it needs T-1.2 for decorator registry. | Both are partially right. T-3.6 at MVP should be manifest-only (checking manifest internal consistency), with T-1.2 dependency for knowing what decorator names to look for. Full code cross-referencing (via T-4.4) is post-MVP. Add T-1.2 dependency; document scope as manifest-level only. |
| T-6.4 sizing | Architecture recommends split; Systems notes it is the highest integration surface. | Agree with split into T-6.4a (scan + manifest + coverage) and T-6.4b (baselines + CI + CODEOWNERS). The single-session claim is misleading for this task. |

---

## 10. Next Steps

**Status: APPROVE WITH CONDITIONS**

Before execution begins:

1. Apply the 12 missing dependency edges from Section 6(a) to both the textual "Depends on" fields and the Mermaid graph
2. Create the 4 new/split tasks from Section 6(b)
3. Strengthen the 14 "Done when" criteria from Section 6(c)
4. Apply the task sizing changes from Section 6(d)

After these conditions are met, run `/review-plan` again to verify the updated execution sequence.

---

*Synthesized from 7 independent reviewer reports on 2026-03-22.*
