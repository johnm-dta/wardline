# Execution Sequence Re-Review Synthesis

**Plan:** `docs/2026-03-22-execution-sequence.md`
**Previous synthesis:** `docs/reviews/2026-03-22-execution-sequence-synthesis.md`
**Review date:** 2026-03-22
**Review type:** Re-review -- verifying previous fixes and identifying new issues
**Reviewers:** Architecture, Reality, Quality, Systems, Python, Security, Leverage
**Verdict:** APPROVE WITH CONDITIONS

---

## 1. Verification Summary

All 7 reviewers independently verified the fixes from the previous synthesis. The results are unanimous.

### 1.1 Dependency Edges (12 required)

All 12 missing dependency edges from Section 6(a) of the previous synthesis landed correctly in BOTH the textual "Depends on" fields AND the Mermaid graph. Every reviewer who checked edges confirmed this.

| # | Edge | Verified By | Status |
|---|------|-------------|--------|
| 1 | T-3.3 to T-5.4 | Architecture, Reality, Quality, Leverage | FIXED |
| 2 | T-3.3 to T-4.3 | Architecture, Reality, Quality, Leverage | FIXED |
| 3 | T-3.4 to T-4.3 | Architecture, Reality, Quality, Leverage | FIXED |
| 4 | T-1.8 to T-2.1 | Architecture, Reality, Systems, Quality, Leverage | FIXED |
| 5 | T-3.5 to T-5.3 | Architecture, Reality, Quality, Leverage | FIXED |
| 6 | T-3.3 to T-5.5 | Architecture, Reality, Quality, Leverage | FIXED |
| 7 | T-1.7 to T-4.12 | Architecture, Reality, Quality, Leverage | FIXED |
| 8 | T-6.2 to T-6.4 | Architecture, Reality, Quality, Leverage | FIXED (evolved to T-6.2b to T-6.4a) |
| 9 | T-1.2 to T-3.6 | Architecture, Reality, Quality, Leverage | FIXED |
| 10 | T-3.2 to T-3.6 | Architecture, Reality, Quality, Leverage | FIXED |
| 11 | T-1.1 to T-4.13 | Architecture, Reality, Quality, Python, Leverage | FIXED |
| 12 | T-5.4 to T-6.3 | Architecture, Reality, Quality, Python, Leverage | FIXED |

### 1.2 New Tasks (4 required)

All 4 new/split tasks from Section 6(b) exist and are properly integrated.

| Task | Verified By | Status |
|------|-------------|--------|
| T-0.3: Initial CODEOWNERS + CI | Architecture, Reality, Quality, Security, Leverage | FIXED |
| T-4.INT: Integration Checkpoint | Architecture, Reality, Quality, Systems, Leverage | FIXED (with new issues -- see Section 3) |
| T-6.2a/T-6.2b split | Architecture, Reality, Quality, Leverage | FIXED |
| T-6.4a/T-6.4b split | Architecture, Reality, Quality, Systems, Leverage | FIXED |

### 1.3 "Done When" Criteria (14 required)

All 14 criteria from Section 6(c) landed. Two are partially placed (in "Produces" but not in "Done when").

| # | Task | Verified By | Status |
|---|------|-------------|--------|
| 1-10, 12-13 | Various | Reality, Quality | FULLY LANDED |
| 11 | T-6.4b (CI regression semantics) | Reality, Quality | PARTIAL -- in Produces but not in Done When |
| 14 | T-5.5 (explain test categories) | Reality | PARTIAL -- test file in Produces, Done When lacks test file reference |

### 1.4 Sizing Changes

| Change | Status | Verified By |
|--------|--------|-------------|
| T-6.4 split into T-6.4a + T-6.4b | APPLIED | Architecture, Systems |
| T-2.3 merge consideration | Advisory note applied, kept separate | Architecture |
| T-4.8 + T-4.9 combination | Kept separate with own test files | Architecture |
| T-3.3 borderline oversized | Not split (advisory "consider") | Architecture |
| Per-rule test files (T-4.7-T-4.11) | APPLIED -- each rule has own test file | Python, Systems |

### 1.5 Previous Leverage Interventions

| Intervention | Status | Verified By |
|-------------|--------|-------------|
| T-1.8 to T-2.1 registry freeze edge | APPLIED | Systems, Leverage |
| T-4.INT integration checkpoint | APPLIED | Systems, Leverage |
| T-4.6 taint precedence test | APPLIED | Systems, Leverage |

**Feedback delay reduction:** The 17-task integration gap identified in the previous review has been compressed to approximately 1 hop (T-4.7 to T-4.INT). Leverage and Systems reviewers both confirmed this improvement.

---

## 2. Cross-Reviewer Convergence

Issues flagged independently by 2+ reviewers carry the highest confidence.

### Convergence I: T-4.INT is a dead-end node (5 reviewers)

**Flagged by:** Architecture (N-1), Systems (NC-1, B-NEW-1), Quality (implicit -- no downstream dep noted), Reality (NEW-4), Leverage (New Leverage Point B)

T-4.INT has incoming dependency edges but NO outgoing edges. No downstream task depends on T-4.INT. The integration checkpoint was added to catch interface mismatches before Phase 5, but T-5.2 can proceed without T-4.INT ever having run. An automated scheduler reading only the graph will never be blocked by T-4.INT failure.

The Leverage reviewer correctly noted that this is LOW risk for gating T-4.8-T-4.11 (rules share a uniform interface), but the Architecture and Systems reviewers correctly identified that the PRIMARY purpose -- gating T-5.2 -- is not achieved.

### Convergence II: `yaml.safe_load()` API hallucination (3 reviewers)

**Flagged by:** Python (Finding H -- Critical), Reality (H-01 -- Blocking), Quality (implicit in test audit)

`yaml.safe_load()` does not accept a `Loader` parameter. T-3.3 says "yaml.safe_load() via custom loader" which is a non-existent API. The correct call is `yaml.load(stream, Loader=WardlineSafeLoader)`. This directly conflicts with the CI grep check (T-0.1, T-0.3) which fails on `yaml.load(` without `Loader=SafeLoader` on the same line. The check needs to accept `WardlineSafeLoader` as a safe pattern.

### Convergence III: `agent_originated: null` governance warning still missing (3 reviewers)

**Flagged by:** Security (THREAT-001 -- Critical), Quality (NQ-12 -- Blocking), Reality (W-09 carry-over)

This was Convergence F in the previous synthesis, flagged by 3 reviewers then. The fix was not applied. The `agent_originated` field is in the exception schema (nullable), but no task emits a GOVERNANCE WARNING when scanning entries with `agent_originated: null`. T-3.7 handles agent-originated *commit detection* (a different control). This is the most-flagged unresolved item across both review rounds.

### Convergence IV: `max_exception_duration_days` date arithmetic still missing (3 reviewers)

**Flagged by:** Security (THREAT-002 -- Critical), Quality (NQ-11 -- Blocking), Reality (W-11 carry-over)

This was W-11 in the previous synthesis. Still not resolved. The schema defines `max_exception_duration_days` but no task performs the cross-field date arithmetic (`expires - grant_date > max_exception_duration_days`). Exceptions with `expires: 2099-12-31` are silently accepted.

### Convergence V: T-5.1 should depend on T-0.1 (3 reviewers)

**Flagged by:** Systems (NC-4), Leverage (New Leverage Point D), Architecture (implicit in critical path analysis)

T-5.1 says "Depends on: Nothing" but must write into `src/wardline/cli/` created by T-0.1. In practice T-0.1 will be done long before Phase 5, but the declaration is technically incorrect and could mislead an agent on a clean checkout.

### Convergence VI: T-0.3 is not threaded into the dependency graph (2 reviewers)

**Flagged by:** Architecture (N-6), Systems (implicit in critical path)

T-0.3 produces the CI pipeline but no Phase 1+ task lists T-0.3 as a dependency. Agents executing Phase 1 can start without CI being active. The CODEOWNERS protection for `wardline.yaml` would not exist during Phase 1 work.

### Convergence VII: T-6.4a should depend on T-4.12 (2 reviewers)

**Flagged by:** Architecture (N-5), Systems (NC-3)

T-4.12 (Registry Sync Tests) is not listed as a dependency of T-6.4a. The self-hosting gate should not close without the bidirectional registry sync tests having passed.

### Convergence VIII: `taints.py` write conflict between T-1.2 and T-1.3 still unenforced (2 reviewers)

**Flagged by:** Systems (W-NEW-3, Part 4), Reality (implicit in Mermaid audit)

The previous review (W-03) flagged that T-1.2 and T-1.3 share write target `taints.py` and cannot be safely parallelized. The resolution was to add a warning comment. The warning exists but no Mermaid edge enforces the sequencing. An automated scheduler will parallelize them.

---

## 3. Consolidated Blocking Issues

Scored using Priority = Severity x Likelihood x Reversibility. Sorted descending.

### B-01: T-4.INT has no downstream dependent (Priority: 12)

- **Severity:** Critical (4) -- the entire rationale for T-4.INT is defeated
- **Likelihood:** Certain (3) -- graph topology is deterministic
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Architecture (N-1), Systems (NC-1), Quality, Reality, Leverage
- **Resolution:** Add T-4.INT to T-5.2's "Depends on" list. Add `T4INT --> T52` to Mermaid graph. This converts the checkpoint from a passive probe into an enforced gate.

### B-02: `yaml.safe_load()` API hallucination in T-3.3 (Priority: 12)

- **Severity:** Critical (4) -- implementation will either break the loader or trigger CI false positive
- **Likelihood:** Certain (3) -- `yaml.safe_load()` provably takes only one argument
- **Reversibility:** Easy (1) -- text correction
- **Sources:** Python (Finding H), Reality (H-01)
- **Resolution:** Replace T-3.3 text "yaml.safe_load() via custom loader" with "yaml.load(stream, Loader=WardlineSafeLoader)". Update T-0.1 and T-0.3 CI grep check to "fails on `yaml.load(` without `Loader=` on the same line" (accepting any SafeLoader subclass, not just literal `SafeLoader`).

### B-03: `agent_originated: null` governance warning has no implementing task (Priority: 9)

- **Severity:** Critical (4) -- agent exception laundering attack path is open
- **Likelihood:** Likely (2) -- requires only omitting a field, not active exploitation
- **Reversibility:** Easy (1) -- add to T-3.7 or T-5.2 Done When
- **Sources:** Security (THREAT-001), Quality (NQ-12), Reality (W-09 carry-over)
- **Resolution:** Add to T-3.7 "Done when": "GOVERNANCE WARNING emitted for each exception entry with `agent_originated: null`. Test fixture: three entries (true, false, null) -- WARNING fires only for null."

### B-04: `max_exception_duration_days` date arithmetic has no implementing task (Priority: 9)

- **Severity:** Critical (4) -- permanent exceptions bypass governance renewal model
- **Likelihood:** Likely (2) -- far-future expiry is the simplest bypass
- **Reversibility:** Easy (1) -- add to T-3.3 or T-3.7
- **Sources:** Security (THREAT-002), Quality (NQ-11), Reality (W-11 carry-over)
- **Resolution:** Add to T-3.7 "Done when": "Expired exception detection: exception past `max_exception_duration_days` from grant date fires GOVERNANCE WARNING. Far-future expiry rejected. Clock injection mechanism documented for test isolation."

### B-05: T-4.INT missing T-4.6 dependency (Priority: 9)

- **Severity:** High (3) -- checkpoint cannot validate taint assignment without the taint assignment module
- **Likelihood:** Certain (3) -- "taint assignment from manifest works" is explicit in Done When
- **Reversibility:** Easy (1) -- add one edge
- **Sources:** Quality (NQ-13)
- **Resolution:** Add T-4.6 to T-4.INT "Depends on". Add `T46 --> T4INT` to Mermaid graph.

---

## 4. Consolidated Warnings

Grouped by theme.

### Theme A: Missing or weak test specifications

| ID | Task | Issue | Source |
|----|------|-------|--------|
| W-01 | T-4.1 | No named test file -- collision risk with T-4.2 | Quality (NQ-2) |
| W-02 | T-4.INT | No test file path or pytest command specified | Quality (NQ-3) |
| W-03 | T-5.2 | Test file not named; registry sync failure and flag override not test-gated | Quality (NQ-4) |
| W-04 | T-5.3 | Test file not named; Done When is "Both commands work" (not machine-verifiable) | Quality (NQ-5) |
| W-05 | T-6.4a | No test file in Produces; 80% coverage has no measurement mechanism | Quality (NQ-6) |
| W-06 | T-6.3 | Done When is subjective; no `wardline corpus verify` invocation required | Quality (NQ-18) |
| W-07 | T-5.4 | No integration test against real specimen; output format check is mock-only | Quality (NQ-19) |

### Theme B: Exit code and observability gaps

| ID | Task | Issue | Source |
|----|------|-------|--------|
| W-08 | T-5.2 | Registry sync failure exit code unspecified (exit 1? 2? 3?) | Quality (NQ-8) |
| W-09 | T-3.4 | Symlink cycle detection observable output not specified | Quality (NQ-9) |
| W-10 | T-3.4 | Undeclared overlay GOVERNANCE ERROR exit code unspecified | Quality (NQ-10) |
| W-11 | T-3.3 | Schema validation failure exit code not tested end-to-end through CLI | Quality (NQ-7) |

### Theme C: Dependency graph and Mermaid consistency

| ID | Task | Issue | Source |
|----|------|-------|--------|
| W-12 | T-5.1 | Declares no dependencies but structurally requires T-0.1 | Systems, Leverage |
| W-13 | T-0.3 | Not threaded into dependency graph; Phase 1 can start without CI | Architecture (N-6) |
| W-14 | T-6.4a | Missing T-4.12 dependency; self-hosting gate can close without registry sync tests | Architecture (N-5), Systems (NC-3) |
| W-15 | T-1.2/T-1.3 | Shared write target `taints.py` -- warning only, no Mermaid edge | Systems (W-NEW-3) |
| W-16 | T-4.1 | Mermaid missing `T11 --> T41` -- textual dep exists, graph edge absent | Reality (D-02) |
| W-17 | T-5.4 | No dependency on T-4.3 despite invoking ScanEngine at runtime | Systems (W-NEW-1) |
| W-18 | T-4.INT | May need T-4.13 for SARIF schema validation (or narrow Done When to dict-level) | Reality (D-01) |

### Theme D: Python implementation guidance

| ID | Task | Issue | Source |
|----|------|-------|--------|
| W-19 | T-4.4 | `TYPE_CHECKING` detection misses `typing.TYPE_CHECKING` qualified form | Python (Finding A) |
| W-20 | T-3.3 | `compose_node` override needs to specify AliasEvent branch and exception type | Python (Finding B) |
| W-21 | T-2.1 | `_wardline_groups` set aliasing risk during decorator stacking via `functools.wraps` | Python (Finding G) |
| W-22 | T-3.2 | `tomllib.load()` requires binary file mode (`rb`) -- not documented | Python (Finding F) |
| W-23 | T-4.4 | Parent-node tracking for `TYPE_CHECKING` not native to `ast.NodeVisitor` | Python (Finding I) |
| W-24 | T-1.5 | `Tier1 = Annotated[T, TierMarker(1)]` TypeVar form is ambiguous | Python (Finding C) |

### Theme E: Carry-over and design decisions

| ID | Task | Issue | Source |
|----|------|-------|--------|
| W-25 | T-4.7/T-4.13 | `PY-WL-001-UNVERIFIED-DEFAULT` type incompatible with `RuleId` StrEnum -- design decision needed | Python (Finding E) |
| W-26 | T-3.3 | Alias limiter threshold configurability unresolved (hardcoded vs `ScannerConfig` field) | Quality (NQ-16), Reality (W-08 carry-over) |
| W-27 | T-5.2 | `wardline.toml` fixture location undocumented -- collision risk with T-6.4a | Systems (W-NEW-5) |
| W-28 | T-6.4b | Done When missing regression semantics (count-decrease vs count-increase) | Reality (PC-01), Quality |
| W-29 | T-5.5 | Done When missing test file reference | Reality (PC-02) |
| W-30 | Various | Design source layout is materially stale relative to execution plan | Reality (WARN-5) |

### Theme F: Security

| ID | Task | Issue | Source |
|----|------|-------|--------|
| W-31 | T-0.3 | CODEOWNERS syntax not validated -- silent failure mode | Quality (NQ-1, NQ-17) |
| W-32 | T-3.5 | Overlay severity narrowing semantics ambiguous (narrowing severity = weakening enforcement?) | Security (THREAT-004) |
| W-33 | T-0.3 | Overlay files outside CODEOWNERS coverage -- `**/wardline.overlay.yaml` not protected | Security (THREAT-NEW-001) |
| W-34 | T-4.INT | Integration test pytest mark not specified -- may run in unit test suite | Quality (NQ-14) |
| W-35 | T-3.7 | First-scan behavior (no baseline) not in Done When | Quality (NQ-15) |

---

## 5. Conflicts Resolved

### Conflict 1: Should T-4.INT gate T-4.8-T-4.11 (remaining rules)?

- **Systems view:** T-4.INT has no outgoing edges, remaining rules proceed regardless.
- **Leverage view:** Do NOT add T-4.INT as dependency for T-4.8-T-4.11. Rules share a uniform interface. Serializing them through the checkpoint adds unnecessary sequencing without proportional risk reduction.
- **Architecture view:** T-4.INT should gate T-5.2, not individual rules.

**Resolution:** Add `T4INT --> T52` only. Do NOT gate T-4.8-T-4.11 on T-4.INT. The checkpoint validates the interface contract that all rules share; if it passes for PY-WL-001, the contract is validated for all five rules. The Leverage reviewer's assessment is correct -- this would be a Level 12 intervention with negative return.

### Conflict 2: T-4.INT SARIF validation -- does it need T-4.13?

- **Reality view:** T-4.INT "Done when" says "SARIF structure is valid" but T-4.13 (SARIF module + vendored schema) is not a dependency. Either add T-4.13 or narrow Done When.
- **Architecture view:** Not raised as a concern.

**Resolution:** Narrow T-4.INT "Done when" to specify dict-level key inspection, not schema validation. Adding T-4.13 would extend the critical path unnecessarily. The integration checkpoint should validate the engine's output structure (correct keys, property bags, severity), not the serialized JSON against the vendored SARIF schema. Full schema validation belongs in T-5.2.

### Conflict 3: T-0.3 -- should it gate Phase 1 tasks?

- **Architecture view:** Add T-0.3 to T-1.1's Depends on (`T03 --> T11`) so CI is active from first committed code.
- **Leverage view:** T-0.3 is the closest to diminishing returns. CODEOWNERS protecting `wardline.yaml` during Phase 0 (when it is still being designed) adds overhead. The CI pipeline portion has strong return.

**Resolution:** Add T-0.3 as a soft dependency of T-1.1 via a scheduling note rather than a hard graph edge. The CI pipeline value is high, but the CODEOWNERS protection is premature before `wardline.yaml` stabilizes. An agent starting T-1.1 should confirm T-0.3 is complete but should not be graph-blocked by it. Add a note to the graph header: "T-0.3 should complete before T-1.1 begins; scheduling preference, not hard dependency."

### Conflict 4: T-5.4 dependency on T-4.3 (ScanEngine)

- **Systems view:** T-5.4 (`wardline corpus verify`) must invoke the scanner to confirm true-negative specimens are silent, but T-4.3 is not a dependency. The runtime dependency is implicit.
- **Architecture/Leverage view:** Not raised. T-6.2b (which calls T-5.4) directly depends on T-4.7-T-4.11, so there is a transitive path.

**Resolution:** Add T-4.3 to T-5.4's "Depends on" and `T43 --> T54` to Mermaid. The transitive coverage via T-6.2b is insufficient because T-5.4 is an independent implementation task. An agent implementing T-5.4 needs the ScanEngine to exist to implement the verify command. Explicit is better than implicit.

---

## 6. Concrete Action List

### (a) Missing Dependency Edges to Add

| # | From | To | Mermaid Edge | Source | Priority |
|---|------|----|-------------|--------|----------|
| 1 | T-4.INT | T-5.2 | `T4INT --> T52` | Architecture, Systems, Quality, Reality, Leverage | BLOCKING |
| 2 | T-4.6 | T-4.INT | `T46 --> T4INT` | Quality | BLOCKING |
| 3 | T-4.3 | T-5.4 | `T43 --> T54` | Systems | WARNING |
| 4 | T-4.12 | T-6.4a | `T412 --> T64a` | Architecture, Systems | WARNING |
| 5 | T-1.3 | T-1.2 | `T13 --> T12` | Systems | WARNING |
| 6 | T-1.1 | T-4.1 | `T11 --> T41` | Reality | WARNING (Mermaid-only fix; text already correct) |
| 7 | T-0.1 | T-5.1 | `T01 --> T51` | Systems, Leverage | WARNING |

### (b) Missing Tasks or Task Modifications

No new tasks are required. The following task modifications address blocking issues:

| Task | Modification | Source |
|------|-------------|--------|
| T-3.3 | Replace "yaml.safe_load() via custom loader" with "yaml.load(stream, Loader=WardlineSafeLoader)". Add: "Raises `yaml.YAMLError` subclass when alias count exceeds threshold. Counter increments only on AliasEvent branch." | Python (H), Reality (H-01) |
| T-0.1, T-0.3 | CI grep check: change "fails on `yaml.load(` without `Loader=SafeLoader`" to "fails on `yaml.load(` without `Loader=` on the same line" (accept any SafeLoader subclass) | Python (H), Reality (H-01) |
| T-3.7 | Add `agent_originated: null` GOVERNANCE WARNING to Done When and Produces | Security, Quality |
| T-3.7 | Add `max_exception_duration_days` date arithmetic to Done When and Produces | Security, Quality |
| T-4.INT | Narrow Done When: "ScanEngine returns findings with correct keys, severity, taint state, and property bags" (remove implication of SARIF schema validation) | Reality (D-01) -- conflict resolved |

### (c) "Done When" Criteria to Strengthen

| # | Task | Add to "Done When" | Source |
|---|------|--------------------|--------|
| 1 | T-6.4b | "CI comparison distinguishes finding-count decrease (suppression regression, human sign-off) from finding-count increase" | Reality (PC-01), Quality |
| 2 | T-5.5 | "Verified by `tests/integration/test_explain.py`" | Reality (PC-02) |
| 3 | T-2.1 | "Stacking test verifies `_wardline_groups` accumulation does not mutate inner decorator's set (copy-on-accumulate)" | Python (G) |
| 4 | T-4.4 | "TYPE_CHECKING detection handles both `TYPE_CHECKING` (direct import) and `typing.TYPE_CHECKING` (qualified)" | Python (A) |
| 5 | T-3.2 | Add implementation note: "`tomllib.load()` requires `open(path, 'rb')` binary mode" | Python (F) |
| 6 | T-3.7 | "First-scan GOVERNANCE INFO emitted when baseline does not exist" | Quality (NQ-15) |
| 7 | T-3.4 | "Symlink cycle: logs WARNING with cycle path, returns None" | Quality (NQ-9) |
| 8 | T-4.4 | Add implementation note: parent-node tracking approach required (pre-pass line ranges or custom visitor with parent stack) | Python (I) |

### (d) Text Corrections

| # | Location | Current Text | Corrected Text |
|---|----------|-------------|----------------|
| 1 | T-3.3 Produces | "yaml.safe_load() via custom loader" | "yaml.load(stream, Loader=WardlineSafeLoader)" |
| 2 | T-0.1, T-0.3 | "fails on `yaml.load(` without `Loader=SafeLoader`" | "fails on `yaml.load(` without `Loader=` on the same line" |
| 3 | Graph header | (no edge for T-1.3 to T-1.2 sequencing) | Add note or edge: "T-1.3 must complete before T-1.2 begins (shared write target taints.py)" |

---

## 7. Bottleneck Shift Analysis

The Leverage reviewer performed detailed bottleneck analysis post-edit. Key findings:

| Task | Direct Dependents | Approx Transitive Dependents | Change from Previous |
|------|-------------------|------------------------------|---------------------|
| T-1.1 (Enums) | 7 | ~40 | Unchanged -- inherent root |
| T-1.2 (Registry) | 5 | ~30 | Unchanged |
| T-3.3 (YAML Loader) | 6 | ~20 | INCREASED -- gained 3 edges from previous fixes |
| T-1.8 (Tracer Bullet) | 2 | ~25 | INCREASED -- now gates both decorator and scanner streams |
| T-4.2 (RuleBase) | 6 | ~15 | Unchanged |

T-3.3 has become a new structural bottleneck due to the (correctly applied) dependency edges. The Leverage reviewer assessed this as MODERATE risk because the task scope is well-defined and the Done When criteria are now comprehensive. No intervention needed.

T-1.8 now gates both development streams (decorator via T-2.1, scanner via T-4.1). This is the intended effect of the registry freeze intervention. If T-1.8 is poorly scoped, it becomes a critical bottleneck. The Done When criteria bound it to 4 validation points, which mitigates the risk.

---

## 8. Design Decisions Required Before Execution

Two design decisions surfaced during this review that must be made before implementing agents begin:

### Decision 1: `Finding.rule_id` type

**Issue:** Pseudo-rule-IDs (`PY-WL-001-UNVERIFIED-DEFAULT`, `WARDLINE-UNRESOLVED-DECORATOR`, `TOOL-ERROR`, `GOVERNANCE-REGISTRY-MISMATCH-ALLOWED`) are not members of the `RuleId` StrEnum. If `Finding.rule_id` is typed as `RuleId`, these cannot be assigned to it.

**Options:**
- Option A: Extend `RuleId` to include all pseudo-rule-IDs as members. More type-safe, mypy-friendly.
- Option B: Type `Finding.rule_id` as `str | RuleId`. Simpler but loses type precision.

**Recommendation:** Option A. Add pseudo-rule constants to `RuleId` in T-1.1, before the enum is frozen and downstream code builds against it.

**Source:** Python (Finding E)

### Decision 2: Overlay severity narrowing semantics

**Issue:** The narrow-only invariant prevents tiers from relaxing. But severity narrowing (ERROR to WARNING) passes the narrow-only check while functionally weakening enforcement (CI no longer blocks). The design doc says overlays "cannot relax tiers, lower severity" but "lower severity" is ambiguous.

**Options:**
- Option A: Severity reduction through overlay IS a widening (rejected by narrow-only). More restrictive.
- Option B: Severity reduction through overlay IS a narrowing (allowed). Less restrictive.

**Recommendation:** Document the chosen interpretation in T-3.5 Done When. If severity narrowing is prohibited, add a test. If allowed, document as a design decision with rationale.

**Source:** Security (THREAT-004)

---

## 9. Reviewer Summaries

| Reviewer | Focus | Previous Fixes Verified | New Blocking | New Warnings | Key Contribution |
|----------|-------|------------------------|-------------|-------------|------------------|
| Architecture | Blast radius, sizing, critical path | All 12 edges, 4 tasks, sizing | 1 (T-4.INT dead end) | 3 | Found T-4.INT terminal node; T-0.3 not threaded into graph |
| Reality | Symbols, paths, API accuracy | All 12 edges, 4 tasks, 14 criteria | 1 (yaml.safe_load API) | 7 | Exhaustive Mermaid audit; caught `T11-->T41` gap |
| Quality | Testing, observability, edge cases | All 14 criteria, structural fixes | 3 (NQ-11, NQ-12, NQ-13) | 16 | Most thorough test coverage audit; caught carry-over gaps |
| Systems | Dependencies, feedback loops, timing | 3 interventions confirmed | 1 (T-4.INT dead end) | 5 | Critical path re-analysis; `taints.py` write conflict; parallelism audit |
| Python | Language patterns, API accuracy | All 8 Python findings | 1 (yaml.safe_load API) | 6 | `functools.wraps` set aliasing; `TYPE_CHECKING` qualified form |
| Security | Threats, attack trees, controls | 4 of 5 (V-5 not fixed) | 0 (elevates carry-overs) | 4 | STRIDE analysis; attack trees for 4 threats; overlay CODEOWNERS gap |
| Leverage | Meadows hierarchy, bottleneck shifts | All 3 interventions confirmed | 0 | 1 | Confirmed no new high-leverage (Level 6+) interventions needed |

---

## 10. Risk Matrix (Post-Fix)

After the blocking issues in this synthesis are resolved:

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| T-3.3 delay blocks 6 downstream tasks | Low | High | Well-scoped Done When criteria |
| T-1.8 delay blocks both development streams | Low | Very High | Bounded scope (4 validation points) |
| T-6.4a wide fan-in delays self-hosting | Medium | Medium | T-4.INT checkpoint mitigates |
| Design source layout stale vs execution plan | Medium | Low | Note in execution plan marking it authoritative |
| Overlay severity narrowing semantic gap | Low | High | Design decision required (Section 8) |

---

## 11. Verdict

### APPROVE WITH CONDITIONS

The execution sequence has substantially improved since the first review. All 12 dependency edges, all 4 new tasks, all 14 Done When criteria, and all 3 leverage interventions from the previous synthesis were applied correctly. Every reviewer confirmed this independently.

Five blocking issues remain. All are straightforward fixes (text corrections, edge additions, Done When additions). None require architectural changes.

### Must Fix Before Execution (5 items)

1. **B-01:** Add `T4INT --> T52` to Mermaid and T-5.2 Depends on (wires the integration checkpoint into the critical path)
2. **B-02:** Fix `yaml.safe_load()` API hallucination in T-3.3; update CI grep check in T-0.1/T-0.3 to accept `Loader=` (any subclass)
3. **B-03:** Add `agent_originated: null` GOVERNANCE WARNING to T-3.7 Done When (carry-over from previous synthesis Convergence F)
4. **B-04:** Add `max_exception_duration_days` date arithmetic to T-3.7 Done When (carry-over from previous synthesis W-11)
5. **B-05:** Add `T46 --> T4INT` to Mermaid and T-4.INT Depends on (checkpoint cannot validate taint without taint module)

### Should Fix Before Execution (7 items)

1. Add `T43 --> T54` edge (T-5.4 needs ScanEngine)
2. Add `T412 --> T64a` edge (self-hosting gate needs registry sync tests)
3. Add `T13 --> T12` edge (enforce `taints.py` write ordering)
4. Add `T11 --> T41` Mermaid edge (text already correct, graph missing)
5. Add `T01 --> T51` edge (T-5.1 needs scaffolding)
6. Resolve `Finding.rule_id` type decision (Section 8, Decision 1)
7. Resolve overlay severity narrowing semantics (Section 8, Decision 2)

### Can Fix Incrementally

Warnings W-01 through W-35 are specificity gaps that implementing agents can address during task execution. They are documented in Section 4 for reference.

---

### Next Steps

Apply the 5 blocking fixes above. These are text edits, dependency edge additions, and Done When criteria -- no structural redesign required. After applying, the plan is ready for execution without further review.

---

*Synthesized from 7 independent reviewer reports on 2026-03-22. This is the second review round.*
