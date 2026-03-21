# Plan Review Synthesis: Wardline for Python Implementation Design

**Plan:** `/home/john/wardline/docs/2026-03-21-wardline-python-design.md`
**Reviewed:** 2026-03-22
**Reviewers:** Architecture, Quality, Test Suite, Systems, Python, Security, Reality
**Verdict:** APPROVE WITH CONDITIONS

---

## Executive Summary

Seven independent reviewers examined the Wardline for Python implementation plan across architecture, quality, test strategy, systems dynamics, Python engineering, security threats, and factual accuracy. The plan is notably thorough -- multiple reviewers called it the most detailed they have reviewed for a project of this scope. No reviewer recommended rejection.

The plan has **5 blocking issues** that must be resolved before implementation begins, **12 consolidated warnings** that should be addressed during the relevant work packages, and **14 suggestions** for optional improvements. The blocking issues cluster around three themes: (1) the YAML billion laughs mitigation gap, (2) the MVP governance enforcement facade for `agent_originated` fields, and (3) several under-specified mechanisms that block parallel work streams.

---

## 1. Verdict: APPROVE WITH CONDITIONS

The plan is architecturally sound, well-decomposed, and demonstrates strong security awareness. Implementation may begin on WP-0 (scaffolding) and WP-1a/1b (core enums and taints) immediately. The 5 blocking conditions below must be resolved before the work packages they affect can proceed.

---

## 2. Blocking Issues (Must Fix Before Affected WP Begins)

### B1. YAML Billion Laughs Mitigation Is Insufficient
**Priority Score:** 12 (Severity 4 x Likelihood 3 x Reversibility 1)
**Flagged by:** Security, Systems
**Affects:** WP-3a (manifest loader)

The plan mandates `yaml.safe_load()` + 1MB file-size limit. The file-size limit is necessary but not sufficient. PyYAML's `safe_load()` prevents code execution but does NOT limit alias expansion. A carefully crafted YAML file well under 1MB can expand to gigabytes through nested anchor references, causing denial of service in CI pipelines where wardline is a blocking gate.

**Resolution:** Add a PyYAML alias expansion limit by subclassing `SafeLoader` to count alias resolutions and raise on threshold breach (e.g., 1000 aliases). This is a known PyYAML extension pattern. Alternatively, validate post-parse object serialized size against a configurable maximum. Add this requirement to WP-3a.

---

### B2. Exception Register Field Backfill Gap for `agent_originated`
**Priority Score:** 12 (Severity 4 x Likelihood 2 x Reversibility 2)
**Flagged by:** Architecture, Systems, Security
**Affects:** WP-3a (exception schema), Phase 2 migration

The plan correctly adds `agent_originated`, `recurrence_count`, and `governance_path` to the exception schema from day one (WP-3a). However, it does not define what Phase 2 enforcement does when it encounters an existing exception entry where these fields are absent (written before Phase 2, or written by a tool that omits optional fields). If Phase 2 defaults `agent_originated: false` silently, every agent-written MVP exception is misclassified as human-authored -- precisely the threat the field defends against. The `--migrate-mvp` flag handles the `PY-WL-001-UNVERIFIED-DEFAULT` case but does not mention re-tagging exception register entries.

The Security reviewer escalates this further: the spec (S9.3) designates agent-originated governance changes as a framework invariant, not a nice-to-have. The MVP violates this invariant while the field is schema-only.

**Resolution:** Define one of these approaches before WP-3a:
- (a) Make `agent_originated` use `null`/absent as "provenance unknown" sentinel (not `false`). Phase 2 treats absent as "provenance unknown" and flags those entries for re-review rather than silently classifying them as human-authored. OR
- (b) Bring `agent_originated` tagging enforcement forward to MVP-adjacent scope: at minimum, add a CI-level check that flags commits modifying wardline.yaml, overlays, or exception registers where the commit author matches a configured agent identity pattern. OR
- (c) At minimum, emit a persistent WARNING on every scan that reads an exceptions file where `agent_originated` is populated but the scanner version is pre-Phase-2, making the governance facade visible.

---

### B3. Incorrect `ast.Num`/`ast.Str`/`ast.Bytes` Removal Claim
**Priority Score:** 9 (Severity 3 x Likelihood 3 x Reversibility 1)
**Flagged by:** Reality
**Affects:** Line 27 of the plan; Python 3.12 floor rationale

The plan states: "the deprecated aliases were removed in 3.12, making `ast.Constant` the sole remaining form." This is factually incorrect. The deprecated aliases (`ast.Num`, `ast.Str`, `ast.Bytes`, `ast.NameConstant`) were NOT removed in Python 3.12. In Python 3.12 they emit `DeprecationWarning`. They are scheduled for removal in Python 3.14. The plan uses this false claim as justification for the Python 3.12+ floor.

The underlying requirement is valid (the scanner should use `ast.Constant`), but implementers who read this claim may make incorrect assumptions about what exists in the `ast` module.

**Resolution:** Change line 27 to: "will be removed in Python 3.14; in 3.12 they emit `DeprecationWarning`. The scanner uses `ast.Constant` exclusively, which is correct from Python 3.8+."

---

### B4. Registry "Expected Arguments" Structure Unspecified
**Priority Score:** 9 (Severity 3 x Likelihood 3 x Reversibility 1)
**Flagged by:** Python
**Affects:** WP-1 completion gate; blocks parallel WP-2 and WP-4

The plan specifies that `core/registry.py` stores decorator names, group numbers, expected arguments, and a registry version string. It does not specify what "expected arguments" means structurally -- is it a list of parameter names, a callable signature, a dict of arg names to expected types? Both WP-2 (decorator factory) and WP-4b (decorator argument extraction from AST) depend on this structure. If WP-2 defines argument structure one way and WP-4b parses it another way, the registry becomes a name list only, not a full contract.

**Resolution:** Specify the "expected arguments" data structure in `core/registry.py` before WP-1 is marked complete. This is a named deliverable at the WP-1 completion gate, not an implicit assumption.

---

### B5. Governance Anomaly Signals Lack "Prior State" Mechanism
**Priority Score:** 6 (Severity 3 x Likelihood 2 x Reversibility 1)
**Flagged by:** Architecture
**Affects:** WP-3e (coherence checks), self-hosting gate

The three governance-level anomaly signals from spec S9.3.2 -- tier downgrade detection, tier upgrade without evidence, agent-originated policy change -- are classified as "MVP-adjacent (implement before self-hosting gate)." These are manifest-level checks that require comparing the current manifest to a prior state. The plan does not specify how "across time" is represented: compare to a committed baseline? To the previous git commit? To an explicit prior-manifest argument? Without a defined comparison mechanism, these signals are unimplementable as specified.

**Resolution:** Define whether the prior state is a committed baseline file (like the SARIF regression baseline), a git-tracked comparison, or an explicit `--prior-manifest` CLI argument. Document this in WP-3e's design before implementation begins.

---

## 3. Warnings (Should Fix)

### W1. The 60% Tier-Distribution Threshold Is Unanchored
**Flagged by:** Architecture, Systems, Security, Test Suite
**Priority Score:** 6

The plan specifies ERROR when >60% of declared functions are at permissive tiers (Tier 3/4). Four reviewers independently flagged this threshold as problematic: it is a policy choice without derivation, it is not project-configurable, and a scanner codebase with legitimately high Tier 4 coverage in boundary modules (manifest loader, CLI input parsing, SARIF output) may naturally exceed it.

**Recommendation:** During WP-0b, sketch the expected tier distribution of the scanner's own modules. Set the threshold empirically (10 points above observed distribution) rather than as an arbitrary prior. Make the threshold configurable in `wardline.yaml` with a default of 60%.

---

### W2. UNKNOWN_RAW Silence Loop Has No CI Gate Breaker
**Flagged by:** Systems, Security
**Priority Score:** 6

Functions in undeclared modules receive UNKNOWN_RAW taint, which may suppress findings. The plan provides metrics (`wardline.unknownRawFunctionCount`) in SARIF run properties, but these are reported in a location most operators do not monitor. A build that passes because undeclared modules are silently UNKNOWN_RAW is indistinguishable from one that passes because those modules are genuinely clean.

**Recommendation:** Add a `--max-unknown-raw-percent` flag (or `wardline.toml` config) that fails the scan when the proportion of UNKNOWN_RAW functions exceeds a project-declared ceiling. Self-hosting gate should set this low.

---

### W3. `schema_default()` Bypass Path: WARNING Is Non-Blocking
**Flagged by:** Security, Systems, Quality
**Priority Score:** 6

The plan's `PY-WL-001-UNVERIFIED-DEFAULT` WARNING is an improvement over silent suppression, but the exit code semantics are undefined for WARNINGs. If CI gates only check exit codes, warnings are invisible. A codebase could accumulate hundreds of unverified `schema_default()` calls during MVP with no CI gate failure.

**Recommendation:** Define whether WARNINGs affect exit codes. Add a `--fail-on-unverified-default` CLI flag (default: false in MVP). Document that without this flag, `schema_default()` is an unblocked bypass path during MVP.

---

### W4. `ast.TryStar` Runtime Guard Is Unnecessary for Python 3.12+
**Flagged by:** Reality, Architecture, Python
**Priority Score:** 4

`ast.TryStar` was added in Python 3.11 and is present in all Python 3.12 builds. The `_HAS_TRY_STAR = hasattr(ast, 'TryStar')` guard and its associated corpus `skip_condition` create dead code and a misleading startup warning path that can never fire under the stated `requires-python = ">=3.12"` constraint.

**Recommendation:** Either remove the guard entirely (assert `ast.TryStar` is always present) or change the justification to "guards against non-CPython implementations." Do not present it as guarding against a real Python 3.12 risk. The Reality reviewer's finding that the plan claims `ast.TryStar` is "not guaranteed to be present in `ast.__all__` across all Python 3.12 builds" is unsupported by any documentation.

---

### W5. Self-Hosting SARIF Regression Baseline Comparison Should Be Structural
**Flagged by:** Architecture, Test Suite, Security
**Priority Score:** 4

The plan commits self-hosting SARIF output as a regression baseline and diffs each new scan against it. Three concerns from three reviewers:
- Architecture: Run-level properties (`manifestHash`, `registryVersion`) change for legitimate reasons, creating noise.
- Test Suite: A finding count decrease (possible suppression regression) should require separate sign-off from a finding count increase (code change).
- Security: Baseline + code change in the same commit is invisible in the diff-based check.

**Recommendation:** Specify in WP-6c that the baseline comparison diffs `runs[].results` only (not run-level properties). Require baseline updates as separate commits. Add CODEOWNERS protection for the baseline file.

---

### W6. Integration Test Execution Policy Is Unspecified
**Flagged by:** Test Suite
**Priority Score:** 4

`test_determinism.py` is marked `@pytest.mark.integration` but the plan does not specify when integration tests run. If they run only on opt-in, byte-identical SARIF determinism is never verified in regular CI.

**Recommendation:** Specify a named CI job that runs the integration suite on every commit (or at minimum every merge to main). The determinism test is a correctness invariant, not an optional extra.

---

### W7. `ScanContext` Taint Map Is Shallow-Frozen
**Flagged by:** Python
**Priority Score:** 4

`ScanContext` is `@dataclass(frozen=True)` but if it holds a mutable `function_level_taint_map: dict`, freezing prevents rebinding the attribute but NOT mutation of the dict itself. Rule authors could accidentally mutate shared state.

**Recommendation:** Wrap the taint map in `types.MappingProxyType` at `ScanContext` construction time. Or explicitly document that `ScanContext` is constructed once after pass 1 completes (not incrementally during pass 1), making the shallow freeze safe by construction discipline. Either way, clarify the construction timing.

---

### W8. Missing `__set_name__` in AuthoritativeField Descriptor
**Flagged by:** Python
**Priority Score:** 4

The `AuthoritativeField` descriptor stores in `obj.__dict__["_wd_auth_{name}"]` but the plan does not specify `__set_name__`. Without it, every field declaration must repeat the name: `status = AuthoritativeField("status")`. With `__set_name__` (standard since Python 3.6), it becomes `status = AuthoritativeField()`.

**Recommendation:** Add `__set_name__` to the AuthoritativeField design in WP-1d. This is trivial to implement and expensive to retrofit across all consumers later.

---

### W9. CLI Error Path Tests Missing
**Flagged by:** Quality
**Priority Score:** 4

The four named error conditions in WP-5a (manifest not found, YAML parse error, schema validation failure, scan error) have no corresponding integration test assertions in Section 9. Developers will hit these paths on first real adoption.

**Recommendation:** Add integration test assertions for all four CLI error paths. Define expected output format and exit codes for each.

---

### W10. Exit Code Catalogue Is Incomplete
**Flagged by:** Quality, Security
**Priority Score:** 4

Three exit codes are defined at scattered points in the document (0 = clean, 1 = findings, 2 = config error). The remainder (GOVERNANCE findings, WARNING-only, TOOL-ERROR) are implied or undefined. CI callers need a complete catalogue.

**Recommendation:** Add a complete exit code table to Section 5 or Section 8 of the plan. Specify whether WARNINGs affect exit codes.

---

### W11. First-Scan Perimeter Blindness
**Flagged by:** Security
**Priority Score:** 4

Perimeter-change detection is diff-based. On the first scan or after baseline reset, a poisoned `wardline.toml` that excludes sensitive modules is undetectable.

**Recommendation:** On first scan (no prior baseline), emit a GOVERNANCE finding listing the full enforcement perimeter. Store the initial perimeter as a baseline artifact for future comparison.

---

### W12. Corpus `verdict` Field Conflates True Negative with Known False Negative
**Flagged by:** Test Suite
**Priority Score:** 3

Taint-flow scenarios 3 and 4 are correctly documented as TN specimens (scanner cannot detect at L1). But `verdict: negative` conflates "expected to be silent at L1" with "correct behavior in the absolute sense." Published recall figures become misleading when known false negatives are counted as true negatives.

**Recommendation:** Introduce a `verdict` value of `known_false_negative` (or a `category: known_l1_limitation` field) distinct from `true_negative`. Report these separately in corpus statistics.

---

## 4. Suggestions (Consider)

| # | Source | Suggestion |
|---|--------|------------|
| S1 | Python | Add `ScannerConfig.from_toml()` classmethod factory instead of mutable builder for post-load normalization of frozen dataclass |
| S2 | Architecture | Clarify `PY-WL-001-UNVERIFIED-DEFAULT` rule ID status in `wardline.implementedRules` -- add `wardline.transitionRules` field or document it as synthetic |
| S3 | Architecture | Add test invariant to `test_self_hosting.py` verifying no `__init_subclass__` side effects during scan |
| S4 | Architecture | Extend `test_registry_sync.py` scope to cover Protocol path when WP-8 begins (document as deferred extension) |
| S5 | Test Suite | Specify exec/eval absence test mechanism: mock `exec`/`eval`/`compile` and assert never called during corpus runner execution |
| S6 | Test Suite | Add unit test for tier-distribution threshold: 61% fires ERROR, 60% does not |
| S7 | Test Suite | YAML coercion tests should be written before schema validation tests (test-driven schema design) |
| S8 | Test Suite | Separate `__wrapped__` chain test into unit test (chain traversal) and integration test (AST scanner discovery) |
| S9 | Systems | Enforce registry freeze mechanically: decorator factory `_base.py` asserts at construction time that every attribute name is present in the registry |
| S10 | Systems | Add GOVERNANCE-level finding when `--allow-registry-mismatch` flag is active (makes flag normalization visible) |
| S11 | Security | Change default `overlay_paths` behavior: when absent, default to directories declared in `module_tiers` rather than all directories |
| S12 | Security | Add schema-enforced maximum exception duration (365 days configurable) to prevent de facto permanent exceptions |
| S13 | Security | Mandate that SARIF serialization uses `json.dumps()` with default escaping; add test with JSON-breaking characters in source |
| S14 | Python | Add negative corpus specimens for `ast.MatchMapping`/`ast.MatchClass` to verify PY-WL-003 does not over-fire on legitimate match/case dispatch |

---

## 5. Cross-Reviewer Convergence Analysis

The following concerns were independently flagged by multiple reviewers, indicating high confidence:

### 5.1 The 60% Tier-Distribution Threshold (4 reviewers)
**Architecture + Systems + Security + Test Suite** all independently flagged the 60% permissive-tier threshold as unanchored, potentially too generous for the scanner's own codebase, and untested. This is the single most cross-validated concern in the review.

### 5.2 Exception Register `agent_originated` Governance Gap (3 reviewers)
**Architecture + Systems + Security** independently identified the same structural risk: schema-only fields create a governance facade during MVP that becomes a data retrofit problem at Phase 2 cutover.

### 5.3 UNKNOWN_RAW Silent Fallback Pattern (2 reviewers)
**Systems + Security** both flagged the "silence = safety" illusion: undeclared modules get UNKNOWN_RAW taint, which may suppress findings, and there is no CI-level signal that this is happening. Systems framed it as a reinforcing feedback loop; Security framed it as a perimeter reduction vector.

### 5.4 `ast.TryStar` Guard Unnecessary for Python 3.12+ (3 reviewers)
**Reality + Architecture + Python** all noted the guard cannot fire under `requires-python = ">=3.12"`. Reality provided the strongest evidence: `ast.TryStar` was added in Python 3.11 and is present in all 3.12 builds; the plan's claim about `ast.__all__` is unsupported.

### 5.5 YAML Billion Laughs Mitigation Insufficient (2 reviewers)
**Security + Systems** both identified the 1MB file-size limit as insufficient against alias-expansion attacks. Security provided the attack tree; Systems provided the integration point stress analysis.

### 5.6 Phase 2 Migration Cliff (3 reviewers)
**Quality + Systems + Architecture** all flagged the unbounded accumulation of `PY-WL-001-UNVERIFIED-DEFAULT` WARNINGs during MVP as a migration cliff when Phase 2 converts them to ERROR. Systems provided the most detailed analysis of the compounding effect with exception register enforcement arriving simultaneously.

### 5.7 Self-Hosting Regression Baseline Fragility (3 reviewers)
**Architecture + Test Suite + Security** independently identified different aspects of the same problem: raw diff is too noisy (Architecture), finding-count decrease needs separate sign-off (Test Suite), and simultaneous baseline + code changes are invisible (Security).

### 5.8 Registry Freeze Enforcement Is Social Only (2 reviewers)
**Systems + Security** both noted the registry freeze is a process convention with no technical enforcement. Systems recommended decorator-factory-level assertions; Security recommended `MappingProxyType` or `__setattr__` guards.

---

## 6. Cross-Reviewer Contradictions

### 6.1 `ast.TryStar` Guard: Remove vs. Retain with Explanation
- **Reality/Python:** Remove the guard -- it is dead code under `requires-python >= 3.12`.
- **Architecture:** Retain with corrected explanation -- document why the guard exists despite the version constraint.
- **Resolution:** Err toward Reality's position (remove the guard). If retained for non-CPython defensive purposes, the justification must be rewritten. The current justification ("not guaranteed in `ast.__all__`") is factually incorrect per Reality's verification.

### 6.2 `agent_originated` Enforcement Timing
- **Architecture:** Define default-value policy (option a: null = unknown sentinel).
- **Security:** Bring enforcement forward to MVP (option b: CI-level agent identity check).
- **Systems:** Emit persistent WARNING when fields exist without enforcement (option c: make facade visible).
- **Resolution:** These are not contradictory -- they are three progressively stronger mitigations. The plan should adopt at minimum option (a) from Architecture, and strongly consider option (b) from Security given the spec designates this as a framework invariant.

### 6.3 Self-Hosting Gate 60% Threshold: Fixed vs. Configurable vs. Empirical
- **Architecture:** Derive empirically from WP-0b manifest sketch.
- **Security:** Make configurable in `wardline.yaml` with 60% default.
- **Systems:** Derive from the scanner's own observed distribution plus 10-point headroom.
- **Resolution:** Not contradictory. Combine: make configurable (Security), derive the default empirically from WP-0b (Architecture + Systems), document the derivation.

No irreconcilable contradictions were found across the seven reviewers.

---

## 7. Concrete Action List

Changes required in `/home/john/wardline/docs/2026-03-21-wardline-python-design.md` before implementation begins:

### Before WP-0 (scaffolding)

1. **Fix line 27:** Change "the deprecated aliases were removed in 3.12" to "will be removed in Python 3.14; in 3.12 they emit `DeprecationWarning`. The scanner uses `ast.Constant` exclusively, which is correct from Python 3.8+." [B3]

### Before WP-1 completion

2. **Specify registry "expected arguments" structure.** Add to the `core/registry.py` design a concrete definition of what "expected arguments" means as a Python data structure. This is a WP-1 completion gate deliverable. [B4]

3. **Add `__set_name__` to AuthoritativeField design** in WP-1d section. [W8]

4. **Clarify `ScanContext` construction timing** -- specify that it is constructed once after pass 1 completes with finalized taint map, and either wrap the taint map in `MappingProxyType` or document the shallow-freeze guarantee. [W7]

### Before WP-3a (manifest/schema)

5. **Add YAML alias expansion limit requirement** to WP-3a: subclass `SafeLoader` with alias count limiter (threshold ~1000). [B1]

6. **Define `agent_originated` default-value policy** for the exception register schema: adopt null-means-unknown sentinel at minimum; consider bringing tagging enforcement to MVP-adjacent scope. [B2]

7. **Define governance anomaly "prior state" mechanism** for WP-3e: specify whether tier-downgrade detection compares to a committed baseline, git history, or an explicit `--prior-manifest` argument. [B5]

### Before WP-5a (CLI)

8. **Add complete exit code table** -- define exit codes for all conditions including GOVERNANCE findings, WARNING-only results, and TOOL-ERROR. Specify whether WARNINGs affect exit code. [W10]

9. **Add `--fail-on-unverified-default` and `--max-unknown-raw-percent` flags** to CLI specification. [W2, W3]

10. **Add CLI error path integration tests** for the four named error conditions in WP-5a. [W9]

### Before WP-6a (corpus)

11. **Introduce `known_false_negative` corpus verdict** or `category: known_l1_limitation` field to distinguish from true negatives. [W12]

### Before WP-6c (self-hosting gate)

12. **Derive 60% tier-distribution threshold empirically** from WP-0b manifest sketch. Make the threshold configurable in `wardline.yaml`. [W1]

13. **Specify SARIF regression baseline comparison at `results` level only.** Require baseline updates as separate commits with CODEOWNERS protection. [W5]

14. **Add integration test CI job specification** -- integration tests must run on every merge to main, not only on opt-in. [W6]

### Resolve or remove `ast.TryStar` guard

15. **Either remove the `_HAS_TRY_STAR` guard and associated corpus `skip_condition`**, or rewrite the justification. The current claim about `ast.__all__` is incorrect. [W4]

---

## 8. Reviewer Summary

| Reviewer | Blocking | Warnings | Suggestions | Status |
|----------|----------|----------|-------------|--------|
| Architecture | 1 (exception backfill) | 3 | 7 | ISSUES FOUND |
| Quality | 0 | 3 | 0 | WARNINGS |
| Test Suite | 3 (threshold test, exec/eval mechanism, integration policy) | 7 | 7 | ISSUES FOUND |
| Systems | 3 (UNKNOWN_RAW gate, migration cliff, governance facade) | 4 | 7 | ISSUES FOUND |
| Python | 1 (registry arguments unspecified) | 2 | 5 | ISSUES FOUND |
| Security | 5 (billion laughs, agent governance, schema_default bypass, perimeter blindness, SARIF injection) | 6 | 6 | ISSUES FOUND |
| Reality | 1 (ast removal hallucination) | 3 | 0 | ISSUES FOUND |

Note: Reviewer-level "blocking" counts reflect each reviewer's own classification. The consolidated blocking list (B1-B5) deduplicates and re-prioritizes across all reviewers.

---

## 9. Overall Assessment

The Wardline for Python implementation plan is a high-quality design document that demonstrates strong security awareness, careful architectural decomposition, and detailed test strategy. The WP-based phasing, the tracer bullet (WP-1.5), the frozen registry interface, and the graduated suppression approach for `schema_default()` are all well-designed.

The five blocking issues are all resolvable with plan-level text changes -- none requires fundamental redesign. The most architecturally significant issue is B2 (exception register backfill gap), which affects the trust model during the MVP-to-Phase-2 transition. The most technically precise issue is B3 (incorrect Python 3.12 claim), which is a simple factual correction. The most security-critical issue is B1 (YAML billion laughs), which requires a concrete mitigation addition.

After the five blocking issues are resolved, this plan is ready for implementation to begin.
