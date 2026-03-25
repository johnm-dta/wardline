# Second-Pass Review Synthesis: Wardline for Python Implementation Design

**Plan:** `/home/john/wardline/docs/2026-03-21-wardline-python-design.md`
**First-pass synthesis:** `/home/john/wardline/docs/reviews/2026-03-22-plan-review-synthesis.md`
**Second-pass date:** 2026-03-22
**Reviewers:** Architecture, Quality, Test Suite, Systems, Python, Security, Reality
**Pass purpose:** Verify first-pass fixes; identify new issues introduced by the 27 edits

---

## Verdict: APPROVE WITH CONDITIONS

All 5 original blocking issues (B1-B5) are resolved. Two new blocking issues were introduced by the edits, both requiring minimal text changes to fix. No reviewer recommended rejection. The plan is ready for implementation once the two new blocking issues are addressed.

---

## 1. Verification of Original Blocking Issues (B1-B5)

### B1. YAML Billion Laughs Mitigation -- RESOLVED

**Verified by:** Security, Systems, Python

The fix adds a `SafeLoader` subclass with alias count limit (default 1,000) applied to all YAML loading paths (manifests, overlays, corpus specimens). The file-size check is retained as the first line of defence.

**Residual notes (non-blocking):**
- Security recommends reducing the default alias threshold from 1,000 to 100 (wardline manifests should never need more than ~50 aliases). At 1,000, memory-constrained CI runners may still be affected.
- Python notes the guidance to "override `compose_node` or `flatten_mapping`" is imprecise: `flatten_mapping` only catches mapping-merge aliases. The correct complete interception point is `compose_node` with an `AliasEvent` check.
- Systems notes the threshold is described as "configurable" without specifying where (wardline.toml? compile-time constant?) or an upper bound. A user-configurable threshold without a maximum bound could be used to defeat the control.

### B2. Exception Register `agent_originated` Backfill Gap -- RESOLVED

**Verified by:** Architecture, Systems, Security

The fix adopts the null-means-unknown sentinel: `agent_originated` defaults to `null`/absent (not `false`). Phase 2 treats absent entries as "provenance unknown" and flags them for re-review. MVP-adjacent enforcement is RECOMMENDED: GOVERNANCE-level WARNING on every scan with null entries, plus CI-level agent identity check.

**Residual notes (non-blocking):**
- Security recommends upgrading the MVP-adjacent WARNING emission from RECOMMENDED to MUST, since the spec (S9.3) designates agent governance as a framework invariant.
- Systems flags alert fatigue risk: the WARNING fires on every scan for all pre-Phase-2 entries with no acknowledgement mechanism to suppress it for reviewed entries.
- Architecture notes the CI-level agent identity check silently does nothing when no agent patterns are configured in `wardline.toml`.

### B3. Incorrect `ast.Num`/`ast.Str`/`ast.Bytes` Removal Claim -- RESOLVED

**Verified by:** Reality

The corrected text accurately states: deprecated in 3.8, emit `DeprecationWarning` in 3.12, scheduled for removal in 3.14. No new inaccuracy introduced.

### B4. Registry "Expected Arguments" Structure Unspecified -- RESOLVED

**Verified by:** Python

The fix specifies `args: dict[str, type | None]` mapping parameter names to expected types. Python confirms this is correct for the WP-4b consumer (`isinstance()` checks against AST-extracted values).

**Residual notes (non-blocking):**
- The semantics of `None` in the type slot are unspecified (does it mean "no type constraint" or "no value"?). WP-4b will need to guess.
- The `attrs: dict[str, str]` field stores annotation strings, not types. The `test_registry_sync.py` comparison mechanism (how to compare live attribute types against annotation strings) is unspecified.
- The per-entry `version: str` field has no documented consumer; the bidirectional version check operates at the registry-container level, not per-entry.

### B5. Governance Anomaly "Prior State" Mechanism Missing -- RESOLVED

**Verified by:** Architecture, Reality

The fix introduces `wardline.manifest.baseline.json` as a committed baseline file, with `wardline manifest baseline update --approve` as the update command, CODEOWNERS protection, and first-scan fallback behavior (GOVERNANCE INFO finding).

**Gap found (promoted to NEW BLOCKING -- see NB1 below):** The `wardline manifest baseline update` command is attributed to WP-5b (MVP) but does not appear in WP-5b's command list.

---

## 2. New Blocking Issues Introduced by Edits

### NB1. `wardline manifest baseline update` Missing from WP-5b Command List

**Priority Score:** 9 (Severity 3 x Likelihood 3 x Reversibility 1)
**Flagged by:** Architecture, Quality, Reality (3 reviewers independently)
**Affects:** WP-5b completion gate; blocks WP-6c self-hosting gate

WP-3e (line 383) defines the `wardline manifest baseline update --approve` command and attributes it to "WP-5b, MVP." WP-5b (lines 497-500) lists only four MVP commands: `wardline scan`, `wardline manifest validate`, `wardline corpus verify`, and `wardline explain`. The baseline update command is absent from the authoritative command list.

WP-6c's tier-downgrade and upgrade-without-evidence detection depend on a manifest baseline existing. If the baseline update command is not in MVP scope, no baseline can be created, and the self-hosting gate at WP-6c cannot perform governance anomaly detection.

**Resolution required:** Add `wardline manifest baseline update [--approve]` to the WP-5b command list. This is a one-line addition.

---

### NB2. Exit Code Priority Ordering Unspecified (Codes 1 vs. 3)

**Priority Score:** 9 (Severity 3 x Likelihood 3 x Reversibility 1)
**Flagged by:** Quality
**Affects:** WP-5a implementation; CI integration contract

The exit code table defines four codes: 0 (clean), 1 (findings), 2 (config error), 3 (tool error). When a scan produces both ERROR-severity findings (exit code 1) and TOOL-ERROR findings (exit code 3) simultaneously, the catalogue does not specify which exit code wins. Two implementers will write incompatible implementations without guidance. CI pipelines that switch behavior on exit code 1 vs. 3 will behave unpredictably.

**Resolution required:** Add a priority ordering rule to the exit code table. Recommended: exit code 3 (tool error) takes precedence over exit code 1 (findings), because a scan that crashed on some files has incomplete results and the findings exit code would be misleading. Alternatively, exit code 1 takes precedence if the design philosophy is "always report findings." Either way, the rule must be stated.

---

## 3. New Warnings (Should Fix)

Deduplicated and prioritized across all seven reviewers. Issues flagged by multiple reviewers are noted.

### NW1. `wardline.perimeter.baseline.json` Has No Update Command or CODEOWNERS

**Priority Score:** 6 (Severity 3 x Likelihood 2 x Reversibility 1)
**Flagged by:** Architecture, Systems, Security (3 reviewers)

The perimeter baseline is created on first scan but has no documented update command for when the enforcement perimeter legitimately changes (new module added, directory restructured). Unlike `wardline.manifest.baseline.json`, it is not listed in the CODEOWNERS mandate.

Without an update command, operators will either manually edit the file (error-prone), delete and regenerate it (losing history), or accept permanent GOVERNANCE noise. Without CODEOWNERS, the file can be manipulated to shrink the enforcement perimeter undetected (THREAT-025).

**Recommendation:** (a) Add `wardline.perimeter.baseline.json` to the CODEOWNERS mandate in WP-3a. (b) Define a `wardline perimeter baseline update` command in WP-5b or WP-5c, or document that `wardline manifest baseline update` covers both baselines.

### NW2. CLI Flags Split Across Sections; `wardline.toml` Equivalents Inconsistent

**Priority Score:** 6 (Severity 2 x Likelihood 3 x Reversibility 1)
**Flagged by:** Quality, Systems (2 reviewers)

Three issues with the CLI flag specifications:

1. `--fail-on-unverified-default` and `--warnings-as-errors` appear only in the exit code catalogue (WP-5a), not in the `wardline scan` command spec (WP-5b). An implementer writing the Click command from WP-5b would miss these flags.
2. `--max-unknown-raw-percent` has a `wardline.toml` equivalent specified; `--fail-on-unverified-default` and `--warnings-as-errors` do not. Operators managing CI configuration will expect all threshold flags to be settable in `wardline.toml`.
3. `--fail-on-unverified-default` is a strict subset of `--warnings-as-errors`, but this relationship is not documented. An operator could set both without understanding the redundancy.

**Recommendation:** (a) Add all scan flags to the `wardline scan` command spec in WP-5b. (b) Specify `wardline.toml` equivalents for all flags, or explicitly state which are CLI-only. (c) Add a flag interaction note documenting the subset relationship.

### NW3. `functools.wraps` Ordering Rationale Still Conflates Two Concerns

**Priority Score:** 4 (Severity 2 x Likelihood 2 x Reversibility 1)
**Flagged by:** Reality
**Persists from first pass**

Line 289 states `_wardline_*` attributes must be set AFTER `functools.wraps()` and justifies this by citing "a subsequent third-party decorator that calls `update_wrapper`." This is the outer-decorator risk, not the within-factory ordering risk. The actual reason for within-factory ordering is that `functools.update_wrapper` calls `wrapper.__dict__.update(wrapped.__dict__)`, which would overwrite attrs if `fn` already carries `_wardline_*` attributes from decorator stacking.

The prescription is correct; only the stated justification is inaccurate. An implementer following the instruction will produce correct code, but someone reading the rationale to understand *why* will conflate two distinct concerns.

**Recommendation:** Replace the rationale with: "If set before, `functools.wraps(fn)(wrapper)` copies `fn.__dict__` onto `wrapper.__dict__` via `update_wrapper`'s dict update step, overwriting any `_wardline_*` attributes previously set on `wrapper` if `fn` already carries wardline attributes from decorator stacking."

### NW4. `--preview-phase2` Flag Lacks Implementation Contract

**Priority Score:** 4 (Severity 2 x Likelihood 2 x Reversibility 1)
**Flagged by:** Quality, Systems (2 reviewers)

The flag is described in Section 12 (Post-MVP Roadmap) with no exit code semantics, no output format, no test requirement, and scope limited to `PY-WL-001-UNVERIFIED-DEFAULT` count only (exception register impact not covered). It is not assigned to a WP. It has no `wardline.toml` equivalent and does not appear in the exit code table.

**Recommendation:** If the flag is Phase 2 scope, label it as such and defer specification. If it is MVP-adjacent, assign it a WP, add exit code semantics, and specify an output format.

### NW5. `__init_subclass__` Test Mechanism Unspecified

**Priority Score:** 4 (Severity 2 x Likelihood 2 x Reversibility 1)
**Flagged by:** Test Suite

WP-6c states `test_self_hosting.py` MUST verify that `WardlineBase.__init_subclass__` was not triggered during the scan, but does not specify the assertion mechanism. Three approaches (mock/patch, flag/counter, introspection via `__subclasses__()`) have different scope and catch different failure modes. Without a specified mechanism, two developers could implement tests that satisfy the requirement while testing for different bugs.

**Recommendation:** Specify the introspection approach: compare `WardlineBase.__subclasses__()` before and after the scan invocation, assert no new entries. This directly tests the observable concern (scan does not cause new subclass registrations) without requiring production code changes or fragile import-time patching.

### NW6. `known_false_negative` Verdict Not in Corpus YAML Schema

**Priority Score:** 4 (Severity 2 x Likelihood 2 x Reversibility 1)
**Flagged by:** Quality, Test Suite (2 reviewers)

The `known_false_negative` verdict is introduced in WP-6a prose but no schema file is updated to enumerate it as a valid value. If the corpus specimen schema enforces `additionalProperties: false` and enum constraints (as stated for other schemas), `wardline corpus verify` will reject specimens that use the new verdict.

**Recommendation:** Add `known_false_negative` to the corpus specimen schema's `verdict` enum definition in WP-3a or WP-6a.

### NW7. Self-Hosting CI Frequency Contradiction

**Priority Score:** 4 (Severity 2 x Likelihood 2 x Reversibility 1)
**Flagged by:** Quality, Test Suite (2 reviewers)

WP-6c states "self-hosting check runs on every commit." Section 9 states integration tests (including `test_self_hosting.py`, marked `@pytest.mark.integration`) run "on every merge to main." These contradict: if `test_self_hosting.py` is in the integration suite and that suite only runs on merge, the self-hosting check does not run on every commit as WP-6c requires.

**Recommendation:** Either move `test_self_hosting.py` to the unit test suite (runs on every commit) or change WP-6c to "runs on every merge to main."

### NW8. `max_exception_duration_days` Claimed as "Schema-Invalid" but Requires Application Logic

**Priority Score:** 3 (Severity 2 x Likelihood 2 x Reversibility 0.75)
**Flagged by:** Reality

Line 332 states exceptions exceeding the duration "are schema-invalid." JSON Schema cannot enforce cross-field date arithmetic (`expires - grant_date > max_duration`). This is application-level validation in the manifest loader.

**Recommendation:** Change "are schema-invalid" to "are rejected by the manifest loader during validation."

### NW9. `overlay_paths: ["*"]` Undefined as Glob vs. Literal Sentinel

**Priority Score:** 3 (Severity 2 x Likelihood 1.5 x Reversibility 1)
**Flagged by:** Reality, Systems (2 reviewers)

The `"*"` value in `overlay_paths` could be interpreted as a filesystem glob (matching only immediate directory contents on most implementations) or a literal sentinel meaning "unrestricted." These require different implementation and have different security properties.

Systems additionally flags an adoption friction loop: the secure default (only `module_tiers` directories) causes a GOVERNANCE ERROR when an overlay is found in an undeclared directory, and the error message does not guide the developer toward the correct fix (add to `module_tiers`) vs. the bypass (`overlay_paths: ["*"]`).

**Recommendation:** (a) Clarify that `"*"` is a literal sentinel, not a glob. (b) Specify that the GOVERNANCE ERROR for undeclared overlay locations includes corrective guidance: "add this directory to `module_tiers` in `wardline.yaml`."

### NW10. Registry Entry Mutability Inconsistency

**Priority Score:** 3 (Severity 2 x Likelihood 1 x Reversibility 1.5)
**Flagged by:** Python, Systems (2 reviewers)

Registry entries are described as "frozen dataclass or `NamedTuple`" with `dict`-valued fields (`args`, `attrs`). Both are only top-level-frozen; the inner dicts remain mutable. The document already requires `MappingProxyType` for `ScanContext`'s taint map but does not apply the same pattern to registry entries. Additionally, the document presents `NamedTuple` and frozen dataclass as equivalent choices, but frozen dataclass supports `__post_init__` for wrapping dicts (needed for `MappingProxyType`); `NamedTuple` does not.

**Recommendation:** (a) Prescribe frozen dataclass (not `NamedTuple`) for registry entries. (b) Require `MappingProxyType` for `args` and `attrs` fields for consistency with the `ScanContext` pattern.

### NW11. Mechanical Registry Enforcement (S9) Not Incorporated

**Priority Score:** 3 (Severity 2 x Likelihood 1.5 x Reversibility 1)
**Flagged by:** Python, Systems (2 reviewers)

The first-pass synthesis suggestion S9 ("decorator factory `_base.py` asserts at construction time that every attribute name is present in the registry") was not incorporated into the WP-2a text. The registry-decorator consistency guarantee remains social-only enforcement. Systems flags this as a residual from W1 (registry freeze enforcement).

**Recommendation:** Add to WP-2a: "The `wardline_decorator()` factory MUST assert at call time that `name` is present in the registry and that all keys in `**semantic_attrs` are present in the corresponding entry's `attrs` contract."

---

## 4. Cross-Reviewer Convergence on New Issues

The following new issues were independently flagged by multiple second-pass reviewers, indicating high confidence:

### 4.1 Missing `wardline manifest baseline update` from WP-5b (3 reviewers)

**Architecture + Quality + Reality** all independently identified that the command is attributed to WP-5b but absent from WP-5b's command list. This is the highest-confidence finding in the second pass. It is the only new issue flagged by three or more reviewers as blocking.

### 4.2 Perimeter Baseline Governance Gap (3 reviewers)

**Architecture + Systems + Security** all flagged that `wardline.perimeter.baseline.json` lacks an update command and/or CODEOWNERS protection. Architecture identified the missing update command; Systems identified the maintenance dead-end; Security identified the manipulation threat (THREAT-025).

### 4.3 CLI Flag Specification Fragmentation (2 reviewers)

**Quality + Systems** both identified that flags are specified across multiple sections without cross-references, that `wardline.toml` equivalents are inconsistently specified, and that the `--fail-on-unverified-default` / `--warnings-as-errors` subset relationship is undocumented.

### 4.4 `known_false_negative` Schema Gap (2 reviewers)

**Quality + Test Suite** both identified that the new verdict value is introduced in prose but not added to any schema definition.

### 4.5 Self-Hosting CI Frequency Contradiction (2 reviewers)

**Quality + Test Suite** both identified the tension between WP-6c ("every commit") and Section 9 ("every merge to main") for the self-hosting test.

### 4.6 Registry Entry Mutability (2 reviewers)

**Python + Systems** both flagged that registry entries with mutable dict fields are inconsistent with the `MappingProxyType` requirement already applied to `ScanContext`.

### 4.7 Mechanical Registry Enforcement Missing (2 reviewers)

**Python + Systems** both noted that S9 (decorator factory assertions) was not incorporated, leaving registry-decorator consistency as social-only.

---

## 5. Security Threat Status Update

The Security reviewer produced an updated threat risk matrix. Key changes from first pass:

| Threat | First-Pass Status | Second-Pass Status | Notes |
|--------|------------------|-------------------|-------|
| THREAT-001 (YAML billion laughs) | OPEN | CLOSED | Alias count limit effective; threshold could be lower |
| THREAT-004/014 (Agent governance) | OPEN | PARTIALLY CLOSED | Null sentinel good; enforcement still RECOMMENDED not MUST |
| THREAT-008 (First-scan perimeter blindness) | OPEN | CLOSED | New: perimeter baseline needs CODEOWNERS |
| THREAT-009 (Non-UNCONDITIONAL rule disablement) | Not flagged in first pass | NEW - OPEN | Silent bypass: no governance finding for STANDARD/RELAXED rule disablement |
| THREAT-011 (Overlay discovery default) | OPEN | CLOSED | Secure default adopted |
| THREAT-016 (Far-future exception expiry) | OPEN | CLOSED | Schema-level enforcement effective |
| THREAT-019 (schema_default() bypass) | OPEN | CLOSED | Flag available; bypass honestly documented |
| THREAT-021 (Regression baseline manipulation) | OPEN | CLOSED | CODEOWNERS + separate commits + directional diff |
| THREAT-024 (SARIF snippet injection) | OPEN | CLOSED | json.dumps() mandate with test requirement |
| THREAT-025 (Perimeter baseline manipulation) | N/A | NEW - OPEN | No CODEOWNERS on perimeter baseline file |
| THREAT-026 (--allow-permissive-distribution no SARIF signal) | N/A | NEW - OPEN | Override not visible in SARIF output |

**Easiest remaining governance evasion path:** THREAT-009. Adding a non-UNCONDITIONAL rule to `[rules].disabled` requires a one-line `wardline.toml` change and produces no automated governance signal. The change is visible only in code review. Security recommends emitting GOVERNANCE-level WARNING for all rule disablement (not just UNCONDITIONAL).

---

## 6. Reviewer Summary Table

| Reviewer | Original Fixes Verified | New Blocking | New Warnings | New Suggestions |
|----------|------------------------|-------------|-------------|-----------------|
| Architecture | 7/7 resolved | 1 (baseline cmd missing from WP-5b) | 3 | 1 |
| Quality | 3/3 resolved (2 partial) | 2 (exit code priority, baseline cmd) | 6 | 0 |
| Test Suite | 6/6 resolved (1 minimal) | 0 | 4 | 0 |
| Systems | 8/8 resolved (1 W3 unresolved) | 0 | 8 | 5 |
| Python | 4/4 resolved | 0 | 5 | 2 |
| Security | 10/10 threats assessed | 0 | 3 new threats open | 6 |
| Reality | 3/3 fixes checked (1 incomplete) | 0 | 4 | 0 |

---

## 7. Concrete Action List

Changes required in `/home/john/wardline/docs/2026-03-21-wardline-python-design.md` before implementation begins:

### Must Fix (Blocking -- 2 items)

**1. Add `wardline manifest baseline update [--approve]` to WP-5b command list.** [NB1]
One line addition to the WP-5b command inventory at lines 497-500.

**2. Add exit code priority ordering to the exit code table.** [NB2]
Add a note specifying which exit code takes precedence when multiple conditions are simultaneously true (e.g., "exit code 3 takes precedence over exit code 1 when both ERROR findings and TOOL-ERROR findings are present").

### Should Fix (Warnings -- 11 items, prioritized by cross-reviewer convergence)

**3. Add `wardline.perimeter.baseline.json` to CODEOWNERS mandate and define update command.** [NW1]
Either add a `wardline perimeter baseline update` command to WP-5b/5c, or document that `wardline manifest baseline update` covers both. Add the file to the CODEOWNERS list in WP-3a.

**4. Consolidate all `wardline scan` flags in the WP-5b command spec.** [NW2]
Move `--fail-on-unverified-default` and `--warnings-as-errors` into the WP-5b command definition. Specify `wardline.toml` equivalents for all flags or state which are CLI-only. Note the subset relationship between `--fail-on-unverified-default` and `--warnings-as-errors`.

**5. Fix `functools.wraps` ordering rationale at line 289.** [NW3]
Replace outer-decorator justification with the correct within-factory reason: `update_wrapper` copies `fn.__dict__` onto `wrapper.__dict__`.

**6. Add `known_false_negative` to corpus specimen schema.** [NW6]
Update the `verdict` enum definition in the relevant schema.

**7. Resolve self-hosting CI frequency contradiction.** [NW7]
Either move `test_self_hosting.py` out of the integration mark or change WP-6c from "every commit" to "every merge to main."

**8. Specify `__init_subclass__` test mechanism.** [NW5]
Recommend the `__subclasses__()` introspection approach.

**9. Change "schema-invalid" to "rejected by the manifest loader" for `max_exception_duration_days`.** [NW8]

**10. Clarify `overlay_paths: ["*"]` as a literal sentinel, not a glob.** [NW9]
Add corrective guidance to the GOVERNANCE ERROR for undeclared overlay locations.

**11. Prescribe frozen dataclass for registry entries; require `MappingProxyType` for `args`/`attrs`.** [NW10]

**12. Add mechanical registry enforcement assertion to WP-2a.** [NW11]

**13. Specify `--preview-phase2` scope or defer explicitly.** [NW4]

### Consider (Suggestions from individual reviewers)

**14.** Reduce YAML alias threshold default from 1,000 to 100. (Security)

**15.** Upgrade `agent_originated` MVP WARNING emission from RECOMMENDED to MUST. (Security)

**16.** Emit GOVERNANCE-level WARNING for all rule disablement, not just UNCONDITIONAL. (Security, THREAT-009)

**17.** Emit GOVERNANCE-level finding when `--allow-permissive-distribution` is active. (Security, THREAT-026)

**18.** Add `object.__setattr__` note for frozen dataclass `__post_init__` + `MappingProxyType`. (Python)

**19.** Define `None` semantics in registry `args: dict[str, type | None]`. (Python)

**20.** Specify `attrs` annotation-string resolution mechanism for `test_registry_sync.py`. (Python)

**21.** Add alert fatigue mitigation for persistent `agent_originated: null` GOVERNANCE WARNING. (Systems)

**22.** Add `--max-unknown-raw-percent` ceiling-breach finding with a specific rule ID. (Systems)

**23.** Add flag interaction table to WP-5a. (Systems, Quality)

---

## 8. Overall Assessment

The first-pass review found 5 blocking issues, 12 warnings, and 14 suggestions. All 5 blocking issues have been resolved by the edits. The fixes are substantively correct across all seven reviewers' assessments.

The 27 edits introduced 2 new blocking issues (both requiring one-line or one-paragraph additions), 11 new warnings (none requiring fundamental redesign), and 10 suggestions. This is a normal attrition rate for a plan of this size: edits that add new mechanisms (baseline files, CLI flags, schema fields) naturally create new specification surface that requires filling in.

The two new blocking issues cluster around a single theme: new mechanisms were described in their originating work package (WP-3e, WP-5a) but not cross-referenced in the work package that must implement them (WP-5b). These are specification completeness gaps, not design flaws.

The most architecturally significant new warnings are NW1 (perimeter baseline governance gap) and NW2 (CLI flag specification fragmentation). Both affect the operability of the tooling in CI pipelines and should be addressed before the relevant work packages begin.

No reviewer found fundamental design flaws introduced by the edits. The plan remains architecturally sound, well-decomposed, and ready for implementation once the two blocking items are resolved.
