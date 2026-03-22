# Population Plan Review Synthesis

**Date:** 2026-03-22
**Plan:** `docs/2026-03-22-filigree-population-plan.md`
**Reviewers:** Architecture, Reality, Quality, Systems, Python, Security, Leverage
**Verdict:** APPROVE WITH CONDITIONS

---

## Executive Summary

Seven independent reviewers examined the filigree population plan from different
perspectives. The plan is structurally sound -- the hierarchy design (Milestone,
Phase, Work Package), dependency direction (Requirements blocked_by WPs), and
label vocabulary are all correct. All 46 WPs from the execution sequence are
present with accurate dependencies and faithful acceptance criteria summaries.
No architectural flaws were found.

However, the plan has 3 blocking text errors that must be fixed before execution,
5 structural changes that reach strong cross-reviewer consensus, and 7 requirement
gaps identified by the Quality and Security reviewers. None of these require
rethinking the plan's architecture -- they are corrections, tightenings, and
scope adjustments to an otherwise well-designed filing system.

---

## 1. Cross-Reviewer Convergence

Issues flagged by 2+ reviewers carry highest confidence. Six convergence themes
emerged.

### Theme A: WP Count Error (Architecture, Reality, Leverage)

All three reviewers who counted WPs independently arrived at 46, not 42. The
"42 total" header in Section 3 is wrong and propagates to Section 7 (Release),
Section 8 (Creation Order), and the total issue count estimate.

- Architecture: "WP count '42' is wrong; actual count is 46."
- Reality: "Section 3 header claims '42 total' -- WRONG. Actual count is 46."
- Leverage: "42 work packages" used in release items analysis (computed from plan).

**Confidence: Certain.** Three independent counts agree. The table has 46 rows.

### Theme B: Verification Checklist Error (Architecture, Reality)

Both reviewers caught that the Section 9 verification checklist incorrectly
includes T-5.1 in the initial `get_ready` set. T-5.1 depends on T-0.1 and will
be blocked until T-0.1 delivers. The plan's own parenthetical acknowledges this
contradiction.

- Architecture: "Initial `get_ready` set incorrectly includes T-5.1; correct
  set is T-0.1 and T-0.2 only."
- Reality: "T-5.1 DOES depend on T-0.1, so it will not appear in `get_ready`
  until T-0.1 is delivered."

**Confidence: Certain.** The dependency graph is deterministic.

### Theme C: Cut Acceptance Criteria Issues (Systems, Leverage, Architecture)

Three reviewers independently recommended eliminating the ~30-40 Acceptance
Criteria sub-issues.

- Systems: "AC issues add a third copy of criteria... triple-hop cost... the
  Requirement `acceptance_criteria` field is sufficient."
- Leverage: "Cut acceptance criteria children (saves ~35 issues)."
- Architecture: "ACs need to either be listed here or explicitly deferred...
  the plan's verification checklist has no check for AC coverage."

**Rationale convergence:** All three cite the same problems: (a) AC duplicates
information already in the Requirement `acceptance_criteria` field and the WP
Done-When criteria, creating three representations that drift independently;
(b) navigating from an AC issue to actionable work requires a triple-hop (AC
to Requirement to WP to execution sequence); (c) no workflow assigns agents to
act on AC issues.

**Confidence: High.** Three independent analyses reach the same conclusion via
different reasoning paths.

### Theme D: Reduce Release Items (Systems, Leverage, Architecture)

Three reviewers flagged per-WP release items as overhead with minimal signal.

- Systems: "Release Items are structurally redundant for a single-release MVP.
  42 issues that track what the WP `delivered` state already tracks."
- Leverage: "Per-phase release items (7) provide sufficient granularity."
- Architecture: "46 release items at one-per-WP has unclear tracking value
  over milestone completion."

**Recommended resolution:** Reduce from 46 per-WP release items to 7 per-phase
release items. The phase is the natural shippable unit; individual WPs are not
independently releasable.

**Confidence: High.** Same conclusion from three different analytical frameworks
(feedback loops, Meadows hierarchy, blast radius).

### Theme E: Requirement Verification Ownership Gap (Systems, Quality)

Two reviewers identified that Requirements have a five-state lifecycle but no
assigned owner or trigger for state transitions.

- Systems: "Requirement verification has no assigned owner or trigger... will
  result in all 17 Requirements rotting at `approved` after their WPs deliver."
- Quality: "The plan does not specify `verification_method` fields in the
  requirements table -- these are required for `verified` status."

**Confidence: High.** The filing system design defines the lifecycle; the
population plan does not assign responsibility for driving it.

### Theme F: Range Notation Must Be Expanded (Architecture, Reality)

Both reviewers noted that "T-4.7--T-4.11" range notation in the deps column of
T-6.2b, T-6.3, and T-6.4a is not valid filigree API syntax.

- Architecture: "Range notation is human-readable shorthand but will not
  translate directly to filigree API calls."
- Reality: Verified that all dependency edges are correct when expanded; the
  notation is the issue, not the content.

**Confidence: Certain.** Filigree's `add_dependency` takes individual issue IDs.

---

## 2. Consolidated Blocking Issues

Deduplicated across all 7 reviewers, scored and sorted.

Priority = Severity x Likelihood x Reversibility

| ID | Issue | Sources | Sev | Like | Rev | Score | Resolution |
|----|-------|---------|-----|------|-----|-------|------------|
| B1 | WP count "42" is wrong; actual is 46. Propagates to Sections 3, 7, 8, total estimate. | Arch, Reality, Leverage | 3 | 3 | 1 | 9 | Global replace: "42 total" to "46", "42 issues" to "46 issues", "~140" to "~76" (after structural cuts) or "~164" (without cuts). |
| B2 | Section 9 verification checklist includes T-5.1 in initial ready set. T-5.1 is blocked by T-0.1. | Arch, Reality | 3 | 3 | 1 | 9 | Correct to: "`get_ready` shows exactly T-0.1 and T-0.2." Remove T-5.1 and the contradictory parenthetical. |
| B3 | PyYAML constructor pattern `WardlineSafeLoader(stream, alias_limit=N)` is invalid API. SafeLoader does not accept kwargs. | Python | 4 | 3 | 1 | 12 | This error is in the execution sequence, not the population plan. The population plan's REQ-SEC-01 AC says only "configurable with hard upper bound" which is correct. However, T-3.3's AC in the population plan does not mention the constructor. **No change needed in population plan.** Flag for execution sequence correction separately. |
| B4 | T-4.2 AC conflates `__init_subclass__` (class definition time) with ABC (instantiation time) in a single bullet. | Python | 3 | 2 | 1 | 6 | Split T-4.2 AC into two sub-bullets: (a) override of `visit_FunctionDef` raises TypeError at class definition via `__init_subclass__`, (b) missing `visit_function` raises TypeError at instantiation via ABC. |
| B5 | REQ-SEC-02 AC text ("without `Loader=SafeLoader`") is inconsistent with the resolved B-02 fix from the execution sequence review. Should be "without `Loader=` on the same line." | Quality | 3 | 2 | 1 | 6 | Update REQ-SEC-02 AC: "CI grep check fails on `yaml.load(` without `Loader=` on the same line. Runs on every push. Excludes `.venv/`." |

**Note on B3:** The Python reviewer rated this as critical, but the error lives
in the execution sequence document, not in the population plan. The population
plan's own wording for T-3.3 and REQ-SEC-01 does not specify the constructor
pattern. This is therefore **not blocking for the population plan** but is
blocking for the execution sequence and must be fixed there before any agent
implements T-3.3. Downgraded from blocking to out-of-scope for this document.

**Effective blocking issues for the population plan: B1, B2, B4, B5** (4 issues).

---

## 3. Structural Recommendations (Issue Count Reduction)

### Consensus: Cut from ~164 to ~76 issues

All three structural reviewers (Architecture, Systems, Leverage) converge on
eliminating two categories of issues that add overhead without proportional
tracking value.

| Category | Current | Proposed | Savings | Consensus |
|----------|---------|----------|---------|-----------|
| Acceptance Criteria children | ~35 | 0 | ~35 | Systems, Leverage, Architecture |
| Release Items | 46 (per-WP) | 7 (per-phase) | 39 | Systems, Leverage, Architecture |
| All other categories | 83 | 83 | 0 | Keep as-is |
| **Total** | **~164** | **~76** | **~88** | |

**Revised issue breakdown (76 total):**

| Category | Count |
|----------|-------|
| Milestone | 1 |
| Phases | 7 |
| Work Packages | 46 |
| Requirements | 17 |
| Release | 1 |
| Release Items (per-phase) | 7 |
| Acceptance Criteria | 0 |

**Rationale for each cut:**

**Acceptance Criteria (cut entirely):** The Requirement `acceptance_criteria`
field already contains machine-verifiable criteria text. Creating Given/When/Then
children as separate issues introduces a third source of truth (alongside the
Requirement field and the WP Done-When in the execution sequence). No agent
workflow assigns work based on AC issues. No lifecycle transition triggers on
AC issue state changes. They are structural decoration.

**Release Items (collapse to per-phase):** For a single-release MVP, per-WP
release items duplicate WP `delivered` status. Per-phase release items (7)
provide the useful rollup: "is Phase 3 release-ready?" is actionable; "is
T-3.5 release-ready?" is not. Per-phase items also match the phase entry/exit
criteria gates that already exist.

### Dissenting view

No reviewer argued for keeping AC issues. The Architecture reviewer noted the
AC gap as a completeness concern (they are mentioned but not enumerated) rather
than advocating for their creation. This strengthens the cut recommendation --
even the completeness reviewer did not argue they add value.

On release items, the Architecture reviewer framed this as "worth a deliberate
decision" rather than an outright cut recommendation. The Systems and Leverage
reviewers were more definitive.

---

## 4. Missing Requirements

Quality and Security reviewers identified requirements gaps. Consolidated below,
deduplicated where both reviewers flagged the same gap.

### 4a. Requirements to Add

| ID | Gap | Sources | Recommendation |
|----|-----|---------|---------------|
| GAP-1 | Overlay severity narrowing governance signal. The invariant (severity narrowing via overlay is allowed and MUST emit GOVERNANCE INFO) is in T-3.5 Done-When but not in any requirement. | Quality, Security (FINDING-02) | Add to REQ-ENF-01 AC: "Severity narrowing through overlay is permitted and emits GOVERNANCE INFO signal." |
| GAP-2 | CLI enforcement-weakening flags must produce GOVERNANCE findings in SARIF. `--allow-permissive-distribution` produces no audit trail. | Security (FINDING-06, THREAT-026) | Add REQ-ENF-04: "CLI flags that weaken enforcement thresholds MUST produce GOVERNANCE-level finding in SARIF output." |
| GAP-3 | Governance signals (disabled rule, registry mismatch) must appear as SARIF findings, not just log output. | Security (FINDING-01), Quality | Strengthen REQ-ENF-03 AC: "GOVERNANCE WARNING for disabled rule appears as a SARIF finding (not log-only)." |
| GAP-4 | REQ-SEC-06 "baselines" is ambiguous. Does not enumerate `wardline.perimeter.baseline.json` explicitly. | Security (FINDING-05, THREAT-025) | Enumerate all baseline files in REQ-SEC-06 AC: `wardline.manifest.baseline.json`, `wardline.perimeter.baseline.json`. |
| GAP-5 | REQ-SH-01 80% coverage criterion has no measurement mechanism. | Quality, Systems | Specify the tool/command that measures coverage, or split REQ-SH-01 so the coverage criterion stands alone with a defined measurement approach. |

### 4b. Requirements to Strengthen

| Requirement | Gap | Sources | Fix |
|-------------|-----|---------|-----|
| REQ-DM-03 | "Bidirectional sync" does not require attribute-level stub decoration check (design doc's check c). Name-only comparison satisfies criterion as written. | Quality | Add: "Attribute-level contract verified via stub decoration, not just name comparison." |
| REQ-SEC-05 | "Far-future expiry rejected" has no threshold definition. | Security | Replace with: "Exception where `expires - grant_date > max_exception_duration_days` fires GOVERNANCE WARNING." |
| REQ-OUT-01 | "All property bags present" has no enumeration. | Quality | Add list of required property bag keys or reference spec section. |
| REQ-SH-01 | Monolithic: combines scan correctness, coverage floor, corpus verify, and CI gate. | Quality | Consider splitting into REQ-SH-01a (zero ERROR on self-scan), REQ-SH-01b (coverage floor), REQ-SH-01c (CI green with baselines). |

### 4c. Requirements Considered and Deferred

The following gaps were identified but are arguably out of MVP scope or have
compensating controls already in the design:

| Gap | Source | Rationale for Deferral |
|-----|--------|----------------------|
| schema_default() bypass as a requirement (THREAT-019) | Security (FINDING-03) | T-4.7 AC already captures the behavior. Promote to requirement if pattern catalogue expands post-MVP. |
| SARIF output sanitization (THREAT-024) | Security (FINDING-04) | `json.dumps()` handles escaping. Document as coding standard, not formal requirement. |
| Supply chain / dependency pinning (FINDING-10) | Security | Standard Python hygiene. Not specific to the enforcement framework. |
| Vendored SARIF schema integrity (FINDING-09) | Security | Add to CODEOWNERS coverage in REQ-SEC-06. Hash verification is low-priority. |
| Annotation coverage floor as scanner output for all scans (Residual Risk 4) | Quality | Currently scoped to self-hosting gate only. Promote post-MVP if needed. |
| Expedited governance ratio tracking (Residual Risk 6) | Quality | Not in any WP or requirement. Explicitly post-MVP. |

---

## 5. Technical Corrections

### 5a. Count and Text Corrections

| Location | Current Text | Corrected Text | Source |
|----------|-------------|----------------|--------|
| Section 3 header | "Work Packages (42 total)" | "Work Packages (46 total)" | Arch, Reality |
| Section 7 Release | "One per WP (42 total)" | "One per Phase (7 total)" (if structural cut accepted) or "One per WP (46 total)" | Arch, Reality, Leverage |
| Section 8 line 3 | "Work Packages (42 issues..." | "Work Packages (46 issues..." | Arch, Reality |
| Section 8 line 5 | "Acceptance Criteria (~30-40 issues..." | Remove line (if structural cut accepted) | Systems, Leverage |
| Section 8 line 7 | "Release Items (42 issues..." | "Release Items (7 issues, one per phase)" or "Release Items (46 issues...)" | Arch, Reality, Leverage |
| Section 8 total | "Total: ~140 issues" | "Total: ~76 issues" (with cuts) or "Total: ~164 issues" (without cuts) | All |
| Section 9 bullet 1 | "`get_ready` shows only T-0.1, T-0.2, and T-5.1..." | "`get_ready` shows exactly T-0.1 and T-0.2." | Arch, Reality |
| REQ-SEC-02 AC | "without `Loader=`" (verify exact wording matches resolved B-02 fix) | "CI grep check fails on `yaml.load(` without `Loader=` on the same line. Runs on every push. Excludes `.venv/`." | Quality |
| T-4.2 AC | Single bullet conflating two distinct checks | Split into: (a) override guard at class definition via `__init_subclass__`, (b) ABC enforcement at instantiation | Python |

### 5b. API and Technical Accuracy

| Item | Issue | Source | Population Plan Impact |
|------|-------|--------|----------------------|
| `WardlineSafeLoader(stream, alias_limit=N)` constructor pattern | Invalid PyYAML API | Python | **Not in population plan** -- this is an execution sequence error. Population plan's REQ-SEC-01 and T-3.3 ACs are correct as written. Flag separately. |
| `blocked_by` presented as a field column in Requirement tables | It is a dependency relationship, not a schema field. Created via `add_dependency`, not a field setter. | Reality | Add clarifying note to Section 4 header or Section 8 Step 4: "REQ-to-WP linkages are created via `add_dependency`, not as a field value." |
| Release `version` field not mentioned | Required before `frozen` transition | Reality | Add to Section 7: "Version: v0.1.0" as a field in the Release table. |
| `tomllib` binary mode absent from T-3.2 AC | Execution sequence specifies `open(path, 'rb')` but population plan AC does not | Python | Add to T-3.2 AC: "`ScannerConfig.from_toml()` uses binary mode (`'rb'`) as required by `tomllib`." |
| T-4.5 "all 6 edge-case patterns" not enumerated | Count without list | Python | Enumerate the six patterns in AC text. |

### 5c. Notation Fixes

| Location | Issue | Fix |
|----------|-------|-----|
| T-6.2b Deps | "T-4.7--T-4.11" range notation | Expand to "T-4.7, T-4.8, T-4.9, T-4.10, T-4.11" |
| T-6.3 Deps | Same range notation | Expand to explicit IDs |
| T-6.4a Deps | Same range notation | Expand to explicit IDs |

---

## 6. Concrete Action List

### (a) Count/Text Corrections (must-fix before execution)

1. Replace "42 total" with "46" in Section 3 header.
2. Replace "42" with "46" (or "7" for per-phase) in Section 7 Release Items.
3. Replace "42 issues" with "46 issues" in Section 8 WP line.
4. Update Section 8 total to reflect final issue count.
5. Correct Section 9 verification checklist: remove T-5.1 from initial ready set.
6. Expand "T-4.7--T-4.11" to five explicit IDs in T-6.2b, T-6.3, T-6.4a.
7. Split T-4.2 AC into two sub-bullets (class definition vs. instantiation).
8. Update REQ-SEC-02 AC to match resolved B-02 wording.

### (b) Requirements to Add or Modify

9. Strengthen REQ-ENF-01 AC to include overlay severity narrowing GOVERNANCE INFO signal.
10. Add REQ-ENF-04 (or fold into REQ-ENF-03): CLI enforcement-weakening flags
    produce GOVERNANCE-level SARIF findings.
11. Strengthen REQ-ENF-03: governance signals must appear as SARIF findings.
12. Enumerate baseline files explicitly in REQ-SEC-06 AC.
13. Strengthen REQ-DM-03: require attribute-level stub decoration check.
14. Sharpen REQ-SEC-05: replace "far-future" with threshold reference.
15. Add coverage measurement mechanism to REQ-SH-01 (or split the requirement).
16. Add `tomllib` binary mode note to T-3.2 AC.
17. Enumerate T-4.5's six edge-case patterns explicitly.

### (c) Structural Changes

18. Remove Acceptance Criteria children (Section 8 Step 5) entirely.
19. Change Release Items from per-WP (46) to per-phase (7) in Sections 7 and 8.
20. Add `version: v0.1.0` to Release table in Section 7.
21. Add clarifying note that `blocked_by` is a dependency relationship, not a field.
22. Remove `spec:` labels from vocabulary (or retain as documentation-only with
    explicit note that no workflow uses them). [Leverage recommendation; optional.]

### (d) Process Additions

23. Add requirement verification ownership convention: "After delivering a WP,
    the implementing agent checks `list_issues --type=requirement` for newly
    unblocked requirements and verifies them using their AC as a checklist."
24. Add creation order guidance for Step 3 (WPs): "Create all WPs first, then
    add dependencies in a second pass to avoid forward-reference failures."
25. Document `get_ready` type-filtering convention for agents: "Use
    `get_ready --type=work_package` to find the next assignable unit."
26. Add T-1.7 negative test note: "Includes negative test confirming that
    calling `super()` after wardline checks breaks cooperative `__init_subclass__`."

---

## 7. Reviewer Summaries

| Reviewer | Focus | Blocking | Warnings | Key Contribution |
|----------|-------|----------|----------|-----------------|
| Architecture | Hierarchy, dependencies, blast radius | 2 (count error, checklist error) | 6 (T-4.INT position, range notation, T-0.2 label, release items, AC enumeration, unused spec:portability label) | Confirmed hierarchy design is sound. Identified count propagation error. |
| Reality | Symbol existence, field validity, completeness | 3 (count error, blocked_by field, checklist error) | 3 (version field, creation order, total undercount) | Exhaustive dependency and label verification: zero discrepancies in 46 WPs. |
| Quality | Requirements coverage, AC quality, gap analysis | 2 (REQ-SEC-02 inconsistency, REQ-SH-01 coverage gap) | 6 (severity narrowing gap, coverage reporting gap, REQ-DM-03 under-specified, REQ-OUT-01 unenumerated, REQ-SH-01 too broad, spec:portability orphaned) | Deepest requirements analysis. Identified AC quality issues and verification method gaps. |
| Systems | Feedback loops, failure modes, overhead | 2 (requirement rot, mixed `get_ready`) | 4 (AC duplication, release item redundancy, T-6.4a convergence, stale AC risk) | Identified requirement verification ownership gap and signal-to-noise problems. |
| Python | Technical accuracy, API correctness | 2 (PyYAML constructor, T-4.2 conflation) | 4 (copy-on-accumulate test, RuleId exhaustiveness, tomllib binary mode, T-1.7 negative test) | Found the PyYAML API error and the `__init_subclass__` timing conflation. |
| Security | Threat coverage, STRIDE analysis | 0 (no blocking issues in population plan itself) | 10 findings total (FINDING-01 through -10) | Identified 2 uncaptured threats (THREAT-025, -026), temporal governance window, and acceptance criteria vagueness. |
| Leverage | Bottleneck analysis, overhead threshold | 0 | 0 (all findings framed as interventions) | Fan-out analysis confirmed priority calibration is correct. Provided the strongest argument for issue count reduction with Meadows hierarchy. |

---

## 8. Conflicts Resolved

| Conflict | Views | Resolution |
|----------|-------|-----------|
| Is B3 (PyYAML constructor) blocking for the population plan? | Python: Critical. Others: not flagged. | **Resolved as out-of-scope.** The error is in the execution sequence, not the population plan. The population plan's own wording (REQ-SEC-01, T-3.3) does not specify the constructor pattern. Flag for execution sequence correction separately. |
| Should `spec:` labels be cut? | Leverage: Cut (documentation-only, no workflow uses them). Quality: Notes orphaned `spec:portability` but does not recommend cutting the namespace. | **Resolved as optional.** Retain `spec:` labels if they aid human readability of the requirement list. They impose near-zero overhead (created once, never filtered). Remove `spec:portability` only if no portability requirement is added. |
| Is T-0.2 mislabeled? | Architecture: `subsystem:manifest` is wrong for a design-only WP; suggests `subsystem:ci` or `subsystem:docs`. Reality: Labels match (T-0.2 produces `wardline.yaml` design, which is manifest subsystem). | **Resolved in favor of Reality.** T-0.2 produces manifest design artifacts. `subsystem:manifest` is accurate even though no code is written. The label describes the subsystem, not the artifact type. |
| Should T-0.3 be a hard dependency of T-1.1? | Security (FINDING-08): Temporal window is a security risk. Architecture: Not flagged. | **Resolved as process addition.** Adding T-0.3 as a hard dep of T-1.1 would serialize work unnecessarily (T-0.3 and T-1.1 can legitimately proceed in parallel on different branches). Instead, add action item 23 (process note) and ensure the scheduling convention addresses this. |
| How many release items? | Systems: 0 or per-phase. Leverage: per-phase (7). Architecture: deliberate decision needed. | **Resolved as per-phase (7).** Three reviewers agree per-WP is redundant. Per-phase provides the useful rollup. |

---

## 9. Verdict

### APPROVE WITH CONDITIONS

The population plan's architecture is sound:

- The Milestone-Phase-WP hierarchy is the correct decomposition.
- All 46 execution sequence tasks are present with zero missing or extra WPs.
- All dependency edges are accurately reproduced (Reality verified every edge).
- All acceptance criteria faithfully summarize the execution sequence.
- All label assignments are correct (Reality verified all 46).
- The requirement-to-WP linkage map is complete and correctly grounded.
- Priority assignments are well-calibrated to fan-out (Leverage verified).
- No circular dependencies exist.

**Conditions for approval (must-fix):**

1. Apply the 8 count/text corrections from Section 6a.
2. Apply the 9 requirement additions/modifications from Section 6b.
3. Apply the 5 structural changes from Section 6c (especially: cut AC children,
   collapse release items to per-phase, add release version field).
4. Apply the 4 process additions from Section 6d.

**Once these 26 action items are applied, the plan is ready for execution.**

The conditions are corrections and tightenings, not architectural changes. The
plan does not need to be re-reviewed after these changes are applied -- a
verification pass confirming the changes were made correctly is sufficient.

---

## Appendix: Priority Scoring Detail

Scores use: Severity (1-4) x Likelihood (1-3) x Reversibility (1-3).

| Issue | Sev | Like | Rev | Score | Category |
|-------|-----|------|-----|-------|----------|
| B1: WP count 42 vs 46 | 3 | 3 | 1 | 9 | Must fix |
| B2: T-5.1 in ready set | 3 | 3 | 1 | 9 | Must fix |
| B4: T-4.2 AC conflation | 3 | 2 | 1 | 6 | Must fix |
| B5: REQ-SEC-02 stale text | 3 | 2 | 1 | 6 | Must fix |
| GAP-2: CLI flag audit trail | 3 | 2 | 2 | 12 | Should fix (new REQ) |
| GAP-1: Severity narrowing signal | 2 | 3 | 1 | 6 | Should fix (REQ mod) |
| GAP-3: Governance in SARIF | 2 | 2 | 2 | 8 | Should fix (REQ mod) |
| GAP-4: Baseline enumeration | 3 | 2 | 1 | 6 | Should fix (REQ mod) |
| GAP-5: Coverage measurement | 2 | 3 | 1 | 6 | Should fix (REQ mod) |
| AC cut (~35 issues) | 2 | 3 | 1 | 6 | Structural |
| Release item collapse | 2 | 3 | 1 | 6 | Structural |
| Req verification ownership | 3 | 3 | 1 | 9 | Process |
