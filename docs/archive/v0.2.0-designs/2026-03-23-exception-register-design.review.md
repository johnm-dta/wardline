# WP 1.4: Exception Register Design — Architecture Review

**Reviewer:** Architecture Critic Agent
**Date:** 2026-03-23
**Document reviewed:** `docs/superpowers/specs/2026-03-23-exception-register-design.md`
**Verdict:** Mostly sound. Two high issues require resolution before implementation.

---

## Confidence Assessment

- **Confidence level:** High (0.85)
- **Basis:** Full access to the design spec, all referenced implementation files, the governance model spec (section 9), the manifest format spec (section 13), and the Python design doc. Cross-referenced the actual `Finding` dataclass, `RuleBase._dispatch`, `ExceptionEntry` model, JSON schema, `coherence.py`, `scan.py` pipeline, and severity matrix.

## Risk Assessment

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 3 |
| Low | 2 |

---

## Findings

### 1. Exception matching placed in CLI, not engine — correct but incompletely separated — HIGH

**Evidence:** Design spec Change 3 states "Pipeline placement: Called in the CLI layer (scan.py) between engine scan and SARIF serialization. The engine does not know about exceptions — clean separation of concerns." Change 6 shows the wiring in `scan.py`.

**The good part:** Keeping exception logic out of the engine is the right call. The engine's job is AST pattern detection; exception suppression is a governance post-processing step. The engine should remain a pure function from (AST + taint context) to findings.

**The problem:** The spec places exception matching in the CLI layer (`cli/scan.py`). But `cli/scan.py` is not the right home. It is already a 460-line orchestration function that handles manifest loading, config parsing, registry sync, rule instantiation, governance signal generation, and SARIF output. Adding exception loading, matching, fingerprint computation, and governance finding emission makes the CLI command responsible for two distinct domains: user-facing command orchestration and security-critical governance logic.

The `apply_exceptions` function itself is proposed in `scanner/exceptions.py` — that module placement is correct. But the *wiring* in `scan.py` means the CLI owns the contract for when and how exceptions are applied. If wardline ever gains a library API, a language server integration, or a different CLI frontend, exception handling must be re-implemented or extracted.

**Impact:** Moderate coupling risk. The governance post-processing step should be callable independently of the CLI. This is not blocking for WP 1.4 but becomes blocking for WP 2.3 (Full Governance CLI) where multiple entry points need exception handling.

**Recommendation:** Extract a `post_process_findings(findings, manifest_dir, project_root) -> PostProcessResult` function in `scanner/pipeline.py` (or similar) that encapsulates: load exceptions, apply matching, merge governance findings. The CLI calls this function. This costs approximately 20 lines of extraction and future-proofs the architecture.

---

### 2. Finding is frozen but the spec mutates it during suppression — HIGH

**Evidence:** `src/wardline/scanner/context.py:19-39` — Finding is `@dataclass(frozen=True)`. The design spec Change 3 states: "On match: finding severity downgraded to SUPPRESS, exceptionability set to TRANSPARENT, exception metadata added."

You cannot mutate a frozen dataclass. The spec does not address how suppressed findings are produced. There are two paths:

- (A) Create new `Finding` instances with modified fields via `dataclasses.replace()`. This preserves immutability but means `apply_exceptions` returns new Finding objects, not modified ones. The caller must replace the original list.
- (B) Drop `frozen=True` from Finding. This would be a regression — the module docstring explicitly states "Frozen because findings are immutable records; mutation after creation is a bug."

The spec's language ("finding severity downgraded to SUPPRESS") reads as mutation. The implementation must use approach (A), but the spec should say so explicitly to prevent an implementer from choosing (B).

**Impact:** If an implementer reads the spec literally and tries to mutate findings, they get `FrozenInstanceError` at runtime. If they "fix" it by unfreezing Finding, they introduce a class of bugs the codebase was specifically designed to prevent. Either outcome wastes time.

**Recommendation:** The spec should state: "Suppressed findings are constructed as new Finding instances (via `dataclasses.replace`) with modified severity, exceptionability, and additional metadata. The original finding is not mutated."

Additionally: the spec says "exception metadata added (wardline.exceptionId, wardline.exceptionExpires)" but Finding has no field for arbitrary metadata / property bags. Either add `properties: dict[str, object] | None = None` to Finding, or clarify that the SARIF serializer reads suppression state and injects the property bag during serialization (checking severity == SUPPRESS + exceptionability == TRANSPARENT as a signal). The latter is cleaner but the spec must specify the mechanism.

---

### 3. AST fingerprint includes file_path — makes exceptions non-portable — MEDIUM

**Evidence:** Design spec Change 2: `sha256(f"{file_path}|{qualname}|{dump}")[:16]`

Including `file_path` in the fingerprint hash means that moving a file (rename, directory restructure) invalidates all exceptions targeting functions in that file, even when the code is unchanged. The spec acknowledges that "If the function moves, the exception must be re-granted" (via the governance model), but the fingerprint should detect *code* changes, not *location* changes. Location changes are already detected by the `location` field in the exception entry (`file_path::qualname`).

The fingerprint has two jobs conflated:
1. Detect code structural changes (AST dump)
2. Bind to a specific file location (file_path + qualname)

Job (2) is already handled by the exception's `location` field matching. If the file moves, the location field won't match, so the exception already won't apply. Including file_path in the fingerprint hash adds redundant location-binding that makes `wardline exception refresh` fail on renames even when no code changed.

**Impact:** Extra governance friction on file renames. In a codebase undergoing refactoring, this generates spurious GOVERNANCE-STALE-EXCEPTION findings for unchanged code, contributing to the governance fatigue the spec itself warns about (section 9.3.2).

**Recommendation:** Compute fingerprint as `sha256(f"{qualname}|{dump}")[:16]`. The qualname alone (without file_path) is sufficient for structural identity within the fingerprint. Location binding is the exception entry's job, not the fingerprint's job.

---

### 4. Schema says `ast_fingerprint` is not required; spec says it is — MEDIUM

**Evidence:** The design spec Change 1 states "Add `ast_fingerprint` to `required` array" in the schema. But the current `exceptions.schema.json` (lines 78-82) shows the `required` array as: `["id", "rule", "taint_state", "location", "exceptionability", "severity_at_grant", "rationale", "reviewer"]`. The `ast_fingerprint` field is defined in the schema (after what appears to be a recent addition) but is NOT in the `required` array.

Looking more carefully: the schema at `/home/john/wardline/src/wardline/manifest/schemas/exceptions.schema.json` already includes `recurrence_count` and `governance_path` as properties but does NOT include `ast_fingerprint` as a property at all. Meanwhile `ExceptionEntry` in `models.py` has `ast_fingerprint: str = ""` with a default — meaning schema validation will pass without it.

This creates an inconsistency: the spec says ast_fingerprint is required (mandatory for exception matching), but the model has a default empty string, and the schema doesn't enforce it. An exception entry created without a fingerprint would pass validation but silently never match any finding (empty string != computed fingerprint).

**Impact:** Silent exception matching failures. An operator creates an exception manually (editing JSON) without computing the fingerprint, validation passes, and the exception never suppresses anything. No error, no warning — just silent non-suppression.

**Recommendation:** The implementation must: (1) add `ast_fingerprint` to the schema `properties` and `required` array, (2) remove the default empty string from the model field (make it a required constructor parameter), (3) validate that the value is a 16-character hex string in the schema via `pattern: "^[0-9a-f]{16}$"`.

---

### 5. `Finding.qualname` addition has broad blast radius — MEDIUM

**Evidence:** Design spec Change 3 Decision (A): "add `qualname` to Finding." The Finding dataclass currently has 12 fields. Every Finding construction site across all rules must be updated to pass `qualname`.

Grepping the codebase shows Finding is constructed in:
- `py_wl_001.py` (at least 2 call sites)
- `py_wl_002.py`
- `py_wl_003.py`
- `py_wl_004.py`
- `py_wl_005.py`
- `scan.py` (`_make_governance_finding`)
- Likely `engine.py` for TOOL-ERROR findings

Adding a required positional field breaks all of these. Adding it as `qualname: str | None = None` (with default) is safe but means existing findings won't carry qualname unless each rule is updated — and the spec says rules already have `self._current_qualname` available, so "just add it" is mechanical but touches every rule file.

**Impact:** Not architecturally wrong — this is the correct approach (option A over option B). But the spec underestimates the change scope. This is not "add a field" — it is "modify every Finding construction site in the codebase."

**Recommendation:** Add as `qualname: str | None = None` with default None for backward compatibility. Update all rule `_emit_*` methods in the same PR. Do NOT make it a required field without default — governance findings and TOOL-ERROR findings legitimately have no qualname. Add a test that asserts all non-governance findings produced by the corpus have `qualname is not None`.

---

### 6. Duplicate exception-checking logic between coherence.py and the new exceptions module — LOW

**Evidence:** `coherence.py` already has `check_agent_originated_exceptions()` (lines 289-317) and `check_expired_exceptions()` (lines 320-381). The design spec Change 3 proposes that `apply_exceptions` also emits GOVERNANCE-UNKNOWN-PROVENANCE and checks expiry. These are the same checks in two places.

**Impact:** Maintenance burden. When expiry logic changes, two modules must be updated. The coherence checks run pre-scan; the exception matching runs post-scan. Same data, same checks, different execution points.

**Recommendation:** Define the governance checks once (in the exception module, since it owns the domain) and have coherence.py call into it if pre-scan checks are still wanted. Alternatively, accept the duplication if the pre-scan/post-scan distinction is intentional — but document why both exist.

---

### 7. No collision handling for 16-char truncated SHA-256 — LOW

**Evidence:** Design spec Change 2: fingerprint is `sha256(...)[:16]` — 16 hex characters = 64 bits of entropy.

With 64 bits, the birthday paradox gives a 50% collision probability at ~2^32 (4 billion) distinct functions. For any real codebase, this is not a practical concern. However, the spec does not mention what happens on collision: two different functions would produce the same fingerprint, and an exception for function A could accidentally match function B if they share a qualname (unlikely but not impossible in a monorepo with copy-pasted code).

**Impact:** Negligible in practice. Theoretical concern only.

**Recommendation:** No action needed. Document the 64-bit collision space in a code comment for future reference. If paranoia warrants it, increase to 32 hex characters (128 bits) at negligible cost — the fingerprint is stored once per exception and compared once per finding.

---

## Strengths

1. **Four-tuple matching key is well-designed.** The (rule, taint_state, location, ast_fingerprint) tuple provides precise targeting without over-broad suppression. An exception cannot accidentally suppress a different rule's finding at the same location, or the same rule under a different taint context.

2. **Rule-independent fingerprinting is the correct design.** Computing the fingerprint from the function's AST structure rather than from the specific finding means a code change invalidates all exceptions on that function. This prevents the scenario where an exception for rule A remains valid while the function's structure has changed in a way that should invalidate rule B's exception too.

3. **UNCONDITIONAL bypass prevention.** The spec explicitly states: "Finding exceptionability is not UNCONDITIONAL" as a match precondition, and "UNCONDITIONAL exceptions are schema-invalid." This is correctly enforced at both the matching layer and the schema layer.

4. **Recurrence escalation addresses a real governance attack vector.** The `recurrence_count >= 2` trigger for GOVERNANCE-RECURRING-EXCEPTION directly addresses the temporal gaming scenario from spec section 9.4, where the same violation is perpetually renewed with fresh rationale.

5. **CLI commands are MCP-friendly by design.** The `refresh` command's workflow (detect stale, review, refresh-or-expire) maps cleanly to an agent's decision loop. The `--json` flag on all commands ensures programmatic consumption.

---

## Information Gaps

1. **No test spec for the fingerprint stability contract.** The spec lists unit tests for `compute_ast_fingerprint` but does not specify a golden fingerprint test — a hardcoded (source, qualname, expected_fingerprint) tuple that fails if the algorithm changes. Without this, a refactor could silently change fingerprint computation and invalidate all existing exceptions in the field.

2. **No specification for how `qualname` is populated for module-level findings.** The spec says "The field is optional (None for findings not inside a function, e.g., module-level findings)" but does not address what happens when an exception targets a module-level location. Can exceptions exist for module-level findings? If so, what is the location format — `"file.py::"` (empty qualname)?

3. **`severity_at_grant` stale detection is not mentioned.** The governance model spec (section 13.1.3) requires: "When the enforcement tool detects that a finding's current severity differs from the exception's severity at grant, the exception is flagged as stale." The design spec does not implement this check. This is a spec-compliance gap.

---

## Caveats

- This review covers architectural coherence and design-level issues only. Implementation-level concerns (error handling edge cases, performance of AST re-parsing, etc.) are out of scope until code exists.
- The assessment assumes the design spec will be implemented as written. If the implementer deviates (e.g., uses `dataclasses.replace` without being told to), some findings may not apply.
- The "out of scope" items listed in the spec (per-overlay exceptions, delegation enforcement, optional_fields cross-reference) are accepted as legitimate deferrals and not assessed.
