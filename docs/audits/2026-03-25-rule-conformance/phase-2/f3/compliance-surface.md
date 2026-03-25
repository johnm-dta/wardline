# Compliance Surface Assessment (Phase 2, F3)

**Date:** 2026-03-25
**Scope:** Normative/non-normative requirement distinction, severity matrix completeness, governance profile compliance
**Assessor:** Compliance Surface Agent

---

## 1. Living Pattern Catalogue (S7 MUST)

**Spec requirement (S7 para 2):** "Language bindings MUST maintain version-tracked lists of semantic equivalents for each pattern rule, extending detection coverage as new evasion variants are identified."

**RFC 2119 classification:** MUST (normative, non-optional)

**Finding:** NOT IMPLEMENTED. A codebase-wide search for "semantic equivalent," "living pattern," and "evasion variant" in `src/` returns zero matches. There is no data structure, configuration file, or code path that maintains or references a list of semantic equivalents for any pattern rule (PY-WL-001 through PY-WL-009).

The scanner rules detect fixed AST patterns. There is no mechanism to:
- Register new evasion variants for a rule
- Version-track the set of patterns each rule detects
- Extend detection coverage when new variants are identified

**Conformance impact:** This is a **conformance blocker** for Wardline-Core profile claim. The word MUST in S7 is unambiguous. The absence of this mechanism means the Python binding does not satisfy the living-catalogue requirement for any of its nine rules.

**Severity:** HIGH. While the current fixed patterns may provide adequate detection today, the spec explicitly anticipates pattern evolution as model capability evolves. The framework treats this as a structural requirement, not a nice-to-have.

**Verdict on item 1:** FAIL

---

## 2. Governance Profile Compliance (S14.3.2 Lite Requirements)

The project declares `governance_profile = "lite"` (hardcoded in `src/wardline/manifest/regime.py:59` and `:209`; not yet read from the manifest itself per the TODO at line 208).

### Lite MUST requirements checklist:

| Requirement | Status | Evidence |
|---|---|---|
| Root wardline manifest (`wardline.yaml`) | PASS | Manifest exists, loads via `load_manifest()`, validated in `test_self_hosting_scan.py:209-215` |
| SARIF output with wardline property bags | PASS | `sarif.py` produces SARIF 2.1.0 with `wardline.*` properties on both run and result levels |
| CODEOWNERS protection for governance artefacts | PASS | `.github/CODEOWNERS` protects `wardline.yaml`, `wardline.toml`, overlay files, corpus, baselines |
| Exception tracking | PASS | Exception register loading and schema validation implemented in `manifest/exceptions.py`; register schema at `manifest/schemas/exceptions.schema.json`; entries carry reviewer identity, rationale, expiry, governance path, agent-originated flag |
| Annotation change tracking (MUST) | PASS | `scanner/fingerprint.py` implements annotation fingerprint computation with canonical hashing and change detection. This exceeds the Lite minimum (which permits VCS diff review). |

### Lite SHOULD requirements:

| Requirement | Status | Notes |
|---|---|---|
| Temporal separation | PARTIAL | No `temporal_separation` field found in the self-hosting manifest. Lite requires documentation of an alternative if temporal separation is not implemented. The manifest models support it, but no alternative is declared. |
| Bootstrap golden corpus | NOT ASSESSED | Corpus directory existence not verified in this assessment (out of scope). |
| Expedited governance ratio | PARTIAL | `expedited_exception_ratio` is computed and reported in SARIF (`sarif.py:244`). No declared threshold found in the self-hosting manifest. Lite MUST documents the expedited exception approval process if the ratio is not computed -- the ratio IS computed, satisfying RECOMMENDED. |

### Governance profile declaration gap:

The governance profile is hardcoded as `"lite"` in `regime.py` with a TODO comment: "read from manifest when field exists" (lines 58-59, 208-209). The spec (S14.3.2) states: "A deployment MUST declare which governance profile it operates under. The governance profile is recorded in the root wardline manifest." The profile is not read from the manifest -- it is always assumed to be `"lite"` regardless of what the manifest says. This is a minor conformance gap: the mechanism exists but the manifest field is not wired.

Additionally, the spec requires `wardline.governanceProfile` in SARIF output. Searching the SARIF module (`sarif.py`) and entire scanner for `governanceProfile` or `governance_profile` returns zero matches. **The SARIF output does not include `wardline.governanceProfile`.** This is a MUST requirement per S14.3.2.

**Verdict on item 2:** CONCERN -- Lite MUST requirements are substantially met, but `wardline.governanceProfile` is absent from SARIF output, and governance profile is not read from the manifest.

---

## 3. Control Law Reporting (S9.5)

**Spec requirement:** "The current enforcement state is reported in the SARIF run properties as `wardline.controlLaw` with values `'normal'`, `'alternate'`, or `'direct'`."

**Finding:** NOT IMPLEMENTED. Searching the entire `src/wardline/` tree for `controlLaw` and `control_law` returns zero matches. The SARIF run properties in `sarif.py:222-255` do not include `wardline.controlLaw`. There is no code that determines whether the scanner is operating in normal, alternate, or direct law.

The spec further requires:
- `wardline.controlLawDegradations` when in alternate law
- `wardline.degradedCommitRange` for alternate/direct law runs
- `wardline.retroactiveScan` marker on first normal-law run after degradation

None of these properties exist in the implementation.

**Conformance impact:** The assessment procedure (S14.6 Step 4) explicitly requires: "Verify `wardline.controlLaw` reports 'normal' for the declared adoption phase." Without this property, the scanner cannot pass formal assessment.

**Verdict on item 3:** FAIL

---

## 4. UNCONDITIONAL Cell Protection

**Spec requirement (S9.1):** "UNCONDITIONAL: No exception permitted. Project invariant. Hardcoded -- cannot be overridden by any actor."

**Finding:** IMPLEMENTED CORRECTLY.

Two enforcement layers protect UNCONDITIONAL cells:

1. **Matrix immutability.** `SEVERITY_MATRIX` in `core/matrix.py:74` is a `MappingProxyType` (read-only mapping proxy). `SeverityCell` is `frozen=True` (line 22). The builder dict is deleted after construction (line 77). There is no API to modify the matrix at runtime.

2. **Exception register validation.** `manifest/exceptions.py:83-97` (`_validate_not_unconditional`) performs load-time validation: every exception entry is checked against the severity matrix, and exceptions targeting UNCONDITIONAL cells raise `ManifestLoadError`. This runs at register load time, preventing invalid exceptions from entering the system.

3. **Overlay merge enforcement.** `manifest/merge.py:108-119` enforces narrow-only semantics: overlays cannot lower severity (only raise it). A `ManifestWidenError` is raised if an overlay attempts to reduce severity. This prevents indirect weakening through the overlay system.

The root manifest cannot alter UNCONDITIONAL cells because:
- The matrix is hardcoded and immutable
- Rule overrides in the manifest go through the merge path which enforces narrow-only
- Exceptions targeting UNCONDITIONAL cells are rejected at load time

**Verdict on item 4:** PASS

---

## 5. Severity Override Constraints

**Spec requirement:** Overrides can only narrow (raise severity), never widen (lower severity).

**Finding:** IMPLEMENTED CORRECTLY in `manifest/merge.py:108-119`.

The merge function compares severity ranks: if `overlay_severity` rank is lower than `base_severity` rank, a `ManifestWidenError` is raised. The rank table (`_SEVERITY_RANKS` at line 170-176) assigns: OFF=0, INFO=1, WARNING=2, ERROR=3, CRITICAL=4. An overlay that attempts ERROR->WARNING (3->2) triggers the error. An overlay that does WARNING->ERROR (2->3) succeeds (narrowing is allowed).

Boundary-level narrow-only checks are also enforced (lines 136-156): overlay boundaries cannot declare tier numbers higher than the module's declared tier.

**Verdict on item 5:** PASS

---

## 6. Self-Hosting Gate (S10 Property 2)

**Spec requirement (S14.2, criterion 7):** "Each enforcement tool passes its own rules where applicable."

**Finding:** PARTIALLY IMPLEMENTED.

`tests/integration/test_self_hosting_scan.py` runs the scanner against `src/wardline/` and verifies:
- No crash (exit code != 3)
- No config error (exit code != 2)
- Valid SARIF output
- Finding counts within expected ranges per rule
- Files scanned count

However, the test **does not assert exit code 0** (no ERROR findings). It tolerates exit code 1 (findings present). The comment at line 97 says: "Exit 1 (findings present) is expected."

This means the scanner's own source code does produce findings that are not resolved or excepted. The self-hosting gate as defined in S10 requires that the tool "passes its own rules" -- which means either zero findings or all findings excepted. The current test verifies the scanner runs without crashing but does not verify it passes clean.

The test does validate that finding counts are within expected ranges (lines 122-183), which demonstrates stability but not compliance. A self-hosting gate that permits a known baseline of findings is weaker than the spec's requirement.

**Mitigating factor:** The project is a tooling project whose own code does not process user data through the wardline pipeline (comment at line 249). The scanner's own source would naturally produce pattern-rule findings (e.g., `.get()` calls in scanner internals) that are architecturally appropriate but syntactically match WL-001. A strict self-hosting reading would require excepting all such findings through the governance model.

**Verdict on item 6:** CONCERN -- Self-hosting test infrastructure exists and is exercised at both L1 and L3, but the gate does not enforce zero unexcepted findings. This is a gap relative to the spec's strict reading, though the tooling-project context provides reasonable mitigation.

---

## Summary of Findings

| Assessment Item | Result | Conformance Level |
|---|---|---|
| 1. Living pattern catalogue (S7 MUST) | FAIL | Not implemented; conformance blocker |
| 2. Governance profile compliance (S14.3.2 Lite) | CONCERN | Substantially met; missing `wardline.governanceProfile` in SARIF |
| 3. Control law reporting (S9.5) | FAIL | Not implemented; no `wardline.controlLaw` in SARIF |
| 4. UNCONDITIONAL cell protection | PASS | Immutable matrix + load-time exception rejection + narrow-only merge |
| 5. Severity override constraints | PASS | Narrow-only invariant enforced in overlay merge |
| 6. Self-hosting gate (S10) | CONCERN | Infrastructure exists; gate does not enforce zero unexcepted findings |

### Key files examined:

- `/home/john/wardline/src/wardline/core/matrix.py` -- Severity matrix (immutable, 72 cells)
- `/home/john/wardline/src/wardline/core/severity.py` -- Enums (Severity, Exceptionability, RuleId)
- `/home/john/wardline/src/wardline/scanner/sarif.py` -- SARIF output (missing controlLaw, governanceProfile)
- `/home/john/wardline/src/wardline/manifest/regime.py` -- Regime status (hardcoded governance_profile)
- `/home/john/wardline/src/wardline/manifest/exceptions.py` -- UNCONDITIONAL rejection at load time
- `/home/john/wardline/src/wardline/manifest/merge.py` -- Narrow-only overlay enforcement
- `/home/john/wardline/wardline.toml` -- Scanner config (no governance_profile field)
- `/home/john/wardline/.github/CODEOWNERS` -- Governance artefact protection
- `/home/john/wardline/tests/integration/test_self_hosting_scan.py` -- Self-hosting gate tests

---

## Verdict: CONCERN

The implementation correctly enforces the hardest structural requirements (UNCONDITIONAL cell immutability, narrow-only severity overrides) and substantially meets Lite governance requirements. However, two normative MUST requirements are unimplemented:

1. **Living pattern catalogue (S7 MUST):** No semantic equivalent tracking exists for any rule. This is a conformance blocker for Wardline-Core profile.
2. **Control law reporting (S9.5):** `wardline.controlLaw` is absent from SARIF output, making formal assessment impossible.

Additionally, `wardline.governanceProfile` is absent from SARIF output (S14.3.2 MUST), and the self-hosting gate does not enforce the spec's strict requirement of zero unexcepted findings.

The two FAIL items prevent a clean conformance claim. The CONCERN items are remediable with bounded effort. Overall assessment: the enforcement core is sound, but the governance reporting surface has gaps that must be addressed before claiming Wardline-Core conformance.
