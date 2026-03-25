### 2. The problem a Wardline solves

There is a structural gap between what automated tooling checks and what high-stakes code requires. The standard assurance stack — linters, type checkers, SAST, DAST, unit tests, conventional peer review — verifies *syntactic* and *conventional* correctness: Does the code parse? Does it conform to style rules? Are types consistent? Do tests pass? These checks are necessary but insufficient. They cannot determine whether a `.get()` default is institutionally appropriate, whether an exception handler preserves the audit trail, or whether data crossing a trust boundary has been validated.

Agent-generated code exploits this gap systematically. Agents produce code that follows established good practice — defensive programming, graceful error handling, sensible defaults — applied without contextual judgement. The patterns are individually correct and collectively dangerous. A `.get("security_classification", "OFFICIAL")` is syntactically identical to `.get("city", "Sydney")`. The first silently downgrades a document's security classification; the second provides a location default that may be harmless in many contexts. No tool in the standard assurance stack distinguishes them, because the distinction is *semantic*: it depends on what the field means in the application's institutional context, not on how the code is structured. Without a wardline, both patterns look identical to tooling. With a wardline, the distinction becomes enforceable — the framework makes it possible to declare which contexts prohibit fallback defaults and which permit them.

The wardline makes the invisible visible. By declaring that a particular data path carries Tier 1 authority and that fallback defaults are prohibited in that context, the application converts tacit institutional knowledge into a machine-readable constraint. The enforcement tool no longer needs to infer context — the wardline supplies it.

**What is and is not novel here.** The individual pattern rules (WL-001 through WL-006) are expressible as custom rules in existing SAST frameworks — Semgrep, CodeQL, Error Prone, or equivalent. Any team with SAST experience could write these rules. The contribution is not the detection primitives but the governance topology that surrounds them: the severity matrix that varies enforcement by declared semantic context, the exceptionability model that distinguishes project invariants from governable overrides, the taint lattice that tracks data authority across boundaries, the fingerprint baseline that makes governance erosion visible, and the institutional integration that connects enforcement to organisational policy. Well-understood SAST capability, freshly composed into a governance-aware framework — that is the claim.

**Why now.** The emergence of a semantic boundary layer fits a longer progression in software abstraction: machine operations gave way to source code (compilers), source code gave way to frameworks and modules (reuse), frameworks gave way to infrastructure-as-code (deployment automation). Each step moved human effort into a layer where leverage is greater, enabled by the layer below becoming cheap enough to automate. The next layer is policy and boundary as code — machine-readable encodings of trust semantics, data classification, boundary contracts, failure posture, evidence requirements, and governance rules. This layer is emerging now because AI-assisted development is making implementation cheap enough that the bottleneck shifts from code production to semantic intent. Once implementation becomes a compilation target, the scarce thing is no longer code production. It is semantic intent, risk posture, and institutional constraint. A wardline is an attempt to encode that scarce layer.

**The capacity baseline.** Human review of LLM-generated code at scale has already failed as a control. Teams are shipping code they have not meaningfully reviewed because volume exceeds capacity. The wardline is not adding governance burden to a team with spare review capacity — it is providing structured triage infrastructure for a review process that is already overwhelmed. The correct baseline comparison is not "wardline governance overhead versus functioning review" but "wardline governance overhead versus unmitigated semantic risk from unreviewed code." The governance model's overhead should be evaluated against this baseline.

Wardline addresses the semantic-boundary gap; it does not address all 13 ACF failure modes. The following table maps wardline coverage to the ACF taxonomy:

| ACF Entry | Wardline Coverage [^groups] |
|-----------|------------------|
| ACF-S1 (Competence Spoofing) | WL-001 (member access with fallback default) |
| ACF-S2 (Hallucinated Field Access) | WL-002 (existence-checking as structural gate); type system enforcement (§8.2) [^acf-s2] |
| ACF-S3 (Structural Identity Spoofing) | WL-002 (catches existence-checking structural gates — e.g., `hasattr()`/`in` in Python, `Map.containsKey()` in Java — the S3 surface), WL-006 (catches runtime type-checking on internal data — a signal of structural doubt that may indicate S3-adjacent problems) [^acf-s3] |
| ACF-T1 (Authority Tier Conflation) | Taint analysis (tier-flow enforcement between declared boundaries) |
| ACF-T2 (Silent Coercion) | WL-001 (defaults as implicit coercion) [^acf-t2] |
| ACF-R1 (Audit Trail Destruction) | WL-003, WL-004, WL-005 (exception handling rules) |
| ACF-R2 (Partial Completion) | WL-005, Group 2 audit primacy enforcement, Group 9 (atomicity and compensatable operation annotations) |
| ACF-R3 (Verification Displacement) | Not directly addressable by pattern rules — wardline coverage is indirect through test structure analysis (mock provenance, factory bypass detection) |
| ACF-I1/I2 (Information Disclosure) | Groups 8 and 11 (secret handling, data sensitivity); WL-003/WL-004 secondary [^acf-i] |
| ACF-D1/D2 (Review Capacity) | Not addressable — process threats |
| ACF-E1 (Implicit Privilege Grant) | Taint analysis (tier-flow enforcement) |
| ACF-E2 (Unvalidated Delegation) | Group 14 access/attribution enforcement, taint analysis (tier-flow enforcement) [^acf-e2] |

[^groups]: "Group N" references refer to the decorator/annotation vocabulary groups defined in Part II-A §A.4 (Python) and Part II-B §B.4 (Java).

[^acf-s3]: WL-002 is the primary S3 rule — it detects existence-checking patterns (e.g., `hasattr()` in Python, `Map.containsKey()` in Java) that substitute structural probing for proper type identity. WL-006 provides secondary coverage: runtime type-checking (e.g., `isinstance()` in Python, `instanceof` in Java) on data the wardline classifies as internal suggests the code does not trust the type system's guarantees, which may indicate an S3-adjacent structural identity problem. WL-006 is not the S3 fix (proper type identity via the language's type system is the fix — see the language binding's type-system enforcement section); it is a signal that the codebase may harbour S3-class issues.

[^acf-s2]: WL-002 catches concealment of hallucinated access via existence-checking patterns (e.g., `hasattr()` in Python, `Map.containsKey()` in Java). Type system enforcement catches the hallucinated access directly where type annotations are present — a misspelled field produces a type error.

[^acf-t2]: Covers default-based coercion only. Broader coercion surface — type coercion (`float()` hiding precision loss), encoding coercion (locale-dependent string operations), format coercion (date parsing with assumed timezone) — is not addressed by the current pattern rule set. A future WL rule targeting type coercion on tier-classified data would close this gap.

[^acf-i]: Group 8 provides taint tracking of SECRET-tagged values through logging, error-message, and persistence paths. Group 11 provides PII and classified data taint tracking. Both use the same taint propagation engine as authority-tier tracking but with sensitivity-specific taint types. Pattern rules WL-003/WL-004 provide secondary coverage via error handler detection.

[^acf-e2]: Authorisation-check-before-action within the annotated codebase. Single-process scope: delegation to subprocesses, external services, or dynamically loaded modules across process boundaries is outside enforcement scope and requires separate governance controls.
