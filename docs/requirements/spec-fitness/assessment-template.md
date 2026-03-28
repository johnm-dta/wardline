# Spec Fitness Assessment Template

Use this worksheet when assessing the current repo against the baseline in this folder.

## Status values

- `pass`: implemented and evidenced
- `partial`: some support exists, but the full contract is incomplete
- `fail`: absent, contradicts the spec, or produces incorrect behavior
- `not_assessed`: no evidence gathered yet

## Framework Core (17 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-CORE-001 | Canonical taint-state vocabulary | `not_assessed` |  |  |
| WL-FIT-CORE-002 | Taint join algebra | `not_assessed` |  |  |
| WL-FIT-CORE-003 | Known-plus-unknown merges collapse conservatively | `not_assessed` |  |  |
| WL-FIT-CORE-004 | Tier-to-taint mapping is explicit | `not_assessed` |  |  |
| WL-FIT-CORE-005 | Severity matrix is total for implemented rule-state cells | `not_assessed` |  |  |
| WL-FIT-CORE-006 | Transition semantics prevent illegal skip-promotions | `not_assessed` |  |  |
| WL-FIT-CORE-007 | Restoration claims are evidence-bounded | `not_assessed` |  |  |
| WL-FIT-CORE-008 | Effective states are a closed set | `not_assessed` |  |  |
| WL-FIT-CORE-009 | Token interpretation is not narrowed | `not_assessed` |  |  |
| WL-FIT-CORE-010 | Join table is normative and must not be short-circuited | `not_assessed` |  |  |
| WL-FIT-CORE-011 | Dependency taint compound call fallback | `not_assessed` |  |  |
| WL-FIT-CORE-012 | Annotation vocabulary expressiveness (17 groups) | `not_assessed` |  |  |
| WL-FIT-CORE-013 | Serialisation sheds direct authority | `not_assessed` |  |  |
| WL-FIT-CORE-014 | Tier assignment is not contagious | `not_assessed` |  |  |
| WL-FIT-CORE-015 | Cross-language taint resets to UNKNOWN_RAW | `not_assessed` |  |  |
| WL-FIT-CORE-016 | Taint analysis scoped to explicit flows | `not_assessed` |  |  |
| WL-FIT-CORE-017 | Dependency taint defaults for undeclared functions | `not_assessed` |  |  |

## Manifest & Governance (19 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-MAN-001 | Root manifest is schema-validated before use | `not_assessed` |  |  |
| WL-FIT-MAN-002 | Overlay location and scope are coherent | `not_assessed` |  |  |
| WL-FIT-MAN-003 | Overlays may narrow but must not widen | `not_assessed` |  |  |
| WL-FIT-MAN-004 | Tier 2 boundaries declare validation scope | `not_assessed` |  |  |
| WL-FIT-MAN-005 | Contract identity is stable and name-based | `not_assessed` |  |  |
| WL-FIT-MAN-006 | Optional-by-contract defaults are governed | `not_assessed` |  |  |
| WL-FIT-MAN-007 | Ratification age is enforceable | `not_assessed` |  |  |
| WL-FIT-MAN-008 | Governance profile is explicit | `not_assessed` |  |  |
| WL-FIT-MAN-009 | Governance artefacts are path-protected | `not_assessed` |  |  |
| WL-FIT-MAN-010 | Annotation change tracking matches declared governance profile | `not_assessed` |  |  |
| WL-FIT-MAN-011 | Temporal separation posture is declared and assessable | `not_assessed` |  |  |
| WL-FIT-MAN-012 | Manifest coherence checks cover five conditions | `not_assessed` |  |  |
| WL-FIT-MAN-013 | Agent-authored governance changes are detectable | `not_assessed` |  |  |
| WL-FIT-MAN-014 | YAML string identifiers are quoted | `not_assessed` |  |  |
| WL-FIT-MAN-015 | Delegation policy governs overlay exception authority | `not_assessed` |  |  |
| WL-FIT-MAN-016 | Module-tier mappings assign default taint to unannotated code | `not_assessed` |  |  |
| WL-FIT-MAN-017 | Incompatible overlay declarations are rejected | `not_assessed` |  |  |
| WL-FIT-MAN-018 | Manifest metadata supports ratification and review | `not_assessed` |  |  |
| WL-FIT-MAN-019 | Root manifest MUST NOT alter UNCONDITIONAL cells | `not_assessed` |  |  |

## Scanner Conformance (20 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-SCAN-001 | Implemented rule set is declared | `not_assessed` |  |  |
| WL-FIT-SCAN-002 | Pattern and structural rules are enforced by tests | `not_assessed` |  |  |
| WL-FIT-SCAN-003 | Two-hop taint and delegated validation are assessable | `not_assessed` |  |  |
| WL-FIT-SCAN-004 | SARIF output carries the required Wardline property bags | `not_assessed` |  |  |
| WL-FIT-SCAN-005 | Precision and recall are measured per cell | `not_assessed` |  |  |
| WL-FIT-SCAN-006 | Corpus exists for claimed coverage | `not_assessed` |  |  |
| WL-FIT-SCAN-007 | Self-hosting gate is substantive | `not_assessed` |  |  |
| WL-FIT-SCAN-008 | Manifest-validation responsibility and conformance surface are documented honestly | `not_assessed` |  |  |
| WL-FIT-SCAN-009 | Living pattern catalogue with version-tracked semantic equivalents | `not_assessed` |  |  |
| WL-FIT-SCAN-010 | Taint propagation correctness (verification property 6) | `not_assessed` |  |  |
| WL-FIT-SCAN-011 | Corpus independence requirements | `not_assessed` |  |  |
| WL-FIT-SCAN-012 | Rejection path definition is precise | `not_assessed` |  |  |
| WL-FIT-SCAN-013 | WL-001 optional-field suppression follows three conditions | `not_assessed` |  |  |
| WL-FIT-SCAN-014 | Binding matrix deviations are narrowing-only | `not_assessed` |  |  |
| WL-FIT-SCAN-015 | Group 2 audit-primacy ordering verification | `not_assessed` |  |  |
| WL-FIT-SCAN-016 | Group 5 schema contract field-completeness verification | `not_assessed` |  |  |
| WL-FIT-SCAN-017 | Group 12 determinism scope verification | `not_assessed` |  |  |
| WL-FIT-SCAN-018 | Specimen schema and fragment requirements | `not_assessed` |  |  |
| WL-FIT-SCAN-019 | Minimum adversarial and suppression interaction specimens | `not_assessed` |  |  |
| WL-FIT-SCAN-020 | Group 13 concurrency enforcement scope is documented | `not_assessed` |  |  |

## Python Binding (12 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-PY-001 | Decorator discovery is AST-based | `not_assessed` |  |  |
| WL-FIT-PY-002 | `schema_default()` is recognised as the governed default marker | `not_assessed` |  |  |
| WL-FIT-PY-003 | Mandatory result-level SARIF properties are emitted | `not_assessed` |  |  |
| WL-FIT-PY-004 | Decorator composition semantics are honoured | `not_assessed` |  |  |
| WL-FIT-PY-005 | Unresolvable third-party delegation is handled conservatively | `not_assessed` |  |  |
| WL-FIT-PY-006 | Implemented rules and binding corpus are declared | `not_assessed` |  |  |
| WL-FIT-PY-007 | Verification mode exists and is deterministic | `not_assessed` |  |  |
| WL-FIT-PY-008 | Mandatory run-level SARIF properties are emitted | `not_assessed` |  |  |
| WL-FIT-PY-009 | Manifest is consumed and validated before findings | `not_assessed` |  |  |
| WL-FIT-PY-010 | Contradictory decorator combinations are detected | `not_assessed` |  |  |
| WL-FIT-PY-011 | Error handling and exit codes follow binding contract | `not_assessed` |  |  |
| WL-FIT-PY-012 | Analysis level is emitted per finding | `not_assessed` |  |  |

## Enforcement Layers (12 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-ENF-001 | Static analysis detects pattern rules WL-001 through WL-006 | `not_assessed` |  |  |
| WL-FIT-ENF-002 | Structural verification WL-007 on all boundary types | `not_assessed` |  |  |
| WL-FIT-ENF-003 | Validation ordering WL-008 is enforced | `not_assessed` |  |  |
| WL-FIT-ENF-004 | Taint flow tracing minimum scope | `not_assessed` |  |  |
| WL-FIT-ENF-005 | SARIF output is deterministic and v2.1.0 compliant | `not_assessed` |  |  |
| WL-FIT-ENF-006 | join_fuse vs join_product distinction | `not_assessed` |  |  |
| WL-FIT-ENF-007 | ACF coverage claims require taint tracking | `not_assessed` |  |  |
| WL-FIT-ENF-008 | Interprocedural analysis (SHOULD) | `not_assessed` |  |  |
| WL-FIT-ENF-009 | Incremental analysis (SHOULD) | `not_assessed` |  |  |
| WL-FIT-ENF-010 | Pre-generation context projection content | `not_assessed` |  |  |
| WL-FIT-ENF-011 | Runtime structural enforcement (SHOULD) | `not_assessed` |  |  |
| WL-FIT-ENF-012 | Type system tier metadata (SHOULD) | `not_assessed` |  |  |

## Governance Operations (16 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-GOV-001 | Exceptionability classes are enforced | `not_assessed` |  |  |
| WL-FIT-GOV-002 | Branch protection CI gates | `not_assessed` |  |  |
| WL-FIT-GOV-003 | Fingerprint baseline uses canonical hashing | `not_assessed` |  |  |
| WL-FIT-GOV-004 | Fingerprint baseline reports annotation coverage | `not_assessed` |  |  |
| WL-FIT-GOV-005 | Governance audit logging | `not_assessed` |  |  |
| WL-FIT-GOV-006 | Exception recurrence tracking | `not_assessed` |  |  |
| WL-FIT-GOV-007 | Expedited governance ratio is computed and reported | `not_assessed` |  |  |
| WL-FIT-GOV-008 | Control law three-state model | `not_assessed` |  |  |
| WL-FIT-GOV-009 | Retrospective scan after degraded law | `not_assessed` |  |  |
| WL-FIT-GOV-010 | Governance artefact exclusion during direct law | `not_assessed` |  |  |
| WL-FIT-GOV-011 | Manifest threat model anomaly detection | `not_assessed` |  |  |
| WL-FIT-GOV-012 | Exception age management | `not_assessed` |  |  |
| WL-FIT-GOV-013 | Policy vs enforcement artefact distinction | `not_assessed` |  |  |
| WL-FIT-GOV-014 | Supplementary group exceptionability is binding-defined | `not_assessed` |  |  |
| WL-FIT-GOV-015 | Governance audit retention | `not_assessed` |  |  |
| WL-FIT-GOV-016 | Provenance justification for trust escalation | `not_assessed` |  |  |

## Conformance Profiles (10 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-CONF-001 | Ten conformance criteria are addressable | `not_assessed` |  |  |
| WL-FIT-CONF-002 | Enforcement profile is declared | `not_assessed` |  |  |
| WL-FIT-CONF-003 | Governance profile is declared and assessable | `not_assessed` |  |  |
| WL-FIT-CONF-004 | Enforcement regime is documented | `not_assessed` |  |  |
| WL-FIT-CONF-005 | Supplementary group enforcement scope is documented | `not_assessed` |  |  |
| WL-FIT-CONF-006 | Assessment procedure is supportable | `not_assessed` |  |  |
| WL-FIT-CONF-007 | Graduation path from Lite to Assurance | `not_assessed` |  |  |
| WL-FIT-CONF-008 | Precision and recall floors per cell | `not_assessed` |  |  |
| WL-FIT-CONF-009 | Enforcement regime composition rules | `not_assessed` |  |  |
| WL-FIT-CONF-010 | Lite governance checklist is verifiable | `not_assessed` |  |  |

## Summary Metrics

| Category | Total | Pass | Partial | Fail | Not Assessed |
|---|---|---|---|---|---|
| Framework Core | 17 |  |  |  |  |
| Manifest & Governance | 19 |  |  |  |  |
| Scanner Conformance | 20 |  |  |  |  |
| Python Binding | 12 |  |  |  |  |
| Enforcement Layers | 12 |  |  |  |  |
| Governance Operations | 16 |  |  |  |  |
| Conformance Profiles | 10 |  |  |  |  |
| **Total** | **106** |  |  |  |  |

Count of `fail` requirements that block an honest conformance claim: ___
