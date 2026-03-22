# Filigree Population Plan

**Date:** 2026-03-22
**Purpose:** Complete specification of all filigree issues to create, with types, fields, labels, and dependencies. Review before executing.

---

## 1. Label Vocabulary (locked)

### Phase Labels
`phase:0` `phase:1` `phase:2` `phase:3` `phase:4` `phase:5` `phase:6`

### Subsystem Labels
`subsystem:core` `subsystem:runtime` `subsystem:decorators` `subsystem:manifest` `subsystem:scanner` `subsystem:cli` `subsystem:corpus` `subsystem:ci`

### Effort Labels
`effort:xs` `effort:s` `effort:m` `effort:l`

### Spec Labels (requirements only, documentation — no agent workflow filters by these)
`spec:authority-tiers` `spec:taint-model` `spec:pattern-rules` `spec:enforcement` `spec:governance` `spec:conformance`

---

## 2. Milestone + Phases

### Milestone

| Field | Value |
|-------|-------|
| Title | Wardline Python MVP |
| Priority | P1 |
| success_criteria | Self-hosting gate passes: wardline scans itself with zero ERROR findings, 80% decorator coverage on Tier 1/4 modules, corpus verify passes |
| scope_summary | Decorator library, AST scanner (5 rules), manifest system, governance CLI, corpus framework. Python 3.12+, single `wardline` package. |
| deliverables | `wardline` package installable via `uv pip install -e .`, `wardline scan` CLI command, `wardline.yaml` self-hosting manifest |

### Phases

| ID | Title | Seq | Entry Criteria | Exit Criteria |
|----|-------|-----|---------------|---------------|
| P0 | Foundation | 0 | None | Scaffold passes ruff/mypy/pytest. CODEOWNERS active. CI pipeline running. |
| P1 | Core Data Model | 1 | P0 complete | All enums, registry, taint lattice, severity matrix frozen. Tracer bullet validates patterns. |
| P2 | Decorator Library | 2 | P1 complete, registry freeze (T-1.8) validated | Factory + Group 1 + Group 2 decorators pass all tests. |
| P3 | Manifest System | 3 | P1 enums available | Loader, discovery, merge, coherence checks all functional. Governance anomaly signals fire. |
| P4 | AST Scanner | 4 | P1 frozen, P3 loader available | 5 rules implemented. ScanEngine orchestrates end-to-end. SARIF output validates. Integration checkpoint passes. |
| P5 | CLI | 5 | P4 engine available, integration checkpoint passes | All 5 CLI commands work. Exit codes correct. Registry sync runs at startup. |
| P6 | Corpus + Self-Hosting | 6 | P4 rules + P5 CLI available | Corpus verify passes. Scanner scans itself cleanly. Baselines committed. CI green. |

---

## 3. Work Packages (46 total)

Format: `ID | Title | Phase | Deps (by ID) | Labels | Priority | Acceptance Criteria`

### Phase 0 — Foundation

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-0.1 | Project Scaffolding | — | `phase:0 subsystem:ci effort:m` | P1 | `uv run pytest` passes. `ruff check src/` passes. `mypy src/` passes. CI grep for unsafe `yaml.load(` in place. |
| T-0.2 | Self-Hosting Manifest Design | — | `phase:0 subsystem:manifest effort:s` | P2 | Every `src/wardline/` sub-package has a tier assignment with rationale. Distribution sketch confirms 60% threshold. |
| T-0.3 | Initial CODEOWNERS + CI Pipeline | T-0.1 | `phase:0 subsystem:ci effort:s` | P1 | CODEOWNERS syntax valid, protects `wardline.yaml`, `wardline.toml`, `corpus/`, `**/wardline.overlay.yaml`. CI runs ruff/mypy/pytest on push. |

### Phase 1 — Core Data Model

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-1.1 | Enums and Constants | T-0.1 | `phase:1 subsystem:core effort:s` | P1 | All enums constructed. Serialisation round-trip passes. `json.dumps` correct for IntEnum and StrEnum. All pseudo-rule-IDs in RuleId. |
| T-1.2 | Canonical Decorator Registry | T-1.1, T-1.3 | `phase:1 subsystem:core effort:s` | P1 | Registry entries frozen via MappingProxyType. All Group 1+2 names registered. |
| T-1.3 | Taint Join Lattice | T-1.1 | `phase:1 subsystem:core effort:s` | P1 | 64 ordered pairs tested. MIXED_RAW absorbing. Associativity spot-checked. Idempotency verified. |
| T-1.4 | Severity Matrix | T-1.1 | `phase:1 subsystem:core effort:s` | P1 | 72 cells verified against independent fixture. KeyError on invalid combos. |
| T-1.5 | Runtime: Type Markers | T-1.1 | `phase:1 subsystem:runtime effort:xs` | P3 | Tier1-Tier4 produce valid Annotated types. FailFast usable as annotation. |
| T-1.6 | Runtime: AuthoritativeField | T-1.1 | `phase:1 subsystem:runtime effort:xs` | P3 | Descriptor tests pass including known-residual bypass test. |
| T-1.7 | Runtime: WardlineBase | T-1.2 | `phase:1 subsystem:runtime effort:s` | P2 | Cooperates with ABCMeta. Both `__init_subclass__` hooks fire. Super ordering tested including negative test (calling `super()` after wardline checks breaks cooperative chaining). |
| T-1.8 | Tracer Bullet | T-1.1, T-1.2, T-1.4 | `phase:1 subsystem:scanner effort:m` | P1 | Spike runs e2e. SARIF validates. Registry lookup works. RuleBase pattern proven. All 4 validation points confirmed. Spike deleted at T-4.1 start. |

### Phase 2 — Decorator Library

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-2.1 | Decorator Factory | T-1.2, T-1.8 | `phase:2 subsystem:decorators effort:m` | P1 | Factory passes all tests. Registry enforcement blocks unregistered attrs. Severed `__wrapped__` chain logs WARNING. `_wardline_groups` copy-on-accumulate verified. |
| T-2.2 | Group 1 Decorators | T-2.1 | `phase:2 subsystem:decorators effort:s` | P1 | All 7 Group 1 decorators set correct attributes. |
| T-2.3 | Group 2 + schema_default | T-2.1 | `phase:2 subsystem:decorators effort:xs` | P2 | `@audit_critical` and `schema_default` exist and pass tests. |

### Phase 3 — Manifest System

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-3.1 | JSON Schemas | T-1.1 | `phase:3 subsystem:manifest effort:s` | P1 | 5 schemas valid JSON Schema. `$id` includes version. `additionalProperties: false`. Schema structural validity verified by test suite. |
| T-3.2 | Manifest Data Models | T-1.1 | `phase:3 subsystem:manifest effort:s` | P1 | All models construct correctly and are immutable. `ScannerConfig.from_toml()` uses binary mode (`'rb'`) as required by `tomllib`, handles normalisation. |
| T-3.3 | YAML Loader + Alias Limiter | T-3.1, T-3.2 | `phase:3 subsystem:manifest effort:m` | P1 | Loader handles all paths. Alias limiter raises on bomb. Coercion tests pass. Exit code 2 for alias bomb and 1MB limit. `$id` mismatch structured error. |
| T-3.4 | Manifest + Overlay Discovery | T-3.3 | `phase:3 subsystem:manifest effort:m` | P1 | All path/symlink edge cases handled. Symlink cycle logs WARNING. Secure overlay default enforced. Undeclared overlay exits 2. |
| T-3.5 | Overlay Merge | T-3.2 | `phase:3 subsystem:manifest effort:s` | P2 | Narrow-only passes. Widen raises with actionable message. Severity narrowing allowed with GOVERNANCE INFO. |
| T-3.6 | Coherence: Annotations + Boundaries | T-3.2, T-3.4, T-1.2 | `phase:3 subsystem:manifest effort:s` | P2 | Orphaned annotation and undeclared boundary checks fire correctly. |
| T-3.7 | Coherence: Governance Signals | T-3.6 | `phase:3 subsystem:manifest effort:m` | P1 | All governance signals fire. Threshold boundary test passes. Baseline comparison works. `agent_originated: null` WARNING fires. `max_exception_duration_days` expiry detection fires. First-scan INFO fires. |

### Phase 4 — AST Scanner

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-4.1 | Scanner Data Models | T-1.1, T-1.8 | `phase:4 subsystem:scanner effort:s` | P1 | Finding and ScanContext frozen. Taint map deeply frozen via MappingProxyType. |
| T-4.2 | RuleBase Abstract Class | T-4.1 | `phase:4 subsystem:scanner effort:s` | P1 | (a) Override of `visit_FunctionDef` in subclass raises TypeError at class definition time via `__init_subclass__`. (b) Missing `visit_function` raises TypeError at instantiation via ABC. Confirmed not from `@typing.final` (static-only). |
| T-4.3 | ScanEngine Orchestrator | T-4.1, T-4.2, T-3.3, T-3.4 | `phase:4 subsystem:scanner effort:m` | P1 | All error paths graceful. TOOL-ERROR findings for crashed rules. |
| T-4.4 | Decorator Discovery: Core | T-1.2, T-4.1 | `phase:4 subsystem:scanner effort:m` | P1 | Core import patterns discovered. TYPE_CHECKING imports excluded (both direct and qualified forms). |
| T-4.5 | Decorator Discovery: Edge Cases | T-4.4 | `phase:4 subsystem:scanner effort:s` | P2 | Six edge cases handled: (1) alias tracking, (2) star import WARNING, (3) dynamic import WARNING, (4) unresolved decorator → WARNING finding, (5) TYPE_CHECKING ignored, (6) nested function handling. |
| T-4.6 | Level 1 Taint Assignment | T-4.4, T-3.2 | `phase:4 subsystem:scanner effort:m` | P1 | All 3 taint sources assigned. Decorator > module_tiers > UNKNOWN_RAW precedence tested. Async functions tested. |
| T-4.7 | Rule PY-WL-001 | T-4.2, T-4.6 | `phase:4 subsystem:scanner effort:s` | P1 | Rule fires on positive patterns. `schema_default()` produces WARNING not silence. |
| T-4.8 | Rule PY-WL-002 | T-4.2, T-4.6 | `phase:4 subsystem:scanner effort:s` | P1 | Fires on 3-arg `getattr` only. |
| T-4.9 | Rule PY-WL-003 | T-4.2, T-4.6 | `phase:4 subsystem:scanner effort:s` | P1 | All existence-checking patterns detected. Negative match/case specimens confirm no over-firing. |
| T-4.10 | Rule PY-WL-004 | T-4.2, T-4.6 | `phase:4 subsystem:scanner effort:s` | P1 | Both ExceptHandler and TryStar broad patterns detected. |
| T-4.11 | Rule PY-WL-005 | T-4.2, T-4.6 | `phase:4 subsystem:scanner effort:s` | P1 | All silent handler patterns detected across both AST node types. |
| T-4.INT | Integration Checkpoint | T-4.3, T-4.7, T-4.6, T-3.3, T-3.4 | `phase:4 subsystem:scanner effort:s` | P1 | ScanEngine returns findings with correct keys, severity, taint, property bags on fixture project. |
| T-4.12 | Registry Sync Tests | T-2.1, T-4.4, T-1.7 | `phase:4 subsystem:scanner effort:s` | P1 | Bidirectional name check passes. Attribute-level check catches mismatches. Both paths validated. Strict-mode exit code tested. |
| T-4.13 | SARIF Output | T-4.1, T-1.1 | `phase:4 subsystem:scanner effort:m` | P1 | SARIF validates against schema. All property bags present. Determinism tests pass. manifestHash key-order-independence tested. |

### Phase 5 — CLI

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-5.1 | CLI Skeleton + Exit Codes | T-0.1 | `phase:5 subsystem:cli effort:m` | P1 | All 4 exit codes tested. Flag subset verified. Structured logging to stderr. Schema-invalid manifest exits 2. |
| T-5.2 | `wardline scan` | T-5.1, T-4.3, T-4.13, T-4.INT | `phase:5 subsystem:cli effort:l` | P1 | Full pipeline e2e. `--max-unknown-raw-percent` enforced. CLI flags override toml. Registry sync at startup (exit 2 without flag, GOVERNANCE with flag). Disabled rule GOVERNANCE signal. |
| T-5.3 | `wardline manifest validate/baseline` | T-5.1, T-3.3, T-3.5 | `phase:5 subsystem:cli effort:s` | P2 | Baseline files valid JSON. `--approve` required. Validate exits 0/1/2 correctly. |
| T-5.4 | `wardline corpus verify` | T-5.1, T-3.1, T-3.3, T-4.3 | `phase:5 subsystem:cli effort:m` | P1 | exec/eval mock test passes. Hash integrity enforced. Output says "Lite bootstrap: N specimens". Integration test against real fixture specimen passes. |
| T-5.5 | `wardline explain` | T-5.1, T-4.6, T-3.3 | `phase:5 subsystem:cli effort:s` | P2 | Shows taint resolution for all 3 categories. Verified by `test_explain.py`. |

### Phase 6 — Corpus + Self-Hosting

| ID | Title | Deps | Labels | Pri | Acceptance Criteria |
|----|-------|------|--------|-----|-------------------|
| T-6.1 | Corpus Skeleton | T-3.1 | `phase:6 subsystem:corpus effort:xs` | P2 | Directory structure exists. Template valid against schema. |
| T-6.2a | TN/KFN Draft Structure | T-6.1 | `phase:6 subsystem:corpus effort:s` | P2 | Draft specimens valid YAML. Templates validate against schema. |
| T-6.2b | TN/KFN Verification | T-6.2a, T-4.7, T-4.8, T-4.9, T-4.10, T-4.11, T-5.4 | `phase:6 subsystem:corpus effort:s` | P1 | All TN verified silent. All KFN verified not-detected at L1. Hashes match. `wardline corpus verify` passes. |
| T-6.3 | TP Specimens | T-6.1, T-4.7, T-4.8, T-4.9, T-4.10, T-4.11, T-5.4 | `phase:6 subsystem:corpus effort:m` | P1 | `wardline corpus verify` passes for full set. All 5 rules have at least one verified TP. |
| T-6.4a | Self-Hosting: Scan + Coverage | T-4.3, T-4.7, T-4.8, T-4.9, T-4.10, T-4.11, T-4.12, T-4.13, T-5.2, T-5.3, T-5.4, T-3.7, T-6.2b, T-6.3 | `phase:6 subsystem:ci effort:l` | P1 | Scanner scans itself cleanly. Coverage floor met (measured by script or `wardline explain` batch). Tier-distribution passes. `test_self_hosting_scan.py` passes. |
| T-6.4b | Self-Hosting: Baselines + CI | T-6.4a | `phase:6 subsystem:ci effort:m` | P1 | All baselines committed. CI green with 3 jobs. CODEOWNERS extended. Regression comparison distinguishes count-decrease from count-increase. |

---

## 4. Requirements (20 total)

Format: `ID | Title | Type | Spec | Blocked By (WPs) | Acceptance Criteria`

> **Note:** "Blocked By" is a dependency relationship created via `add_dependency`, not a schema field. Requirements cannot be verified until all blocking WPs are delivered.

### Security Requirements

| ID | Title | Type | Spec | Blocked By | Acceptance Criteria |
|----|-------|------|------|-----------|-------------------|
| REQ-SEC-01 | YAML alias bomb protection | constraint | `spec:enforcement` | T-3.3 | WardlineSafeLoader counts AliasEvent resolutions. Exceeding threshold raises YAMLError subclass. Exit code 2. Configurable via factory function with hard upper bound of 10000. |
| REQ-SEC-02 | No unsafe yaml.load() in codebase | constraint | `spec:enforcement` | T-0.1, T-0.3 | CI grep check fails on `yaml.load(` without `Loader=` on the same line. Accepts any SafeLoader subclass (not just literal `SafeLoader`). Runs on every push. Excludes `.venv/`. |
| REQ-SEC-03 | No exec/eval on corpus specimens | constraint | `spec:enforcement` | T-5.4 | `ast.parse()` only. Mock test for `exec`, `eval`, `compile` asserts none called. |
| REQ-SEC-04 | agent_originated provenance tracking | functional | `spec:governance` | T-3.7 | GOVERNANCE WARNING emitted for each exception entry with `agent_originated: null`. Test: 3 entries (true, false, null) — WARNING fires only for null. |
| REQ-SEC-05 | Exception duration enforcement | functional | `spec:governance` | T-3.7 | Exception where `expires - grant_date > max_exception_duration_days` fires GOVERNANCE WARNING. Default `max_exception_duration_days` defined in root manifest schema. Clock injection for test isolation. |
| REQ-SEC-06 | CODEOWNERS protects governance files | constraint | `spec:governance` | T-0.3, T-6.4b | Protected files: `wardline.yaml`, `wardline.toml`, `corpus/`, `**/wardline.overlay.yaml`, `wardline.manifest.baseline.json`, `wardline.perimeter.baseline.json`, SARIF regression baseline, vendored SARIF schema. Syntax validated via linter or test. |

### Data Model Requirements

| ID | Title | Type | Spec | Blocked By | Acceptance Criteria |
|----|-------|------|------|-----------|-------------------|
| REQ-DM-01 | Taint precedence invariant | functional | `spec:taint-model` | T-4.6, T-4.INT | Decorator taint > module_tiers > UNKNOWN_RAW. Tested with conflicting sources. Async functions included. |
| REQ-DM-02 | RuleId exhaustive typing | constraint | `spec:pattern-rules` | T-1.1 | All pseudo-rule-IDs are RuleId members. `Finding.rule_id` typed as `RuleId`. Round-trip test for each. All governance signal rule IDs included. |
| REQ-DM-03 | Registry immutability + sync | functional | `spec:enforcement` | T-1.2, T-4.12, T-5.2 | Registry entries frozen (MappingProxyType). Three-part bidirectional sync at scan startup: (a) every registry name in library exports, (b) every library export in registry, (c) attribute-level contract verified via stub decoration. Mismatch without `--allow-registry-mismatch` exits 2. |
| REQ-DM-04 | Taint lattice mathematical properties | constraint | `spec:taint-model` | T-1.3 | MIXED_RAW absorbing. Commutativity (64 pairs). Associativity (spot-checked on representative triples). Idempotency (all states). |
| REQ-DM-05 | Severity matrix independent verification | constraint | `spec:pattern-rules` | T-1.4 | 72 cells verified against fixture that does NOT import matrix module. |

### Enforcement Requirements

| ID | Title | Type | Spec | Blocked By | Acceptance Criteria |
|----|-------|------|------|-----------|-------------------|
| REQ-ENF-01 | Narrow-only overlay invariant | functional | `spec:authority-tiers` | T-3.5 | Tier relaxation rejected with `ManifestWidenError` (message identifies overlay file, field, values). Severity narrowing through overlay is permitted and emits GOVERNANCE INFO signal. |
| REQ-ENF-02 | Rule crash produces TOOL-ERROR | functional | `spec:enforcement` | T-4.3 | Rule exception caught. TOOL-ERROR finding in output. Scan continues. |
| REQ-ENF-03 | Disabled rule governance signal | functional | `spec:governance` | T-5.2 | GOVERNANCE WARNING for disabled rule appears as a SARIF finding (not log-only). GOVERNANCE ERROR for UNCONDITIONAL disablement. |
| REQ-ENF-04 | CLI enforcement-weakening flags produce audit trail | functional | `spec:governance` | T-5.2 | CLI flags that weaken enforcement thresholds MUST produce GOVERNANCE-level finding in SARIF output. Specifically: `--allow-registry-mismatch` and `--allow-permissive-distribution` each produce a GOVERNANCE finding. |

### Output Requirements

| ID | Title | Type | Spec | Blocked By | Acceptance Criteria |
|----|-------|------|------|-----------|-------------------|
| REQ-OUT-01 | SARIF schema validity | constraint | `spec:conformance` | T-4.13 | Output validates against vendored SARIF v2.1.0 schema. Required property bag keys: `wardline.rule`, `wardline.taintState`, `wardline.severity`, `wardline.exceptionability`, `wardline.analysisLevel` (per result); `propertyBagVersion`, `implementedRules`, `conformanceGaps`, `unknownRawFunctionCount`, `unresolvedDecoratorCount` (per run). |
| REQ-OUT-02 | SARIF determinism | non_functional | `spec:conformance` | T-4.13, T-6.4b | Byte-identical output on repeated runs (with `--verification-mode`). manifestHash key-order-independent. |

### Self-Hosting Requirements

| ID | Title | Type | Spec | Blocked By | Acceptance Criteria |
|----|-------|------|------|-----------|-------------------|
| REQ-SH-01 | Self-hosting scan correctness | functional | `spec:conformance` | T-6.4a | Scanner scans itself with zero ERROR findings (or documented exceptions). |
| REQ-SH-02 | Decorator coverage floor | functional | `spec:conformance` | T-6.4a | 80% decorator coverage on Tier 1/4 modules. Measured by `scripts/coverage_check.py` or `wardline explain` batch invocation — measurement tool committed and documented. |
| REQ-SH-03 | CI and baseline gate | functional | `spec:conformance` | T-6.4b | Baselines committed. CI green with 3 jobs. CODEOWNERS extended for baselines. Regression comparison distinguishes finding-count decrease from count-increase. |

---

## 5. WP → Requirement Linkage Map

Shows which WPs a requirement is `blocked_by` (created via `add_dependency`, not a field). Requirement can't be verified until all blocking WPs are delivered.

| Requirement | Blocked By WPs |
|------------|---------------|
| REQ-SEC-01 | T-3.3 |
| REQ-SEC-02 | T-0.1, T-0.3 |
| REQ-SEC-03 | T-5.4 |
| REQ-SEC-04 | T-3.7 |
| REQ-SEC-05 | T-3.7 |
| REQ-SEC-06 | T-0.3, T-6.4b |
| REQ-DM-01 | T-4.6, T-4.INT |
| REQ-DM-02 | T-1.1 |
| REQ-DM-03 | T-1.2, T-4.12, T-5.2 |
| REQ-DM-04 | T-1.3 |
| REQ-DM-05 | T-1.4 |
| REQ-ENF-01 | T-3.5 |
| REQ-ENF-02 | T-4.3 |
| REQ-ENF-03 | T-5.2 |
| REQ-ENF-04 | T-5.2 |
| REQ-OUT-01 | T-4.13 |
| REQ-OUT-02 | T-4.13, T-6.4b |
| REQ-SH-01 | T-6.4a |
| REQ-SH-02 | T-6.4a |
| REQ-SH-03 | T-6.4b |

---

## 6. Cross-Phase Dependency Graph

All WP-to-WP dependencies, extracted from the Mermaid graph. Format: `Target ← blocked by Sources`.

### Phase 0
- T-0.3 ← T-0.1

### Phase 1
- T-1.1 ← T-0.1
- T-1.2 ← T-1.1, T-1.3
- T-1.3 ← T-1.1
- T-1.4 ← T-1.1
- T-1.5 ← T-1.1
- T-1.6 ← T-1.1
- T-1.7 ← T-1.2
- T-1.8 ← T-1.1, T-1.2, T-1.4

### Phase 2
- T-2.1 ← T-1.2, T-1.8
- T-2.2 ← T-2.1
- T-2.3 ← T-2.1

### Phase 3
- T-3.1 ← T-1.1
- T-3.2 ← T-1.1
- T-3.3 ← T-3.1, T-3.2
- T-3.4 ← T-3.3
- T-3.5 ← T-3.2
- T-3.6 ← T-3.2, T-3.4, T-1.2
- T-3.7 ← T-3.6

### Phase 4
- T-4.1 ← T-1.1, T-1.8
- T-4.2 ← T-4.1
- T-4.3 ← T-4.1, T-4.2, T-3.3, T-3.4
- T-4.4 ← T-1.2, T-4.1
- T-4.5 ← T-4.4
- T-4.6 ← T-4.4, T-3.2
- T-4.7 ← T-4.2, T-4.6
- T-4.8 ← T-4.2, T-4.6
- T-4.9 ← T-4.2, T-4.6
- T-4.10 ← T-4.2, T-4.6
- T-4.11 ← T-4.2, T-4.6
- T-4.INT ← T-4.3, T-4.7, T-4.6, T-3.3, T-3.4
- T-4.12 ← T-2.1, T-4.4, T-1.7
- T-4.13 ← T-4.1, T-1.1

### Phase 5
- T-5.1 ← T-0.1
- T-5.2 ← T-5.1, T-4.3, T-4.13, T-4.INT
- T-5.3 ← T-5.1, T-3.3, T-3.5
- T-5.4 ← T-5.1, T-3.1, T-3.3, T-4.3
- T-5.5 ← T-5.1, T-4.6, T-3.3

### Phase 6
- T-6.1 ← T-3.1
- T-6.2a ← T-6.1
- T-6.2b ← T-6.2a, T-4.7, T-4.8, T-4.9, T-4.10, T-4.11, T-5.4
- T-6.3 ← T-6.1, T-4.7, T-4.8, T-4.9, T-4.10, T-4.11, T-5.4
- T-6.4a ← T-4.3, T-4.7, T-4.8, T-4.9, T-4.10, T-4.11, T-4.12, T-4.13, T-5.2, T-5.3, T-5.4, T-3.7, T-6.2b, T-6.3
- T-6.4b ← T-6.4a

---

## 7. Release

| Field | Value |
|-------|-------|
| Title | Wardline v0.1.0 |
| Priority | P1 |
| Version | v0.1.0 (required before `frozen` transition) |
| Release Items | One per Phase (7 total), all starting as `queued` |

---

## 8. Creation Order

1. **Milestone** (1 issue)
2. **Phases** (7 issues, children of milestone)
3. **Work Packages** (46 issues, children of phases) — create ALL WPs first, then add all WP→WP dependencies in a second pass to avoid forward-reference failures
4. **Requirements** (20 issues, standalone) — then add REQ→WP dependencies via `add_dependency`
5. **Release** (1 issue — or update existing "Future" release, set `version: v0.1.0`)
6. **Release Items** (7 issues, children of release, one per phase)

**Total: 82 issues** (1 milestone + 7 phases + 46 WPs + 20 requirements + 1 release + 7 release items)

---

## 9. Verification Checklist

After creation, verify:
- [ ] `get_ready` shows exactly T-0.1 and T-0.2 (the only WPs with no upstream deps)
- [ ] `get_blocked` shows all WPs with upstream deps (including T-5.1 blocked by T-0.1)
- [ ] `get_plan <milestone>` renders the full tree with 7 phases and 46 WPs
- [ ] Requirements are blocked by their implementing WPs (19 requirements, all blocked)
- [ ] Labels filter correctly: `list_issues --label=phase:0` returns 3 WPs
- [ ] Closing T-0.1 unblocks T-1.1, T-0.3, T-5.1

---

## 10. Agent Workflow Conventions

### Requirement Verification Ownership

After delivering a WP, the implementing agent MUST:
1. Run `list_issues --type=requirement` and check for newly unblocked requirements
2. For single-blocker requirements that are now unblocked: verify against acceptance criteria and move to `verified` (requires setting `verification_method`)
3. For multi-blocker requirements: leave at `approved` until all blocking WPs are delivered

### `get_ready` Type Filtering

When looking for work, agents should filter by type:
- `get_ready` then filter for `work_package` type — this is the assignable unit
- Ignore `phase`, `milestone`, `requirement`, and `release_item` in ready output
- After claiming a WP, use `list_issues --type=step --parent=<WP-id>` for sub-task navigation

### Scheduling Note

T-0.3 (CODEOWNERS + CI pipeline) should complete before T-1.1 begins so CI is active from the first committed code. This is a scheduling preference, not a hard graph dependency — T-0.3 does not produce artifacts consumed by T-1.1.
