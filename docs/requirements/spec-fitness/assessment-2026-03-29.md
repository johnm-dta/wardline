# Spec Fitness Assessment — 2026-03-29

Assessed by 7 opus subagents against the corrected spec-fitness baseline.
All 106 requirements evaluated against current implementation state.

## Framework Core (17 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-CORE-001 | Canonical taint-state vocabulary | `pass` | `taints.py:8-23` TaintState(StrEnum) with all 8 tokens; `sarif.py:154` emits wardline.taintState; tests verify round-trip | Consistent across code, schemas, SARIF |
| WL-FIT-CORE-002 | Taint join algebra | `pass` | `taints.py:44-62` lookup-based join; `test_taints.py` exhaustive: idempotency, commutativity (64 pairs), absorbing element, associativity (512 triples) | All 4 algebraic properties verified exhaustively |
| WL-FIT-CORE-003 | Known-plus-unknown merges collapse conservatively | `pass` | `_JOIN_TABLE` only contains UNKNOWN-family internal joins; unlisted pairs → MIXED_RAW (line 62); `test_taints.py:104-113` explicit cross-family verification | Conservative collapse enforced by table structure |
| WL-FIT-CORE-004 | Tier-to-taint mapping is explicit | `pass` | `tiers.py:26-35` TAINT_TO_TIER MappingProxyType; runtime completeness check at :38-40; `test_taint_to_tier.py` per-entry + immutability tests | Explicit, complete, frozen, tested |
| WL-FIT-CORE-005 | Severity matrix is total for implemented rule-state cells | `pass` | `matrix.py:94-125` 9 rules × 8 states = 72 cells; runtime count check :136-143; independent test fixture `test_matrix.py:26-116` | Total for all implemented rules; independently verified |
| WL-FIT-CORE-006 | Transition semantics prevent illegal skip-promotions | `pass` | `loader.py:302-313` rejects to_tier=1 from any from_tier≠2; `test_loader.py:530-628` covers T4→T1, T3→T1 rejected, T2→T1 accepted, restoration exempted | Hard failure with clear error; thorough test coverage |
| WL-FIT-CORE-007 | Restoration claims are evidence-bounded | `pass` | `evidence.py:8-34` max_restorable_tier(); `function_level.py:268-315` emits RestorationOverclaim; `test_taint.py:628+` verification | Evidence-bounded at manifest and scanner levels |
| WL-FIT-CORE-008 | Effective states are a closed set | `pass` | TaintState is StrEnum (prevents subclassing); `test_taints.py:13-14` asserts len==8; runtime completeness checks in tiers.py and callgraph.py | Closed set enforced by enum type and assertions |
| WL-FIT-CORE-009 | Token interpretation is not narrowed | `pass` | No narrowing in code or comments; INTEGRAL used for all T1 contexts (integral_read, integral_writer, integral_construction) | Broad usage confirms no narrowing |
| WL-FIT-CORE-010 | Join table is normative and must not be short-circuited | `pass` | Explicit _JOIN_TABLE lookup; `test_taints.py:100` verifies join(INTEGRAL, ASSURED)==MIXED_RAW (trust-ordering would give INTEGRAL) | Lookup-based, specific cross-chain case tested |
| WL-FIT-CORE-011 | Dependency taint compound call fallback | `partial` | No dependency_taint mechanism exists; unresolved calls fall back via pessimistic floor in callgraph, not explicit UNKNOWN_RAW | No compound call resolution or dedicated fallback |
| WL-FIT-CORE-012 | Annotation vocabulary expressiveness (17 groups) | `partial` | `registry.py:51-203` covers 16 of 17 groups; Group 16 (data_flow) noted as "not yet implemented" | Core group gap: Group 16 missing |
| WL-FIT-CORE-013 | Serialisation sheds direct authority | `fail` | No serialization boundary handling in taint engine; json.dumps/pickle.loads inherit function taint without shedding | Not implemented |
| WL-FIT-CORE-014 | Tier assignment is not contagious | `pass` | `function_level.py:102-152` per-function assignment from decorators/module defaults; anchored functions immutable in callgraph propagation | Per-function, not inherited through call chain |
| WL-FIT-CORE-015 | Cross-language taint resets to UNKNOWN_RAW | `partial` | Structurally safe for mono-language; no manifest or scanner support for polyglot boundary declarations | No polyglot infrastructure |
| WL-FIT-CORE-016 | Taint analysis scoped to explicit flows | `partial` | Explicit flows covered via variable_level.py; implicit-flow evasion heuristic (SHOULD) not implemented | SHOULD-level heuristic absent |
| WL-FIT-CORE-017 | Dependency taint defaults for undeclared functions | `pass` | `function_level.py:368-369` fallback UNKNOWN_RAW for unannotated functions; `test_taint.py:184-204` tests both cases | MUST-level default implemented; SHOULD-level import validation absent |

## Manifest & Governance (19 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-MAN-001 | Root manifest is schema-validated before use | `pass` | `loader.py:148-159` calls _validate_schema() before constructing dataclass; errors raise ManifestLoadError | Hard error on invalid manifest |
| WL-FIT-MAN-002 | Overlay location and scope are coherent | `pass` | `resolve.py:57-66` checks overlay_for vs file location; mismatch raises GovernanceError | Scope/location coherence enforced |
| WL-FIT-MAN-003 | Overlays may narrow but must not widen | `pass` | `merge.py:108-119` raises ManifestWidenError on severity widening; `merge.py:141-156` raises on tier widening | Hard error, not warning |
| WL-FIT-MAN-004 | Tier 2 boundaries declare validation scope | `pass` | `coherence.py:661-703` check_validation_scope_presence; overlay.schema.json:58-87 defines validation_scope | Schema + coherence check enforce this |
| WL-FIT-MAN-005 | Contract identity is stable and name-based | `pass` | `models.py:194-199` ContractBinding with contract (name) and functions (bindings) as separate fields | Clean separation |
| WL-FIT-MAN-006 | Optional-by-contract defaults are governed | `pass` | `py_wl_001.py:200-270` governed vs ungoverned default detection; overlay.schema.json:108-119 defines optional_fields | Scanner verifies schema_default() against overlay |
| WL-FIT-MAN-007 | Ratification age is enforceable | `pass` | `regime.py:195-205` computes age and overdue; `regime_cmd.py:582-598` emits governance finding | Full lifecycle implemented |
| WL-FIT-MAN-008 | Governance profile is explicit | `pass` | wardline.schema.json:13-16 governance_profile enum; sarif.py:221,288 emits wardline.governanceProfile | Both manifest and SARIF carry profile |
| WL-FIT-MAN-009 | Governance artefacts are path-protected | `pass` | .github/CODEOWNERS covers wardline.yaml, wardline.toml, overlays, exceptions, fingerprints, baselines | All governance artefacts protected |
| WL-FIT-MAN-010 | Annotation change tracking matches declared governance profile | `pass` | fingerprint_cmd.py provides update/diff with policy/enforcement categorization; CODEOWNERS protects baseline | Full fingerprint mechanism with review protection |
| WL-FIT-MAN-011 | Temporal separation posture is declared and assessable | `pass` | wardline.yaml:16-23 declares temporal_separation with alternative; schema defines structure; regime_cmd checks | Lite alternative documented with rationale |
| WL-FIT-MAN-012 | Manifest coherence checks cover five conditions | `partial` | coherence.py implements all 5 checks; missing: Assurance-profile automatic gate enforcement (--gate is opt-in) | All 5 checks exist; profile-driven gating absent |
| WL-FIT-MAN-013 | Agent-authored governance changes are detectable | `partial` | models.py:40 agent_originated field; exception_cmds.py --agent-originated flag; coherence.py:327-355 flags unknown provenance | Declarative detection only; no automated VCS-level detection |
| WL-FIT-MAN-014 | YAML string identifiers are quoted | `fail` | JSON Schema cannot enforce YAML quoting; loader uses SafeLoader subject to implicit typing; no Norway-problem check | No mechanism to enforce quoted strings |
| WL-FIT-MAN-015 | Delegation policy governs overlay exception authority | `partial` | wardline.schema.json:105-130 defines delegation; UNCONDITIONAL included in authority enum (should be structurally excluded) | Delegation exists but UNCONDITIONAL not structurally undelegable |
| WL-FIT-MAN-016 | Module-tier mappings assign default taint to unannotated code | `pass` | wardline.schema.json:131-152 defines module_tiers; consumed by function_level.py for default assignment | Schema, model, and scanner all connected |
| WL-FIT-MAN-017 | Incompatible overlay declarations are rejected | `pass` | merge.py rejects widening with ManifestWidenError; resolve.py rejects scope mismatches and duplicates | Hard errors on all incompatible cases |
| WL-FIT-MAN-018 | Manifest metadata supports ratification and review | `pass` | wardline.schema.json:19-63 defines all 4 fields; regime.py computes age; regime_cmd emits governance findings | Full metadata with age computation |
| WL-FIT-MAN-019 | Root manifest MUST NOT alter UNCONDITIONAL cells | `partial` | exceptions.py:83-98 rejects exceptions targeting UNCONDITIONAL cells; merge.py does NOT check rule-override path | Exception register protected; rule-override merge path unprotected |

## Scanner Conformance (20 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-SCAN-001 | Implemented rule set is declared | `pass` | rules/__init__.py declares all 11 rules; sarif.py filters pseudo-rule IDs from implementedRules | Clean canonical vs pseudo-rule separation |
| WL-FIT-SCAN-002 | Pattern and structural rules are enforced by tests | `pass` | Test files exist for all 9 canonical rules (test_py_wl_001 through 009) plus SCN-021 and SUP-001 | Full test coverage for all claimed rules |
| WL-FIT-SCAN-003 | Two-hop taint and delegated validation are assessable | `pass` | test_taint.py (45 tests), test_engine_l3.py, test_rejection_path_convergence.py (2/3/4-hop), test_delegated_rejection.py | All required flow types tested |
| WL-FIT-SCAN-004 | SARIF output carries the required Wardline property bags | `pass` | sarif.py:151-166 result-level (5 mandatory keys); :278-323 run-level properties; integration tests verify | Both levels present and tested |
| WL-FIT-SCAN-005 | Precision and recall are measured per cell | `pass` | corpus_cmds.py:261-304 per-cell stats with TP/FP/TN/FN; floors computed from matrix; JSON report covers 72 cells | Many cells have <5 specimens (expected pre-v1.0) |
| WL-FIT-SCAN-006 | Corpus exists for claimed coverage | `pass` | 244 specimens across PY-WL-001-009; corpus_manifest.json; corpus verify CLI; adversarial directory (15 specimens) | Comprehensive with schema validation |
| WL-FIT-SCAN-007 | Self-hosting gate is substantive | `pass` | test_self_hosting_scan.py: per-rule baseline regression, SARIF validation, security property verification | Not just "it runs" — rule-level regression |
| WL-FIT-SCAN-008 | Manifest-validation responsibility documented honestly | `pass` | wardline-02-A-python-binding.md documents tool landscape, capability mapping, post-MVP rules acknowledged | Explicit tool-to-capability mapping |
| WL-FIT-SCAN-009 | Living pattern catalogue with version-tracked equivalents | `pass` | docs/spec/semantic-equivalents/ has versioned files for all 9 rules with detection status per pattern | Honest detection status per variant |
| WL-FIT-SCAN-010 | Taint propagation correctness (verification property 6) | `partial` | Corpus includes taint-flow specimens; L3 tested at engine level; taint module itself lacks isolated two-hop/container unit tests | Tested through corpus and engine, not isolated taint-module tests |
| WL-FIT-SCAN-011 | Corpus independence requirements | `partial` | corpus_manifest.json with hashes; corpus verify works; no separate publication, no spec-version binding, no whole-corpus hash | Infrastructure present; independence not yet achieved (pre-v1.0) |
| WL-FIT-SCAN-012 | Rejection path definition is precise | `pass` | rejection_path.py: Raise/Return only (assertions excluded); _is_constant_false() for dead branches; two-hop delegation | All classification types correctly handled |
| WL-FIT-SCAN-013 | WL-001 optional-field suppression follows three conditions | `pass` | py_wl_001.py:214-253 three-condition check; mismatch escalates to UNCONDITIONAL; corpus has 3 suppression-interaction specimens | Exact specimen triad required by spec |
| WL-FIT-SCAN-014 | Binding matrix deviations are narrowing-only | `pass` | One deviation documented: PY-WL-002 WARNING/RELAXED where framework has SUPPRESS (narrowing); matrix.py matches | Single documented narrowing-only deviation |
| WL-FIT-SCAN-015 | Group 2 audit-primacy ordering verification | `partial` | PY-WL-006 implements dominance analysis for success-path bypass; full path-sensitive ordering across all paths not implemented | Partial via PY-WL-006 and SUP-001 |
| WL-FIT-SCAN-016 | Group 5 schema contract field-completeness verification | `fail` | @all_fields_mapped decorator exists in registry; no scanner rule implements field-completeness verification | Declared but not enforced |
| WL-FIT-SCAN-017 | Group 12 determinism scope verification | `pass` | sup_001.py ban list: random.*, uuid4, datetime.now, etc.; _check_deterministic() scans function bodies | Direct non-deterministic calls detected |
| WL-FIT-SCAN-018 | Specimen schema and fragment requirements | `pass` | corpus-specimen.schema.json defines required fields; test_corpus_skeleton validates conformance | expected_severity/exceptionability optional in schema (minor gap) |
| WL-FIT-SCAN-019 | Minimum adversarial and suppression interaction specimens | `partial` | 9 AFP + 9 AFN (meets 8 minimum each); 3 suppression-interaction (meets minimum); naming convention gap in adversarial/ | Counts meet spec minimums |
| WL-FIT-SCAN-020 | Group 13 concurrency enforcement scope documented | `partial` | @ordered_after and @not_reentrant implemented; @thread_safe not implemented; minimum scope not explicitly documented | 2 of 3 declaration types enforced |

## Python Binding (12 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-PY-001 | Decorator discovery is AST-based | `pass` | discovery.py uses ast.parse(), ast.iter_child_nodes(), ast.walk() exclusively; no runtime introspection | Purely AST-based |
| WL-FIT-PY-002 | schema_default() recognised as suppression marker | `pass` | py_wl_001.py:131-149 detects schema_default(d.get(...)); :200-270 governed → SUPPRESS, ungoverned → ERROR | Full contract implemented |
| WL-FIT-PY-003 | Mandatory result-level SARIF properties | `pass` | sarif.py:151-161 emits all 5 mandatory keys: rule, taintState, severity, exceptionability, analysisLevel | Always present on every finding |
| WL-FIT-PY-004 | Decorator composition semantics honoured | `pass` | @int_data alone → UNKNOWN_RAW via fallback chain; @restoration_boundary uses evidence matrix | Implicit via taint assignment precedence |
| WL-FIT-PY-005 | Unresolvable third-party delegation handled conservatively | `pass` | py_wl_008.py:75-98 only credits delegation if FQN found in rejection_path_index; unknown → no credit → finding fires | Conservative by construction |
| WL-FIT-PY-006 | Implemented rules and corpus declared | `pass` | rules/__init__.py declares 11 rules; corpus specimens for PY-WL-001-009; sarif.py emits implementedRules | 244 specimens indexed |
| WL-FIT-PY-007 | Verification mode exists and is deterministic | `pass` | scan.py --verification-mode flag; sarif.py suppresses timestamps/commitRef; test_determinism.py byte-identical check | Integration tests verify byte-identical output |
| WL-FIT-PY-008 | Mandatory run-level SARIF properties | `pass` | sarif.py:278-323 emits inputHash, inputFiles, manifestHash, controlLaw, overlayHashes | All required run-level properties present |
| WL-FIT-PY-009 | Manifest consumed and validated before findings | `pass` | scan.py: _load_manifest() → loader.py validates via jsonschema; failure exits code 2 before scanning | Validation mandatory, precedes scanning |
| WL-FIT-PY-010 | Contradictory decorator combinations detected | `partial` | scn_021.py implements 32 pairs (28 of 29 spec pairs + 5 extra); missing: data_flow+external_boundary (data_flow not yet implemented) | 28/29 spec pairs covered |
| WL-FIT-PY-011 | Error handling and exit codes follow binding contract | `partial` | Exit codes 0/1/2/3 correct; invalid/missing manifest → code 2; T1 syntax error escalation NOT implemented (all syntax errors → WARNING) | Exit codes correct; tier-aware escalation absent |
| WL-FIT-PY-012 | Analysis level emitted per finding | `pass` | sarif.py:160 emits wardline.analysisLevel; rules set it explicitly (e.g., py_wl_001.py:194 analysis_level=1) | Every finding carries level |

## Enforcement Layers (12 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-ENF-001 | Static analysis detects WL-001 through WL-006 | `pass` | py_wl_001.py through py_wl_007.py implement all 6 framework pattern rules (WL-001 split into PY-WL-001/002) | All with tests and corpus |
| WL-FIT-ENF-002 | Structural verification WL-007 on all boundary types | `pass` | py_wl_008.py covers all 5 boundary types; two-hop delegation via _has_delegated_rejection | All boundary types + delegation |
| WL-FIT-ENF-003 | Validation ordering WL-008 enforced | `pass` | py_wl_009.py fires on semantic boundaries without shape evidence; combined boundaries excluded | Tested for all relevant states |
| WL-FIT-ENF-004 | Taint flow tracing minimum scope | `pass` | 3-level taint: L1 function, L2 variable, L3 callgraph; two-hop via rejection path expansion | Direct + two-hop satisfied |
| WL-FIT-ENF-005 | SARIF output deterministic and v2.1.0 | `pass` | SARIF v2.1.0 schema; deterministic sorting; verification mode strips non-deterministic fields; byte-identical tests | Full determinism |
| WL-FIT-ENF-006 | join_fuse vs join_product distinction | `partial` | All joins → MIXED_RAW (conservative fallback); no join_fuse/join_product distinction | SHOULD-level; conservative fallback is conformant |
| WL-FIT-ENF-007 | ACF coverage claims require taint tracking | `pass` | Taint tracking implemented (3-level); no ACF overclaims in SARIF output | Consistent |
| WL-FIT-ENF-008 | Interprocedural analysis (SHOULD) | `pass` | L3 callgraph propagation with SCC and fixed-point; two-hop rejection delegation | SHOULD satisfied |
| WL-FIT-ENF-009 | Incremental analysis (SHOULD) | `fail` | No incremental analysis; engine always scans all files; no --changed-only flag | SHOULD-level but entirely absent |
| WL-FIT-ENF-010 | Pre-generation context projection | `fail` | No projection implementation; no CLI command; no design docs | Advisory feature, not implemented |
| WL-FIT-ENF-011 | Runtime structural enforcement (SHOULD) | `partial` | TierStamped[T] wrapper, stamp_tier(), check_tier_boundary() exist; no subclass enforcement or serialization detection | SHOULD-level; tier stamping present, other mechanisms absent |
| WL-FIT-ENF-012 | Type system tier metadata (SHOULD) | `partial` | Tier1-Tier4 NewType wrappers with TIER_REGISTRY; no mypy plugin for deeper enforcement | SHOULD-level; basic types exist |

## Governance Operations (16 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-GOV-001 | Exceptionability classes enforced | `pass` | severity.py defines 4 classes; exceptions.py rejects UNCONDITIONAL at load; scanner re-checks at match | Double enforcement: load-time + match-time |
| WL-FIT-GOV-002 | Branch protection CI gates | `partial` | ci.yml defines self-hosting-scan job; not configured as required status check (GitHub settings concern) | Scan runs but doesn't gate merges |
| WL-FIT-GOV-003 | Fingerprint baseline uses canonical hashing | `pass` | fingerprint.py sorted decorators + attrs → SHA-256; deterministic regardless of declaration order | Canonical serialisation |
| WL-FIT-GOV-004 | Fingerprint baseline reports annotation coverage | `pass` | CoverageReport with annotated/total/ratio + tier1_unannotated enumeration; CLI outputs both human and JSON | Full coverage reporting |
| WL-FIT-GOV-005 | Governance audit logging | `partial` | SARIF carries governance metadata and findings; no discrete event log for all 7 required event types | State reported but no structured event trail |
| WL-FIT-GOV-006 | Exception recurrence tracking | `pass` | models.py recurrence_count; exception_cmds.py carries forward count; scanner escalates at count≥2 | Tracked on (rule, location) tuple |
| WL-FIT-GOV-007 | Expedited governance ratio computed and reported | `pass` | regime.py computes ratio; sarif.py emits wardline.expeditedExceptionRatio | Ratio computed and in SARIF |
| WL-FIT-GOV-008 | Control law three-state model | `partial` | SARIF wardline.controlLaw exists (defaults "normal"); no state machine, transition logic, or CLI for Alternate/Direct | Property exists; operational model absent |
| WL-FIT-GOV-009 | Retrospective scan after degraded law | `fail` | No implementation; no wardline.retroactiveScan property; no --retrospective flag | Entirely absent |
| WL-FIT-GOV-010 | Governance artefact exclusion during direct law | `partial` | CODEOWNERS protects always; no conditional enforcement tied to control law state | Always-on protection, not law-conditional |
| WL-FIT-GOV-011 | Manifest threat model anomaly detection | `partial` | coherence.py covers ~5 of 10 vectors: tier downgrades, upgrades without evidence, agent provenance, expired exceptions, restoration overclaim | Missing: volume spikes, boundary widening, SUPPRESS changes, dependency taint signals |
| WL-FIT-GOV-012 | Exception age management | `partial` | Expired exception detection with configurable max_exception_duration_days (365); no per-class age limits or grace period | SHOULD-level; basic expiry present, differentiation absent |
| WL-FIT-GOV-013 | Policy vs enforcement artefact distinction | `pass` | fingerprint.py _POLICY_GROUPS classifies annotations; diff output shows [policy] and [enforcement] sections | Clean distinction in fingerprint |
| WL-FIT-GOV-014 | Supplementary group exceptionability binding-defined | `partial` | SUP-001 hardcodes UNCONDITIONAL for all supplementary findings; spec says STANDARD should be default | Stricter than spec recommends |
| WL-FIT-GOV-015 | Governance audit retention | `fail` | Retention requirement in spec only; no adopter-facing documentation | Not documented |
| WL-FIT-GOV-016 | Provenance justification for trust escalation | `partial` | BoundaryEntry.provenance supports structured declarations; evidence categories checked; provenance is freeform dict (no mandatory rationale fields) | Evidence checked; rationale quality not enforced |

## Conformance Profiles (10 requirements)

| Requirement | Title | Status | Evidence | Notes |
|---|---|---|---|---|
| WL-FIT-CONF-001 | Ten conformance criteria addressable | `partial` | All 10 functionally addressed; no explicit criteria-to-implementation mapping table in binding doc | Mapping must be reconstructed from scattered sections |
| WL-FIT-CONF-002 | Enforcement profile declared | `pass` | Python binding declares Wardline-Core profile; rules PY-WL-001-009 declared; SARIF emits implementedRules | Profile and rules documented |
| WL-FIT-CONF-003 | Governance profile declared and assessable | `partial` | Schema supports governance_profile; SARIF emits it; wardline.yaml does NOT explicitly declare it (implicit lite) | Self-hosting manifest should declare explicitly |
| WL-FIT-CONF-004 | Enforcement regime documented | `pass` | wardline-02-A-python-binding.md A.6 regime composition matrix; 10 capabilities mapped to tools | Comprehensive mapping |
| WL-FIT-CONF-005 | Supplementary group enforcement scope documented | `fail` | No explicit documentation distinguishing enforced vs expressiveness-only supplementary groups; no overlay supplementary section | Assessor cannot determine scope from docs alone |
| WL-FIT-CONF-006 | Assessment procedure supportable | `pass` | All 7 steps have CLI commands: manifest validate, coherence, corpus verify, scan, fingerprint, self-hosting tests | corpus publish generates conformance.json |
| WL-FIT-CONF-007 | Graduation path from Lite to Assurance | `partial` | Schema supports profile change; corpus exceeds 126 floor; fingerprint CLI exists; no baseline file yet, no graduation guide | Implicitly supportable, not explicitly guided |
| WL-FIT-CONF-008 | Precision and recall floors per cell | `pass` | corpus_cmds.py implements exact spec floors (80%/65%/90%/70%); JSON report covers 72 cells with cell-level verdicts | All spec floor values implemented |
| WL-FIT-CONF-009 | Enforcement regime composition rules documented | `partial` | A.6 maps capabilities to tools; SARIF includes conformanceGaps; no explicit criteria-level coverage table | Capability mapping present, criteria-level gaps not tabulated |
| WL-FIT-CONF-010 | Lite governance checklist verifiable | `partial` | 6 of 7 items verifiable; item 5 (annotation changes in assessment window) has no explicit tooling | governance_profile not declared in manifest |

## Summary Metrics

| Category | Total | Pass | Partial | Fail | Not Assessed |
|---|---|---|---|---|---|
| Framework Core | 17 | 12 | 4 | 1 | 0 |
| Manifest & Governance | 19 | 13 | 5 | 1 | 0 |
| Scanner Conformance | 20 | 13 | 6 | 1 | 0 |
| Python Binding | 12 | 10 | 2 | 0 | 0 |
| Enforcement Layers | 12 | 7 | 3 | 2 | 0 |
| Governance Operations | 16 | 6 | 7 | 3 | 0 |
| Conformance Profiles | 10 | 4 | 5 | 1 | 0 |
| **Total** | **106** | **65** | **32** | **9** | **0** |

## Fail Requirements Blocking Conformance

| Requirement | Gap | Conformance Impact |
|---|---|---|
| CORE-013 | Serialisation does not shed authority | Violates §5.2 invariant 5; taint can leak through serialization boundaries |
| MAN-014 | No YAML quoted-string enforcement | Norway problem possible; loader-level mitigation needed |
| SCAN-016 | Group 5 field-completeness not enforced | @all_fields_mapped declared but no scanner rule |
| ENF-009 | No incremental analysis | SHOULD-level; does not block conformance but limits CI scalability |
| ENF-010 | No pre-generation projection | Advisory; does not block conformance |
| GOV-009 | No retrospective scan | MUST for both Lite and Assurance; blocks governance conformance |
| GOV-015 | Audit retention not documented | Process gap; blocks assessor verification |
| CONF-005 | Supplementary enforcement scope undocumented | Assessor cannot evaluate regime coverage |

Of these, **CORE-013**, **GOV-009**, and **SCAN-016** are the highest-impact gaps for an honest conformance claim. ENF-009 and ENF-010 are SHOULD-level and do not block conformance.
