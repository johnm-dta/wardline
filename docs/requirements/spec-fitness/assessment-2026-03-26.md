# Spec Fitness Assessment — 2026-03-26

This is the first repo fitness assessment against the baseline in this folder.

## Rollup

- Pass: 18
- Partial: 8
- Fail: 5

Overall judgment: the project has a solid core implementation and test surface, but it is not yet fit to claim clean alignment with the current normative spec. The main issues are concentrated in three areas:

1. Python binding incompleteness: `@restoration_boundary(...)` is still missing, and generic boundary decorators are not parameterized per the binding contract.
2. Manifest/spec drift: the implementation still uses `bounded_context` where the current spec uses `validation_scope`, and several governance/reporting surfaces remain behind the normative wording.
3. Conformance surface gaps: the scanner and corpus are strong in core areas, but corpus breadth, self-hosting strictness, and some SARIF/run-level properties lag the spec.

## Verification Run

Targeted tests executed successfully:

```bash
uv run pytest tests/unit/core/test_taints.py \
  tests/unit/core/test_taint_to_tier.py \
  tests/unit/decorators/test_boundaries.py \
  tests/unit/manifest/test_loader.py \
  tests/unit/manifest/test_resolve.py \
  tests/unit/manifest/test_regime.py \
  tests/unit/scanner/test_sarif.py \
  tests/unit/scanner/test_py_wl_001.py \
  tests/unit/scanner/test_py_wl_007.py \
  tests/unit/scanner/test_py_wl_009.py \
  tests/unit/scanner/test_engine_l3.py \
  tests/unit/scanner/test_delegated_rejection.py \
  tests/unit/scanner/test_rejection_path_convergence.py -q
```

Result: `252 passed in 0.38s`

## Assessment Table

| Requirement | Status | Primary evidence | Notes |
|---|---|---|---|
| `WL-FIT-CORE-001` | pass | `src/wardline/core/taints.py`, `tests/unit/core/test_taints.py`, `src/wardline/scanner/sarif.py` | Canonical taint tokens are defined and exercised in tests. |
| `WL-FIT-CORE-002` | pass | `src/wardline/core/taints.py`, `tests/unit/core/test_taints.py` | Join algebra properties are explicitly tested, including exhaustive associativity. |
| `WL-FIT-CORE-003` | pass | `src/wardline/core/taints.py`, `tests/unit/core/test_taints.py` | Known-plus-unknown merges collapse to `MIXED_RAW` as required. |
| `WL-FIT-CORE-004` | pass | `src/wardline/core/tiers.py`, `tests/unit/core/test_taint_to_tier.py` | Tier-to-taint mapping is explicit and complete. |
| `WL-FIT-CORE-005` | pass | `src/wardline/core/matrix.py`, `tests/unit/core/test_matrix.py`, `tests/unit/scanner/test_matrix_cells.py` | Implemented rule/state severity behavior is covered by dedicated tests. |
| `WL-FIT-CORE-006` | fail | `src/wardline/manifest/schemas/overlay.schema.json`, `src/wardline/manifest/loader.py` | Skip-promotions to Tier 1 are not rejected by schema or loader logic. |
| `WL-FIT-CORE-007` | fail | `src/wardline/decorators/__init__.py`, `src/wardline/core/registry.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f1/evidence-restoration.md` | Restoration claims are not fully implementable because the core decorator contract is missing. |
| `WL-FIT-MAN-001` | pass | `src/wardline/manifest/loader.py`, `src/wardline/manifest/schemas/wardline.schema.json`, `tests/unit/manifest/test_schemas.py` | Root manifest schema validation is enforced before model construction. |
| `WL-FIT-MAN-002` | pass | `src/wardline/manifest/resolve.py`, `src/wardline/manifest/scope.py`, `tests/unit/manifest/test_loader.py`, `tests/unit/manifest/test_resolve.py` | Overlay path/scope spoofing is rejected. |
| `WL-FIT-MAN-003` | pass | `src/wardline/manifest/merge.py`, `tests/unit/manifest/test_merge.py`, `tests/unit/manifest/test_resolve.py` | Narrow-only enforcement exists for severity and scoped tier widening. |
| `WL-FIT-MAN-004` | fail | `src/wardline/manifest/models.py`, `src/wardline/manifest/loader.py`, `src/wardline/manifest/schemas/overlay.schema.json`, `docs/audits/2026-03-25-rule-conformance/phase-2/f1/bounded-context.md` | Implementation still uses `bounded_context`; current spec baseline requires `validation_scope`. Presence-check enforcement is also absent. |
| `WL-FIT-MAN-005` | partial | `src/wardline/manifest/models.py`, `src/wardline/manifest/loader.py`, `src/wardline/manifest/resolve.py` | Contract bindings are separate and name-based, but contract declarations remain raw dicts and cross-validation is weak. |
| `WL-FIT-MAN-006` | pass | `src/wardline/scanner/rules/py_wl_001.py`, `tests/unit/scanner/test_py_wl_001.py`, `src/wardline/manifest/resolve.py` | `schema_default()` is tied to overlay optional-field governance and tested. |
| `WL-FIT-MAN-007` | partial | `src/wardline/manifest/models.py`, `src/wardline/manifest/regime.py`, `tests/unit/manifest/test_regime.py` | Ratification age is computed and surfaced in regime metrics, but the evidence is stronger in governance CLI than in scan-time findings. |
| `WL-FIT-MAN-008` | pass | `src/wardline/manifest/schemas/wardline.schema.json`, `src/wardline/manifest/models.py`, `src/wardline/manifest/loader.py`, `src/wardline/manifest/regime.py`, `src/wardline/scanner/sarif.py` | Governance profile is now modeled in the manifest, consumed by regime reporting, and emitted in SARIF as `wardline.governanceProfile`. |
| `WL-FIT-SCAN-001` | pass | `src/wardline/scanner/rules/__init__.py`, `src/wardline/scanner/sarif.py`, `tests/unit/scanner/test_sarif.py` | Implemented rules are declared and pseudo-rules are excluded from `implementedRules`. |
| `WL-FIT-SCAN-002` | pass | `tests/unit/scanner/test_py_wl_001.py` through `test_py_wl_009.py`, `tests/unit/scanner/test_scn_021.py` | Implemented rule behavior has substantial unit coverage. |
| `WL-FIT-SCAN-003` | pass | `tests/unit/scanner/test_engine_l3.py`, `tests/unit/scanner/test_delegated_rejection.py`, `tests/unit/scanner/test_rejection_path_convergence.py` | Direct, two-hop, delegated, and convergence paths are explicitly tested. |
| `WL-FIT-SCAN-004` | partial | `src/wardline/scanner/sarif.py`, `tests/unit/scanner/test_sarif.py`, ready issues `keisei-d1dfd63456` and related audit notes | SARIF is deterministic and now includes core Wardline properties including governance profile, but run-level property coverage is still incomplete relative to the current spec/audit expectations. |
| `WL-FIT-SCAN-005` | pass | `src/wardline/scanner/engine.py`, `tests/unit/scanner/test_engine.py`, `tests/unit/scanner/test_engine_l3.py` | Tool failures are surfaced and fall back behavior is tested. |
| `WL-FIT-SCAN-006` | partial | `corpus/specimens`, `tests/unit/corpus/test_corpus_skeleton.py`, `tests/unit/scanner/test_corpus_runner.py` | Corpus machinery exists and is runnable, but skeleton coverage is still narrower than the full claimed rule surface. |
| `WL-FIT-SCAN-007` | partial | `docs/audits/2026-03-25-rule-conformance/phase-2/f3/compliance-surface.md`, `tests/unit/test_wp04_hardening.py`, CLI scan/regime surfaces | Self-hosting is measurable, but the current gate is closer to stability checking than strict “passes its own rules” conformance. |
| `WL-FIT-SCAN-008` | partial | `docs/spec/wardline-02-A-python-binding.md`, `src/wardline/scanner/sarif.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f3/compliance-surface.md` | Regime composition is documented, but machine-readable conformance honesty lags because SARIF reports no conformance gaps despite known tracked gaps. |
| `WL-FIT-PY-001` | partial | `src/wardline/decorators/__init__.py`, `src/wardline/core/registry.py`, `tests/unit/scanner/test_registry_sync.py` | Export surface is strong for Groups 1–15, but core binding vocabulary is incomplete for the current spec baseline. |
| `WL-FIT-PY-002` | fail | `src/wardline/decorators/__init__.py`, `src/wardline/core/registry.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f1/evidence-restoration.md`, ready issue `keisei-125ea62dcd` | `@restoration_boundary(...)` is missing from the decorator library and registry. |
| `WL-FIT-PY-003` | fail | `src/wardline/decorators/boundaries.py`, `tests/unit/decorators/test_boundaries.py`, ready issue `keisei-ad7fa05ab1` | `trust_boundary` and `tier_transition` exist only as boolean markers, not parameterized transitions. |
| `WL-FIT-PY-004` | partial | `src/wardline/decorators/_base.py`, `src/wardline/runtime/base.py`, `tests/unit/decorators/test_decorators.py`, ready issue `keisei-cb8fe87f0b` | `get_wardline_attrs()` traverses `__wrapped__`, but `WardlineBase` still relies on top-level attrs instead of full chain traversal. |
| `WL-FIT-PY-005` | pass | `src/wardline/scanner/rules/scn_021.py`, `tests/unit/scanner/test_scn_021.py` | Contradictory/suspicious decorator combinations are implemented and tested. |
| `WL-FIT-PY-006` | pass | `src/wardline/scanner/rules/py_wl_009.py`, `tests/unit/scanner/test_py_wl_009.py` | Validation ordering enforcement is implemented and well tested. |
| `WL-FIT-PY-007` | pass | `src/wardline/runtime`, `tests/unit/runtime` | Runtime support exists and is tested as complementary enforcement. |
| `WL-FIT-PY-008` | pass | `src/wardline/scanner/sarif.py`, `src/wardline/scanner/rules/__init__.py`, `src/wardline/core/severity.py` | Python-specific rule splits and diagnostics are distinguishable from core rule IDs. |

## Highest-Value Gaps

1. Implement Group 17 properly.
   This means adding `@restoration_boundary(...)`, registering it in the canonical registry, exporting it from the decorator package, and wiring it through scanner/runtime consumers.

2. Reconcile manifest terminology with the current spec.
   The codebase still uses `bounded_context`; the current baseline is `validation_scope`. This needs a fix across model, loader, schema, CLI serialization, and any rule/coherence consumers.

3. Add proper parameterized generic boundaries.
   `trust_boundary(from_tier=..., to_tier=...)` and `tier_transition(...)` need to carry real transition metadata instead of boolean presence markers.

4. Tighten conformance reporting.
   The repo already knows about several active spec mismatches; the machine-readable conformance surface should stop claiming an empty gap set while those remain open.

## Suggested Next Moves

1. Fix the binding blockers first: `WL-FIT-PY-002`, `WL-FIT-PY-003`, `WL-FIT-PY-004`.
2. Fix the manifest drift next: `WL-FIT-MAN-004`, `WL-FIT-CORE-006`.
3. Then refresh SARIF/conformance honesty: `WL-FIT-SCAN-004`, `WL-FIT-SCAN-008`, `WL-FIT-SCAN-007`.
