# Spec Conformance Audit Phase 1

Date: 2026-03-25
Work package: `wardline-25e2cf5885` (`4.2: Full Spec Conformance Audit`)

## Audit contract

A rule is considered online only when all of the following are true:

- Matrix conformance: every non-`SUPPRESS` matrix cell emits a finding at the correct severity/exceptionability, and every `SUPPRESS` cell does not.
- Detection-target alignment: AST patterns match the normative rule definition and Python binding.
- Suppression inventory: every suppression or non-emission path is documented and justified.
- Corpus coverage: each rule has per-taint positive/negative coverage plus adversarial and known-false-negative coverage where applicable.
- SARIF property completeness: findings serialize all mandatory Python-binding result properties.
- Reconciliation record: every divergence is tracked as fix-code, fix-spec, or documented behavior.

## Phase 1 pre-sweep

The scanner infrastructure is not the current risk. All nine rule files:

- call `matrix.lookup()`
- acquire taint via `_get_function_taint()`
- populate `severity`, `exceptionability`, `taint_state`, and `analysis_level` on `Finding`

The remaining conformance risk is localized to rule-specific heuristics and suppression behavior.

| Rule | Matrix usage | Taint acquisition | Finding fields | Current audit status | Primary concern |
|---|---|---|---|---|---|
| `PY-WL-001` | Partial | Yes | Complete | Not online | `schema_default()` suppression behavior diverges from binding contract |
| `PY-WL-002` | Faithful | Yes | Complete | Close | Binding docs still classify `hasattr()` under PY-WL-002 |
| `PY-WL-003` | Partial | Yes | Complete | Not online | `_ACTIVE_TAINTS` gate preempts 5 matrix cells |
| `PY-WL-004` | Faithful | Yes | Complete | Close | No major code-level divergence found in this slice |
| `PY-WL-005` | Faithful | Yes | Complete | Close, but unresolved | Narrower silent-handler interpretation than binding prose |
| `PY-WL-006` | Faithful | Yes | Complete | Not online | Heuristic audit-write detection vs binding's audit-path-aware contract |
| `PY-WL-007` | Faithful | Yes | Complete | Not online | Declared-boundary suppression applies to `isinstance()` but not `type()` checks |
| `PY-WL-008` | Faithful | Yes | Complete | Not online | Scopes to validation-like names instead of declared boundary functions |
| `PY-WL-009` | Faithful | Yes | Complete | Not online | Scopes to arbitrary functions and line order instead of declared boundary ordering |

## Reconciliation ledger

Confirmed reconciliation items tracked under the work package:

- `wardline-b0e9f900fa`: Reconcile `PY-WL-001` `schema_default` suppression with binding contract
- `wardline-fd0cde1304`: Resolve `PY-WL-002` `hasattr()` classification mismatch between binding docs and implementation
- `wardline-9a0b0cb70c`: Reconcile `PY-WL-003` `_ACTIVE_TAINTS` gate with full matrix and boundary-aware suppression
- `wardline-5781330b6b`: Reconcile `PY-WL-006` heuristic audit-write detection with audit-path-aware contract
- `wardline-4637107ccc`: Reconcile `PY-WL-007` declared-boundary suppression with runtime type-check rule contract
- `wardline-653921f090`: Scope `PY-WL-008` to declared boundary functions and reconcile rejection-path heuristics
- `wardline-af25bdc839`: Scope `PY-WL-009` to semantic/combined boundary ordering semantics
- `wardline-922c61c6ac`: Add explicit SARIF assertion for `wardline.taintState`

## Early rule verdicts

- `PY-WL-004` is the strongest candidate for online status in the current audit slice: matrix use is faithful, detection surface aligns with the rule target, and corpus coverage is comparatively strong.
- `PY-WL-002` is also close, but its binding documentation mismatch must be resolved before calling it fully online.
- `PY-WL-005` is matrix-faithful but still needs a decision on whether the implementation's narrow "single-statement no-op" interpretation is the intended contract.
- `PY-WL-001`, `PY-WL-003`, `PY-WL-006`, `PY-WL-007`, `PY-WL-008`, and `PY-WL-009` are not online yet because rule behavior diverges materially from the current binding/spec text.

## SARIF note

Code-level SARIF property completeness is intact: the rules emit the mandatory finding fields and SARIF serialization includes:

- `wardline.rule`
- `wardline.taintState`
- `wardline.severity`
- `wardline.exceptionability`
- `wardline.analysisLevel`

The remaining gap is test evidence: the current SARIF test suite does not explicitly assert `wardline.taintState`.
