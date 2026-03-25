# Bounded-Context Completeness Assessment

**Date:** 2026-03-25
**Scope:** Bounded-context declarations, contract bindings, and coherence checks
**Spec references:** SS13.1.2 (overlay schema), SS9.2 (coherence checks)

---

## 1. Bounded-context presence check on Tier 2 boundaries

**Spec requirement (SS13.1.2):** "Every boundary that claims Tier 2 semantics -- `semantic_validation` boundaries, `combined_validation` boundaries, and restoration boundaries with `semantic: true` in their provenance evidence -- MUST include a `bounded_context` object." The enforcement paragraph states: "The tool presence-checks the `bounded_context` field -- a boundary claiming Tier 2 semantics without a `bounded_context` declaration is a finding."

**Implementation status: NOT IMPLEMENTED.**

Evidence:

- No scanner rule references `bounded_context` anywhere in `src/wardline/scanner/rules/`. A `grep` for `bounded_context` across all rule files returns zero matches.
- The `BoundaryEntry` model (`src/wardline/manifest/models.py:149`) carries the field: `bounded_context: dict[str, object] | None = None`.
- The overlay loader (`src/wardline/manifest/loader.py:268`) correctly parses `bounded_context` from YAML into the dataclass.
- The overlay JSON schema (`src/wardline/manifest/schemas/overlay.schema.json:58`) defines the `bounded_context` object with `contracts` array and `description`.
- `ScanContext` (`src/wardline/scanner/context.py:95`) receives `boundaries: tuple[BoundaryEntry, ...]` -- the data is available to rules.
- **No rule inspects `boundary.bounded_context` to verify it is present when the boundary claims Tier 2 semantics.** No rule checks `transition == "semantic_validation"` or `transition == "combined_validation"` or `(transition == "restoration" and provenance.get("semantic") is True)` against `bounded_context is None`.

The data model and loader are complete. The enforcement check that the spec mandates is absent.

## 2. Contract bindings implementation

**Spec requirement (SS13.1.2):** Contract bindings map named contracts to implementing functions, declared in the overlay under `contract_bindings`.

**Implementation status: SCHEMA AND LOADER ONLY.**

Evidence:

- `ContractBinding` dataclass exists (`src/wardline/manifest/models.py:166-170`) with `contract: str` and `functions: tuple[str, ...]`.
- `WardlineOverlay` includes `contract_bindings: tuple[ContractBinding, ...] = ()` (`models.py:192`).
- The loader (`loader.py:273-278`) correctly parses `contract_bindings` from YAML.
- The overlay JSON schema (`overlay.schema.json:110`) defines the `contract_bindings` array.
- **No code consumes `contract_bindings` after loading.** The `ScanContext` does not carry contract bindings. No scanner rule, coherence check, or CLI command references `contract_bindings` beyond the loader and the `resolve_cmd.py` pass-through (which serialises them for display but does not validate them).

The binding mechanism is parsed and stored but never validated or enforced.

## 3. Stale contract binding detection

**Spec requirement (SS9.2, coherence condition 5):** "A `contract_bindings` entry whose declared function path does not resolve to an existing function in the codebase. Detection is a simple existence check (no semantic analysis needed)."

**Implementation status: NOT IMPLEMENTED.**

Evidence:

- `src/wardline/manifest/coherence.py` implements 8 coherence checks: `check_orphaned_annotations`, `check_undeclared_boundaries`, `check_tier_distribution`, `check_tier_downgrades`, `check_tier_upgrade_without_evidence`, `check_agent_originated_exceptions`, `check_expired_exceptions`, `check_first_scan_perimeter`.
- None of these checks reference `contract_bindings` or `ContractBinding`.
- The coherence CLI command (`src/wardline/cli/coherence_cmd.py`) invokes exactly these 8 checks and no others.
- The `CATEGORY_MAP` in the coherence CLI lists 8 kinds. There is no `stale_contract_binding` kind.

The spec describes this as "a simple existence check" -- verifying that each function path in `contract_bindings` resolves to a real annotated function. This check does not exist.

## 4. Unmatched contracts detection

**Spec requirement (SS9.2, coherence condition 4):** "Contract declarations in the manifest or overlay that do not match any code-level annotation at the declared location."

**Implementation status: NOT IMPLEMENTED.**

Evidence:

- Same analysis as above. No coherence check in `coherence.py` handles contract matching.
- The `check_undeclared_boundaries` function checks whether overlay boundary entries have corresponding decorated functions -- but this is boundary-level, not contract-level. It does not verify that `bounded_context.contracts[*].name` values match anything in code annotations.
- No scanner rule performs contract-to-annotation matching.

## 5. Implementation completeness summary

| SS13.1.2 Feature | Data Model | Schema | Loader | Enforcement/Coherence |
|---|---|---|---|---|
| `bounded_context` field on BoundaryEntry | Yes | Yes | Yes | **No** -- no presence check on Tier 2 boundaries |
| `bounded_context.contracts` structure | Yes (as dict) | Yes | Yes | **No** -- not validated beyond schema |
| `contract_bindings` in overlay | Yes | Yes | Yes | **No** -- parsed but never consumed |
| Stale contract binding detection (SS9.2) | N/A | N/A | N/A | **No** -- coherence check absent |
| Unmatched contract detection (SS9.2) | N/A | N/A | N/A | **No** -- coherence check absent |
| Tier 2 bounded_context presence-check | N/A | N/A | N/A | **No** -- no rule implements this |

The data layer (models, schema, loader) is complete for bounded contexts and contract bindings. The enforcement layer -- the scanner rules and coherence checks that give these declarations teeth -- is entirely absent.

## What would be needed

1. **Bounded-context presence-check rule or coherence check:** Iterate all `BoundaryEntry` objects. For each where `transition in {"semantic_validation", "combined_validation"}` or `(transition == "restoration" and provenance and provenance.get("semantic") is True)`, verify `bounded_context is not None`. Emit a finding if missing.

2. **Stale contract binding coherence check:** For each `ContractBinding.functions` entry, verify the function path exists in the project annotations map. Emit a `stale_contract_binding` issue for each unresolved path.

3. **Unmatched contract coherence check:** For each `bounded_context.contracts[*].name` across all boundaries, verify a corresponding `contract_bindings` entry exists (and vice versa). Emit an `unmatched_contract` issue for orphans in either direction.

---

## Verdict: FAIL

The spec (SS13.1.2) explicitly mandates: "The tool presence-checks the `bounded_context` field -- a boundary claiming Tier 2 semantics without a `bounded_context` declaration is a finding." This check is not implemented. The coherence checks specified in SS9.2 for stale contract bindings and unmatched contracts are also absent. The data model and loader infrastructure exists, but no enforcement code consumes it. The bounded-context machinery is plumbed but inert.
