# Evidence Restoration Boundary Assessment

**Date:** 2026-03-25
**Scope:** Restoration boundaries (spec section 5.3), evidence category enforcement, tier demotion
**Assessor:** Evidence Restoration Agent

---

## 1. @restoration_boundary implementation status

**Finding: NOT IMPLEMENTED as a decorator. Partially supported via overlay manifest only.**

The spec (Part II-A, section A.4.2, Group 17) defines `@restoration_boundary(...)` as a decorator accepting:
- `restored_tier`: int
- `structural_evidence`: bool
- `semantic_evidence`: bool (optional)
- `integrity_evidence`: str (optional, enum: checksum/signature/hmac)
- `institutional_provenance`: str (optional)

Current state:
- **No decorator module exists.** The `src/wardline/decorators/` directory has no file for Group 17. The `boundaries.py` file contains only Group 6 decorators (`trust_boundary`, `tier_transition`).
- **No registry entry.** `src/wardline/core/registry.py` defines Groups 1-15 but has no Group 16 (`data_flow`) or Group 17 (`restoration_boundary`) entry. The registry ends at Group 15 (Lifecycle).
- **Not exported.** `src/wardline/decorators/__init__.py` does not import or export `restoration_boundary`.
- **Overlay schema supports it.** `src/wardline/manifest/schemas/overlay.schema.json` defines the `"restoration"` transition type with `restored_tier` (integer 1-4) and a `provenance` object containing `structural`, `semantic`, `integrity`, and `institutional` fields.
- **BoundaryEntry model supports it.** `src/wardline/manifest/models.py` includes `restored_tier: int | None` and `provenance: dict[str, object] | None` on `BoundaryEntry`.

**Gap:** The decorator itself -- the code-level annotation that a developer places on a function -- does not exist. Only the manifest/overlay path is available.

## 2. Evidence-to-tier enforcement (tier demotion)

**Finding: NOT IMPLEMENTED. No scanner rule enforces the evidence-to-tier matrix.**

The spec (section 5.3) defines a strict evidence-to-tier matrix:
- Tier 1 restoration requires all four evidence categories (structural + semantic + integrity + institutional)
- Tier 2 maximum without integrity evidence
- Tier 3 maximum without semantic evidence
- UNKNOWN_SEM_VALIDATED without institutional evidence
- UNKNOWN_SHAPE_VALIDATED with only structural evidence

Searched `src/wardline/scanner/` for any evidence demotion logic (patterns: "evidence.*demotion", "demote.*taint", "evidence.*tier"). **No matches found.** There is no scanner rule that:
1. Reads the `provenance` field from `BoundaryEntry`
2. Compares declared evidence against `restored_tier`
3. Demotes the effective taint when evidence is insufficient for the claimed tier

This means a developer can declare `restored_tier=1` in an overlay with `provenance: {structural: true}` (no semantic, integrity, or institutional evidence) and the scanner will not flag the mismatch. The evidence-to-tier matrix from section 5.3 is entirely unenforced.

## 3. WL-007 application to restoration boundaries (PY-WL-008)

**Finding: CORRECTLY IMPLEMENTED.**

`src/wardline/scanner/rules/py_wl_008.py` correctly includes restoration boundaries in its scope:

- `_BOUNDARY_TRANSITIONS` includes `"restoration"` (line 25) -- manifest-declared restoration boundaries are checked.
- `_BOUNDARY_DECORATORS` includes `"restoration_boundary"` (line 32) -- direct decorator usage is checked (forward-compatible with the decorator when it is implemented).
- The `_is_checked_boundary` method checks both overlay-declared boundaries and direct decorator syntax.
- Test coverage confirms this: `test_restoration_boundary_without_rejection_path_fires` and `test_restoration_boundary_decorator_with_rejection_is_silent` in the test suite.

The structural verification requirement from section 5.3 ("WL-007-style structural verification applies: a restoration boundary function that contains no rejection path is structurally unsound") is satisfied.

## 4. Manifest integration

**Finding: PARTIALLY IMPLEMENTED. Schema supports evidence; loader parses it; no rule consumes it.**

- **Overlay schema:** `overlay.schema.json` defines `provenance` as an object with `structural` (boolean), `semantic` (boolean), `integrity` (string enum or null: checksum/signature/hmac), and `institutional` (string or null). This matches the four evidence categories from section 5.3.
- **Loader:** `src/wardline/manifest/loader.py` (line 266) reads `restored_tier` and `provenance` from overlay TOML and populates `BoundaryEntry`.
- **BoundaryEntry model:** `src/wardline/manifest/models.py` stores `restored_tier` and `provenance` on the frozen dataclass.
- **ScanContext:** `src/wardline/scanner/context.py` carries `boundaries: tuple[BoundaryEntry, ...]` which propagates the evidence data to rules.
- **No consumer:** No scanner rule reads `boundary.provenance` or `boundary.restored_tier` to perform evidence validation. The data flows from overlay file through loader to ScanContext but is never acted upon for tier demotion.

## 5. Evidence category validation (body behavior matching)

**Finding: NOT IMPLEMENTED.**

The spec states the scanner should demote effective taint when evidence is insufficient. A stronger requirement implied by section A.7.2 of the Python binding is that the scanner should verify that evidence *declarations* match function body *behavior* -- e.g., if `integrity_evidence: "checksum"` is declared, the body should contain checksum verification logic.

No such body-evidence correlation analysis exists. This is a Phase 2+ concern (the spec acknowledges this is hard to verify technically for some categories, particularly institutional provenance), but even the machine-verifiable categories (structural evidence = rejection path, integrity evidence = checksum/signature call) are not correlated with the overlay declarations.

## 6. Contradictory combination detection (SCN-021)

**Finding: CORRECTLY IMPLEMENTED as far as it goes.**

`src/wardline/scanner/rules/scn_021.py` correctly flags:
- `@tier1_read` + `@restoration_boundary` (contradictory)
- `@audit_writer` + `@restoration_boundary` (contradictory)

These match the spec's Table A.4.3 entries 16 and 17.

---

## Summary of gaps

| Assessment area | Status | Severity |
|---|---|---|
| @restoration_boundary decorator (Group 17) | Not implemented | HIGH -- no code-level annotation available |
| Registry entry for restoration_boundary | Missing | HIGH -- scanner discovery cannot resolve the decorator |
| Evidence-to-tier demotion (section 5.3 matrix) | Not implemented | CRITICAL -- the core enforcement guarantee of section 5.3 is absent |
| PY-WL-008 rejection path check for restoration | Implemented | OK |
| Overlay schema for evidence categories | Implemented | OK |
| BoundaryEntry model + loader | Implemented | OK |
| Evidence-body correlation analysis | Not implemented | MEDIUM -- partially deferred by spec design |
| SCN-021 contradictory combinations | Implemented | OK |

The infrastructure (schema, model, loader, context propagation) is in place. The critical missing piece is the scanner rule that consumes the evidence data and enforces the tier demotion matrix.

---

## Verdict: FAIL

**Evidence:**
1. The `@restoration_boundary` decorator (Group 17) does not exist in the decorator library (`src/wardline/decorators/`) or the canonical registry (`src/wardline/core/registry.py`). The spec (Part II-A, section A.4.2) defines it as a core annotation.
2. No scanner rule enforces the evidence-to-tier matrix from section 5.3. A restoration boundary declaring `restored_tier=1` with only structural evidence (which should cap at UNKNOWN_SHAPE_VALIDATED per the matrix) will not be flagged. This is the primary enforcement guarantee of section 5.3 and it is entirely absent.
3. The overlay/manifest plumbing (schema, model, loader) correctly carries the evidence data through to ScanContext, but no rule consumes it. The data arrives at the rules layer and is ignored.

The PY-WL-008 rejection path check for restoration boundaries is correctly implemented, and the overlay schema faithfully models the four evidence categories. These are necessary but not sufficient for section 5.3 conformance.
