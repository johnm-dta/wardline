# Session Pickup — 2026-03-29

## Branch

`sync-and-validate` — all work is on this branch, not yet merged to main.

## What just shipped

Three critical-path phases closed in one session:

**Phase 4.1: Normative Contract Fixes (8/8)** — validation_scope rename, skip-promotion rejection, T2 presence check, restoration_boundary, SARIF run-level properties, control_law computation, conformanceGaps, resolved format version bump.

**Phase 4.2: Security Hardening (5/5)** — THREAT-006 (resolved hash blocking + --allow-stale-resolved), THREAT-006b (resolved validation pipeline with 4 layers), THREAT-T-1b (overlay OFF rejection for uncovered rules), THREAT-003b (blank ast_fingerprint rejection at load), THREAT-008 (GOVERNANCE_FILE_SKIPPED on parse failure).

**Phase 4.3a: API Surface Stabilization (6/6)** — public API exports (42 names in wardline/__init__.py), _wardline_groups frozenset, decorator return types Any, assert→RuntimeError, version 0.4.0.

**Also this session:**
- ADR-001/002 rename migration (AUDIT_TRAIL→INTEGRAL, PIPELINE→ASSURED, etc. — 403 files)
- 10 PY-WL-003 false positives fixed (closure params, substring suppression, obj.attr, intermediate set vars, AST introspection)
- .get(key) is None detection gap closed in PY-WL-003
- Control law computation from governance signals (§9.5)
- 3 conformance blockers: CORE-013 (serialisation shedding), GOV-009 (retrospective scan --retrospective flag + SARIF properties), SCAN-016 (SCN-022 field-completeness rule)
- Full spec-fitness assessment: 65 pass / 32 partial / 9 fail (down from 17 pass / 10 partial / 8 fail)

## Current state

- 1946 tests pass, 149 deselected (integration/network)
- Self-hosting scan: 16 errors, 139 warnings, 233 excepted, controlLaw: alternate
- Ruff: 31 pre-existing errors (not from our changes)
- Mypy: 25 pre-existing errors (not from our changes)
- The ruff/mypy errors would fail CI on a PR — these need fixing before merge

## What's next — critical path

```
4.4: Test Quality Gates (just unblocked by 4.3a)
  → 4.3b: Schema Freeze + Package Publication
    → 4.6: Adopter Documentation
```

Run `filigree show wardline-9262bbc3e1` to see 4.4's children.

## Key files touched this session

- `src/wardline/core/taints.py` — renamed taint states, fixed join table key ordering
- `src/wardline/core/matrix.py` — updated docstring for T3 ERROR exceptions
- `src/wardline/core/severity.py` — added SCN_022, GOVERNANCE_FILE_SKIPPED
- `src/wardline/core/registry.py` — all_fields_mapped extended with source attr
- `src/wardline/scanner/sarif.py` — compute_control_law(), controlLawDegradations, retroactiveScan, SCN-022 description
- `src/wardline/scanner/taint/variable_level.py` — serialisation sinks → UNKNOWN_RAW
- `src/wardline/scanner/rules/py_wl_003.py` — 5 false positive root causes + .get() is None detection
- `src/wardline/scanner/rules/scn_022.py` — new field-completeness rule
- `src/wardline/scanner/engine.py` — GOVERNANCE_FILE_SKIPPED, RuntimeError invariant
- `src/wardline/cli/scan.py` — control_law wiring, --retrospective, --allow-stale-resolved, _load_resolved validation
- `src/wardline/manifest/loader.py` — reject_skip_promotions extracted
- `src/wardline/manifest/merge.py` — overlay OFF rejection for uncovered rules
- `src/wardline/manifest/exceptions.py` — blank ast_fingerprint rejection
- `src/wardline/decorators/` — integrity.py rename, schema.py source param, _base.py frozenset groups
- `src/wardline/__init__.py` — 42-name public API export

## Assessment file

`docs/requirements/spec-fitness/assessment-2026-03-29.md` — all 106 requirements assessed. The 3 conformance-blocking FAILs (CORE-013, GOV-009, SCAN-016) are now fixed but the assessment file still shows them as FAIL. Update it when continuing.

## Bugs closed

- wardline-49bc7fc6f7 — PY-WL-003 string substring false positives
- wardline-d2050c772f — PY-WL-003 set-membership suppression gaps
