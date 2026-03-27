# Conformance Evidence

**Date:** 2026-03-27
**Status:** Draft
**Spec requirements:** WL-FIT-SCAN-005, WL-FIT-SCAN-006, WL-FIT-SCAN-007, WL-FIT-SCAN-008
**Normative sources:** Part I §10 (Verification properties 1–4), §14.2 (Conformance criteria)

## Problem

Four conformance evidence gaps, all PARTIAL:

1. **WL-FIT-SCAN-005 (per-cell metrics):** Precision/recall computed per-rule in `corpus_cmds.py:260` but spec requires per-cell (rule × taint_state). All 72 matrix cells have specimens (70 with positive+negative, 2 SUPPRESS with negatives-only). The aggregation is at the wrong granularity.
2. **WL-FIT-SCAN-006 (corpus breadth):** 191 specimens covering all 72 cells — minimum viable coverage met. No new specimens needed for this scope. Adversarial expansion deferred.
3. **WL-FIT-SCAN-007 (self-hosting gate):** Current gate in `test_self_hosting_scan.py` checks finding-count stability (tolerance ranges). Spec requires "scanner passes the rules it implements on its own source" (§10 property 2).
4. **WL-FIT-SCAN-008 (honest conformance surface):** `wardline.conformanceGaps` hardcoded to `[]` in `sarif.py:283` despite known gaps.

## Design

### 1. Per-cell metrics — `_CellStats` (WL-FIT-SCAN-005)

Replace `_RuleStats` (per-rule) with `_CellStats` keyed by `(rule_id, taint_state)`:

```python
@dataclass
class _CellStats:
    """Per-cell (rule × taint_state) verdict counters."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    kfn: int = 0
```

`_evaluate_specimen()` currently keys on `rule_id` alone. Change to key on `(rule_id, taint_state)`. The `taint_state` field is already present on specimens.

`_print_stats()` becomes `_print_cell_stats()` — groups output by rule, lists each taint_state cell under it, flags cells below floors:
- Precision < 80% (65% for MIXED_RAW)
- Recall < 70% (90% for UNCONDITIONAL cells)

Summary line: "X of Y cells measured, Z below floor."

### 2. `corpus verify --json` — assessment artefact (WL-FIT-SCAN-005)

Add `--json` flag to `corpus verify`. The output is an assessment artefact with explicit per-cell and overall pass/fail verdicts:

```json
{
  "format_version": "1.0",
  "generated_at": "2026-03-27T12:00:00Z",
  "overall_verdict": "FAIL",
  "cells": [
    {
      "rule": "PY-WL-001",
      "taint_state": "AUDIT_TRAIL",
      "exceptionability": "UNCONDITIONAL",
      "suppress": false,
      "tp": 1, "tn": 1, "fp": 0, "fn": 0, "kfn": 0,
      "precision": 1.0,
      "recall": 1.0,
      "precision_floor": 0.80,
      "recall_floor": 0.90,
      "cell_verdict": "PASS"
    }
  ],
  "summary": {
    "total_cells": 72,
    "measured_cells": 70,
    "suppress_cells": 2,
    "passing_cells": 68,
    "failing_cells": 2,
    "cells_below_precision_floor": 1,
    "cells_below_recall_floor": 1
  }
}
```

**Verdict rules:**
- Cell `PASS`: precision ≥ floor AND recall ≥ floor (or SUPPRESS cell with no false positives)
- Cell `FAIL`: below either floor
- Cell `NO_DATA`: zero specimens (defensive — shouldn't occur with current corpus)
- Overall `PASS`: all non-SUPPRESS cells pass
- Overall `FAIL`: any non-SUPPRESS cell fails or has no data

**Floor lookup:** Precision and recall floors come from the severity matrix. UNCONDITIONAL cells use 90% recall floor; STANDARD/RELAXED use 70%. MIXED_RAW cells use 65% precision floor; all others use 80%. These are the spec's recommended calibration points (§10 properties 3–4).

The JSON is deterministic (sorted by rule then taint_state) so an assessor running it twice on the same corpus + tool produces identical output.

### 3. `wardline.conformance.json` — generated status artefact (WL-FIT-SCAN-008)

`conformanceGaps` must not be hand-maintained in `wardline.yaml`. Instead, it's derived from generated evidence.

Add a new CLI command: `wardline corpus publish`. This command:
1. Runs `corpus verify --json` internally
2. Reads the self-hosting scan output (SARIF from a previous `wardline scan` run, path provided as argument)
3. Produces `wardline.conformance.json`:

```json
{
  "format_version": "1.0",
  "generated_at": "2026-03-27T12:00:00Z",
  "corpus_verdict": "PASS",
  "self_hosting_verdict": "PASS",
  "gaps": [
    "adversarial corpus below full floor (8 FP + 8 FN minimum not met)"
  ],
  "corpus_cells_failing": [],
  "self_hosting_unexcepted_findings": 0
}
```

The scan command (`wardline scan`) reads `wardline.conformance.json` if present and populates `wardline.conformanceGaps` from its `gaps` array. If the file is absent, the scan emits a single gap: `"conformance status not generated — run 'wardline corpus publish'"`. If the file is stale (older than manifest ratification date), add `"conformance status stale"`.

This keeps the evidence chain: corpus verify produces per-cell metrics → `corpus publish` aggregates with self-hosting → scan reads the generated artefact. No self-attestation.

**CODEOWNERS:** Add `wardline.conformance.json` to `.github/CODEOWNERS` — it's a governance artefact.

### 4. Self-hosting gate (WL-FIT-SCAN-007)

The spec says "each enforcement tool's own source MUST pass the rules that tool implements" (§10 property 2). This means **all** implemented rules, not just UNCONDITIONAL.

Add a new test: `test_self_hosting_passes_own_rules`. This test:
1. Runs a scan on `src/wardline/` with the project manifest
2. Parses the SARIF output
3. Filters for findings from implemented rules (PY-WL-001 through PY-WL-009)
4. Excludes:
   - Findings with `wardline.exceptionId` present in SARIF properties (active exceptions)
   - GOVERNANCE diagnostic pseudo-rules (ruleId starts with `GOVERNANCE-`)
   - TOOL-ERROR diagnostics
5. Asserts zero remaining findings

If any implemented-rule finding exists without an active exception, self-hosting fails. The fix is either: fix the code, or add an exception (which requires reviewer approval via CODEOWNERS). Both are correct — the spec allows exceptions, it just requires the gate to be real.

Keep the existing stability-range test as a separate regression guard — it catches unexpected shifts even when exceptions are in place.

### 5. Corpus coverage reporting (WL-FIT-SCAN-006)

No new specimens needed. The corpus already has minimum viable coverage for all 72 cells (verified: 70 with positive+negative, 2 SUPPRESS with negatives-only).

`corpus verify --json` reports coverage as part of its output. Cells with insufficient specimens are flagged as `NO_DATA`. The `corpus publish` command includes any `NO_DATA` cells as gaps.

The adversarial specimen floor (8 FP + 8 FN) is tracked as a declared gap in the generated `wardline.conformance.json` until the follow-on corpus expansion addresses it.

## Testing

### Per-cell metrics

| Test | Assertion |
|------|-----------|
| `test_cell_stats_keyed_by_rule_and_taint` | Stats accumulate per `(rule, taint)` tuple |
| `test_print_cell_stats_groups_by_rule` | Text output grouped by rule |
| `test_precision_recall_per_cell` | Correct computation per cell |
| `test_suppress_cells_negative_only` | SUPPRESS cells have no precision (only TN/FP check) |
| `test_json_output_overall_verdict` | `--json` overall verdict is PASS/FAIL |
| `test_json_output_per_cell_verdict` | Each cell has PASS/FAIL/NO_DATA |
| `test_json_output_deterministic` | Two runs produce identical JSON |
| `test_floor_comparison_unconditional` | UNCONDITIONAL uses 90% recall floor |
| `test_floor_comparison_mixed_raw` | MIXED_RAW uses 65% precision floor |

### Conformance status

| Test | Assertion |
|------|-----------|
| `test_conformance_json_generated` | `corpus publish` produces valid JSON |
| `test_conformance_gaps_from_corpus_failures` | Failing cells appear in gaps |
| `test_scan_reads_conformance_json` | SARIF `conformanceGaps` populated from file |
| `test_scan_reports_missing_conformance_file` | Absent file → gap reported |
| `test_sarif_conformance_gaps_wired` | `SarifReport.conformance_gaps` replaces hardcoded `[]` |

### Self-hosting gate

| Test | Assertion |
|------|-----------|
| `test_self_hosting_passes_own_rules` | Zero unexcepted implemented-rule findings |

## Files Changed

| File | Change |
|------|--------|
| `src/wardline/cli/corpus_cmds.py` | Per-cell stats, `--json` flag, floor comparison, `corpus publish` command |
| `src/wardline/scanner/sarif.py` | `conformance_gaps` field replaces hardcoded `[]` |
| `src/wardline/cli/scan.py` | Read `wardline.conformance.json`, pass gaps to `SarifReport` |
| `tests/unit/scanner/test_corpus_runner.py` | Per-cell metric tests |
| `tests/integration/test_self_hosting_scan.py` | `test_self_hosting_passes_own_rules` |
| `tests/unit/scanner/test_sarif.py` | conformance_gaps wiring tests |
| `.github/CODEOWNERS` | Add `wardline.conformance.json` |

## Scope

**In scope:**
- Per-cell (rule × taint_state) metrics computation and publication
- Assessment-artefact JSON output with explicit verdicts
- Generated conformance status file (`wardline.conformance.json`)
- Self-hosting gate: zero unexcepted findings for implemented rules
- Honest `conformanceGaps` derived from generated evidence

**Deferred:**
- Full adversarial corpus expansion (8 FP + 8 FN minimum) — tracked as a gap in the generated conformance file
- CI-integrated corpus verification pipeline
- Precision/recall floor as CI merge gate
