# SARIF Aggregation Design — WP 3.3

**Date:** 2026-03-24
**Status:** Draft
**Scope:** `wardline sarif diff` and `wardline sarif trend` — multi-run comparison, trend analysis, SARIF-native output
**Target release:** v0.4.0
**Dependencies:** None (operates on SARIF output files, no runtime or scanner changes)

## Context

Wardline produces SARIF v2.1.0 output per scan run. There is no mechanism to compare runs, detect regressions/improvements, or track trends over time. WP 3.3 adds two CLI commands that operate on SARIF files as input and produce text, JSON, or SARIF-native output.

**Cross-project note:** The Rust `wardline-watcher` project may also consume SARIF output for governance dashboard integration. All output formats are language-neutral JSON/SARIF — no Python-specific serialization.

## 1. Finding Identity

Two matching strategies determine what constitutes the "same finding" across runs.

**`qualname` (default):** Identity key = `(rule_id, file_path, qualname)`. When multiple findings share the same key (same rule, same function), `line` is the tiebreaker. When `qualname` is None (governance findings), falls back to `(rule_id, file_path, line)`.

**`fingerprint`:** Identity key = `sha256(rule_id|file_path|qualname|source_snippet)[:16]`. More robust against function renames when snippet is stable. Falls back to qualname strategy when `source_snippet` is missing.

Both strategies produce a string key per finding. The diff/trend algorithms are strategy-agnostic — they operate on key sets.

Toggle: `--match-strategy qualname|fingerprint` on both commands.

## 2. `wardline sarif diff`

### CLI Interface

```
wardline sarif diff <baseline.sarif.json> <current.sarif.json> [--match-strategy qualname|fingerprint] [--json] [--sarif] [--gate]
```

### Algorithm

1. Load both SARIF files, extract findings from `runs[0].results`
2. Compute identity key per finding using chosen strategy
3. Partition into four sets:
   - **New:** in current but not baseline (regressions)
   - **Fixed:** in baseline but not current (improvements)
   - **Unchanged:** in both with same severity
   - **Severity changed:** in both but severity differs

### Output Formats

**Text:**
```
SARIF Diff: baseline (2026-03-20) → current (2026-03-24)

  New findings:      3  (regressions)
  Fixed findings:    2  (improvements)
  Unchanged:        45
  Severity changed:  1  (PY-WL-003 adapters/client.py::fetch WARNING→ERROR)

  Direction: REGRESSING (+1 net)
```

**JSON (`--json`):** Structured object with `new`, `fixed`, `unchanged`, `severity_changed` arrays, each containing finding details plus identity key. Summary counts at top level.

**SARIF (`--sarif`):** Valid SARIF v2.1.0 file. Every finding carries `wardline.diffStatus` in its property bag:
- `"new"` — appeared in current run
- `"fixed"` — was in baseline but not current (included as suppressed result for traceability)
- `"unchanged"` — present in both
- `"severity_changed"` — present in both, severity differs (carries `wardline.previousSeverity`)

Run-level properties: `wardline.baselineTimestamp`, `wardline.currentTimestamp`, `wardline.matchStrategy`, `wardline.diffSummary` (counts object with `new`, `fixed`, `unchanged`, `severity_changed` fields).

### Gate Behavior

`--gate`: Exit 1 if `new > 0` (any regression). Exit 0 if only fixed/unchanged/severity-changed. CI gate for "no new findings."

## 3. `wardline sarif trend`

### CLI Interface

```
wardline sarif trend <run1.sarif.json> [run2.sarif.json ...] [--json] [--sarif]
```

Takes 2+ SARIF files in chronological order.

### Algorithm

1. Load each SARIF file, extract `wardline.scanTimestamp` from run properties (falls back to file modification time)
2. Sort by timestamp
3. Per run: count findings by `rule_id` and by `severity`
4. Compute deltas between consecutive runs

### Output Formats

**Text:**
```
SARIF Trend: 4 runs (2026-03-20 → 2026-03-24)

  Date        Total  New  Fixed  PY-WL-001  PY-WL-003  PY-WL-005
  2026-03-20    42    —     —        15          12          8
  2026-03-21    40    1     3        15          11          7
  2026-03-23    38    0     2        14          11          7
  2026-03-24    41    5     2        16          12          8

  Direction: REGRESSING (42 → 41 → 38 → 41)
  Net change: -1 from first to last
```

**JSON (`--json`):** Array of run summaries with timestamp, total, per-rule counts, per-severity counts, delta from previous.

**SARIF (`--sarif`):** Single SARIF file with multiple runs (one per input file). Each run carries `wardline.trendIndex` (0-based) and `wardline.trendDelta` (+N/-N from previous). Final run has full finding details; earlier runs carry summary in properties only.

No `--gate` on trend — trend is informational. Gating belongs on `diff`.

## 4. Implementation

### New module: `src/wardline/scanner/sarif_aggregation.py` (~200 lines)

Pure functions, no CLI concerns:
- `compute_finding_key(finding_dict, strategy) -> str`
- `diff_sarif_runs(baseline, current, strategy) -> SarifDiff`
- `trend_sarif_runs(runs) -> SarifTrend`
- `diff_to_sarif(diff) -> dict` — SARIF-native diff output
- `trend_to_sarif(trend) -> dict` — SARIF-native trend output

### Data models (frozen dataclasses in sarif_aggregation.py):

```python
@dataclass(frozen=True)
class DiffEntry:
    key: str
    rule_id: str
    file_path: str
    line: int
    qualname: str | None
    severity: str
    message: str

@dataclass(frozen=True)
class SarifDiff:
    new: tuple[DiffEntry, ...]
    fixed: tuple[DiffEntry, ...]
    unchanged: tuple[DiffEntry, ...]
    severity_changed: tuple[tuple[DiffEntry, DiffEntry], ...]
    baseline_timestamp: str | None
    current_timestamp: str | None
    match_strategy: str

@dataclass(frozen=True)
class RunSummary:
    timestamp: str | None
    total: int
    by_rule: dict[str, int]
    by_severity: dict[str, int]
    delta_from_previous: int | None

@dataclass(frozen=True)
class SarifTrend:
    runs: tuple[RunSummary, ...]
    match_strategy: str
```

### New CLI: `src/wardline/cli/sarif_cmd.py` (~150 lines)

`wardline sarif` click group with `diff` and `trend` subcommands. Registered in `main.py`.

### Files Changed

| File | Change |
|---|---|
| `scanner/sarif_aggregation.py` | New — diff/trend logic + data models |
| `cli/sarif_cmd.py` | New — CLI commands |
| `cli/main.py` | Register `sarif` group |
| `tests/unit/scanner/test_sarif_aggregation.py` | New — ~20 tests |
| `tests/integration/test_sarif_cmd.py` | New — CLI integration tests |

### Testing (~20 tests)

**Diff:**
- `test_diff_new_findings` — baseline empty, current has findings → all new
- `test_diff_fixed_findings` — baseline has findings, current empty → all fixed
- `test_diff_unchanged` — identical runs → all unchanged
- `test_diff_severity_changed` — same key, different severity
- `test_diff_mixed` — combination of new + fixed + unchanged
- `test_diff_qualname_strategy` — qualname-based matching
- `test_diff_fingerprint_strategy` — fingerprint-based matching
- `test_diff_qualname_fallback_to_line` — qualname is None, falls back to line
- `test_diff_json_output` — valid JSON with all fields
- `test_diff_sarif_output` — valid SARIF with wardline.diffStatus properties
- `test_diff_gate_new_findings` — `--gate` exits 1 on regressions
- `test_diff_gate_no_new` — `--gate` exits 0 when clean

**Trend:**
- `test_trend_two_runs` — minimum viable trend
- `test_trend_multiple_runs` — 4 runs with deltas
- `test_trend_by_rule` — per-rule counts
- `test_trend_json_output` — valid JSON array
- `test_trend_sarif_output` — multi-run SARIF with trendIndex/trendDelta
- `test_trend_missing_timestamp` — falls back to file mtime

**Edge cases:**
- `test_diff_empty_sarif` — empty results array → 0 findings
- `test_diff_malformed_sarif` — invalid JSON → exit 2
