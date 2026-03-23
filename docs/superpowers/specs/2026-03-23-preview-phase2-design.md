# Design: `wardline scan --preview-phase2`

**WP:** 1.7 — Migration Tooling (`wardline-8dd855f73b`)
**Requirement:** `wardline-a2f59e3cf4`
**Date:** 2026-03-23
**Status:** Draft

## Purpose

A reporting flag on `wardline scan` that shows the impact of Phase 2 governance
changes — specifically, ungoverned `schema_default()` calls and exception register
entries needing re-review. Produces a JSON impact report instead of SARIF. Uses
normal exit codes (not an enforcement bypass).

This flag is intentionally thin and may be deprecated or evolved into a lightweight
analysis layer once Phase 2 rules (PY-WL-006–009) are implemented.

## CLI Interface

```
wardline scan [path] --preview-phase2 [-o/--output FILE] [--manifest FILE] [--config FILE]
```

- `--preview-phase2`: Mutually exclusive with normal SARIF output. When set,
  output is the impact JSON report.
- `-o/--output FILE`: Write report to file instead of stdout.
- All existing scan flags (`--manifest`, `--config`) work unchanged — the full
  pipeline runs.
- Exit code: **normal exit code rules apply**. The preview changes the output
  format, not the enforcement posture. Findings still drive exit 1, config
  errors exit 2, tool errors exit 3.
- Write failures on `--output` follow the same path as normal scan: `_error()`
  to stderr and exit 2.
- The stderr summary line is suppressed in `--preview-phase2` mode.

## Prerequisite: `PY_WL_001_UNGOVERNED_DEFAULT` Pseudo-Rule ID

PY-WL-001 fires for multiple patterns (`.get()`, `setdefault`, `defaultdict`,
`schema_default()`) with taint-derived severity. Filtering on `rule_id + severity`
would incorrectly capture non-`schema_default()` findings.

To provide a stable predicate, add `PY_WL_001_UNGOVERNED_DEFAULT` to `RuleId` as
a pseudo-rule ID (mirroring the existing `PY_WL_001_GOVERNED_DEFAULT`). The
ungoverned `schema_default()` code path in `py_wl_001.py` emits this ID instead
of `PY_WL_001`.

**Breaking change:** Existing exception register entries keyed on `"PY-WL-001"`
for `schema_default()` calls will stop matching because the rule now emits
`"PY-WL-001-UNGOVERNED-DEFAULT"`. This is intentional — we are the only
consumers, and these exceptions should be re-evaluated under the new governance
model rather than silently carried forward.

## JSON Output Schema

All fields are always present. Counts are `0` and detail lists are `[]` when
there is nothing to report. No formal versioning policy until the flag stabilizes.

```json
{
  "version": "1.0",
  "scan_metadata": {
    "wardline_version": "0.2.0",
    "scanned_path": "/home/user/project",
    "timestamp": "2026-03-23T14:30:00Z"
  },
  "unverified_default_count": 12,
  "exception_rereview_count": 3,
  "total_phase2_impact": 15,
  "details": {
    "unverified_defaults": [
      {
        "file": "src/adapters/client.py",
        "line": 42,
        "qualname": "Client.handle",
        "message": "schema_default() without overlay boundary"
      }
    ],
    "exceptions_needing_rereview": [
      {
        "exception_id": "EXC-a1b2c3d4",
        "rule": "PY-WL-001",
        "location": "src/adapters/client.py::Client.handle",
        "reasons": ["stale_fingerprint", "no_expiry"]
      }
    ]
  }
}
```

### Field Definitions

- **`version`**: Schema version string. `"1.0"` for initial release.
- **`scan_metadata.wardline_version`**: Wardline package version.
- **`scan_metadata.scanned_path`**: Absolute path that was scanned.
- **`scan_metadata.timestamp`**: ISO 8601 UTC timestamp of the scan.
- **`unverified_default_count`**: Count of findings with
  `rule_id == "PY-WL-001-UNGOVERNED-DEFAULT"` — ungoverned `schema_default()`
  calls that lack an overlay boundary declaration.
- **`exception_rereview_count`**: Count of **distinct exception IDs** that
  triggered at least one governance finding. A single exception that triggers
  multiple governance signals (e.g., both `unknown_provenance` and `no_expiry`)
  counts as 1, not N.
- **`total_phase2_impact`**: `unverified_default_count + exception_rereview_count`.
- **`details.unverified_defaults`**: List of ungoverned default findings with
  file path, line number, qualified name, and message.
- **`details.exceptions_needing_rereview`**: One entry per distinct exception ID.
  Each entry aggregates all governance reasons for that exception into a
  `reasons` array. The `rule` field contains the original rule the exception
  was granted for. Possible reason values: `stale_fingerprint`,
  `unknown_provenance`, `recurring`, `no_expiry`.

### Governance Reason Mapping

| Pseudo-Rule String Value             | Reason String        |
|--------------------------------------|----------------------|
| `"GOVERNANCE-STALE-EXCEPTION"`       | `stale_fingerprint`  |
| `"GOVERNANCE-UNKNOWN-PROVENANCE"`    | `unknown_provenance` |
| `"GOVERNANCE-RECURRING-EXCEPTION"`   | `recurring`          |
| `"GOVERNANCE-NO-EXPIRY-EXCEPTION"`   | `no_expiry`          |

## Implementation

### New Pseudo-Rule ID: `src/wardline/core/severity.py`

Add `PY_WL_001_UNGOVERNED_DEFAULT` to `RuleId` enum. Mark as pseudo-rule (not
included in `implementedRules`).

### Rule Change: `src/wardline/scanner/rules/py_wl_001.py`

In the ungoverned `schema_default()` emission path, use
`RuleId.PY_WL_001_UNGOVERNED_DEFAULT` instead of `RuleId.PY_WL_001`.

### Pseudo-Rule Registry: `src/wardline/scanner/sarif.py`

Add `RuleId.PY_WL_001_UNGOVERNED_DEFAULT` to both `_PSEUDO_RULE_IDS` and
`_RULE_SHORT_DESCRIPTIONS`. This prevents the ID from appearing in
`implementedRules` and prevents `_check_registry_sync` from treating it as a
missing rule class.

### Governance Finding Enhancements: `src/wardline/scanner/exceptions.py`

Two changes:

1. **`exception_id`**: Governance findings emitted by `_emit_register_governance`
   currently have `exception_id=None`. Add `exception_id=exc.id` to
   `make_governance_finding` so that `build_preview_report` can group governance
   findings by exception ID without fragile message parsing.

2. **`original_rule`**: Governance findings don't carry the rule the exception
   was granted for. Add the exception's `rule` field to the governance finding
   (via the `properties` dict or a new field on `Finding`) so the preview
   report can populate the `rule` field in `exceptions_needing_rereview`.

### New Module: `src/wardline/cli/preview.py`

Single pure function:

```python
def build_preview_report(
    findings: list[Finding],
    governance_findings: list[Finding],
    *,
    scanned_path: str,
    wardline_version: str,
) -> dict:
```

- Filters `findings` for `rule_id == PY_WL_001_UNGOVERNED_DEFAULT` →
  `unverified_defaults`.
- Groups `governance_findings` by `finding.exception_id`. Builds one entry per
  distinct exception, aggregating reasons into a list. Extracts the original
  rule from the governance finding metadata.
- Computes `total_phase2_impact` as
  `len(unverified_defaults) + len(distinct_exception_ids)`.
- Returns the report dict with `scan_metadata` envelope.

### Integration: `src/wardline/cli/scan.py`

After the exception-matching step:

1. If `--preview-phase2` is set, call `build_preview_report()`.
2. Serialize to JSON. Write to `--output` file or stdout.
3. Suppress stderr summary. Apply normal exit code logic.

No changes to `ScanEngine` or SARIF serialization.

## Test Migration

The new pseudo-rule ID changes rule output for ungoverned `schema_default()`
calls. The following existing tests must be updated:

### `test_severity.py`

- Pseudo-rule count assertion: `20` → `21` (one new pseudo-rule added).
- `test_all_pseudo_rules_are_members`: Will pass automatically since the new
  ID is a `RuleId` member, but verify it's included in the pseudo-rule set.

### `test_py_wl_001.py`

7 tests in `TestSchemaDefaultUngoverned` assert `finding.rule_id == RuleId.PY_WL_001`.
These must be updated to assert `RuleId.PY_WL_001_UNGOVERNED_DEFAULT`:

- `test_schema_default_no_boundary_emits_error`
- `test_schema_default_no_boundaries_in_context`
- `test_schema_default_boundary_wrong_function`
- `test_schema_default_boundary_wrong_transition`
- `test_schema_default_boundary_wrong_scope`
- `test_schema_default_nested_in_conditional`
- `test_schema_default_in_async_function`

This is an intentional migration, not test rot.

## Testing

### Unit Tests

- `test_build_preview_report_empty`: No findings → all counts 0, empty lists,
  `scan_metadata` present.
- `test_build_preview_report_unverified_defaults`: Synthetic
  `PY_WL_001_UNGOVERNED_DEFAULT` findings → correct count and details.
- `test_build_preview_report_governance_findings`: Synthetic governance findings
  → correct count, reason mapping, and details.
- `test_build_preview_report_mixed`: Both types → `total_phase2_impact` is sum.
- `test_build_preview_report_ignores_governed_defaults`:
  `PY_WL_001_GOVERNED_DEFAULT` findings are not counted.
- `test_build_preview_report_ignores_regular_py_wl_001`: Regular `PY_WL_001`
  findings (`.get()`, `setdefault`) with ERROR severity are not counted.
- `test_build_preview_report_deduplicates_exceptions`: One exception with 3
  governance findings → `exception_rereview_count` is 1, `reasons` list has 3
  entries.

### Integration Tests

- Run `wardline scan --preview-phase2` against a test fixture containing:
  - A `schema_default()` call without overlay boundary (ungoverned).
  - A `schema_default()` call with overlay boundary (governed).
  - A `.get(key, default)` call with ERROR taint (must NOT appear in report).
  - Exception A: stale fingerprint AND `expires=None` — tests multi-reason
    aggregation (`stale_fingerprint` + `no_expiry` on one entry).
  - Exception B: `agent_originated=None` AND `recurrence_count >= 2` — tests
    `unknown_provenance` + `recurring` reasons.
- Assert `unverified_default_count` is 1 (only the ungoverned `schema_default`).
- Assert `exception_rereview_count` is 2 (two distinct exception IDs).
- Assert Exception A's `reasons` includes `stale_fingerprint` and `no_expiry`.
- Assert Exception B's `reasons` includes `unknown_provenance` and `recurring`.
- Assert exit code 1 (findings present → normal enforcement).
- Assert `scan_metadata` fields are populated.
- Test `--output` flag writes to file.

## Scope Exclusions

- No `--migrate-mvp` command — deferred to backlog (`wardline-a660040169`, P4,
  `needs-consumer` label). No external consumers used the MVP.
- No Phase 2 rule stubs or estimates — those rules don't exist yet. The report
  covers overlay/exception migration impact only.
- No changes to engine or SARIF serialization beyond the pseudo-rule ID in
  `py_wl_001.py`, the `_PSEUDO_RULE_IDS`/`_RULE_SHORT_DESCRIPTIONS` updates in
  `sarif.py`, and the `exception_id`/`original_rule` fixes in `exceptions.py`.
