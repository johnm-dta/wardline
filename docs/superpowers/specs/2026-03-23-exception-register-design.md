# WP 1.4: Exception Register — Design Spec

**Date:** 2026-03-23
**Status:** Draft
**Work Package:** wardline-6730f5a533
**Blocks:** WP 1.7 (Migration Tooling), WP 2.3 (Full Governance CLI)

## Summary

Implement the exception register: load `wardline.exceptions.json`, match
exceptions against findings using a four-tuple key with mandatory AST
fingerprinting, suppress matched findings to SARIF `note` level with
audit metadata, enforce threat controls (agent provenance, recurrence
escalation, governance path tracking), and provide CLI commands for
exception lifecycle management with zero-friction MCP integration.

## Change 1: Exception Loading

**Files:** `src/wardline/manifest/exceptions.py` (new),
`src/wardline/manifest/models.py`, `src/wardline/manifest/schemas/exceptions.schema.json`

### Model changes

Add three fields to `ExceptionEntry` in `models.py`:

```python
ast_fingerprint: str = ""       # 16-char hex SHA-256 of function AST
recurrence_count: int = 0       # renewal counter
governance_path: str = "standard"  # "standard" or "expedited"
```

### Schema changes

Update `exceptions.schema.json`:
- Add `ast_fingerprint` as an optional field (NOT in the `required` array).
  Empty string = always treated as stale. The CLI `add` command always computes
  and sets it. Old entries without fingerprints will trigger
  GOVERNANCE-STALE-EXCEPTION on first scan, prompting `refresh`.
- Add `recurrence_count` (integer, minimum 0, default 0)
- Add `governance_path` (enum: `["standard", "expedited"]`)

### Loading

New module `src/wardline/manifest/exceptions.py`:

```python
def load_exceptions(manifest_dir: Path) -> tuple[ExceptionEntry, ...]:
    """Load and validate wardline.exceptions.json from the manifest directory.

    Returns empty tuple if the file does not exist (no exceptions = valid state).
    Raises ManifestLoadError on schema validation failure.

    Load-time UNCONDITIONAL re-validation: each entry's (rule, taint_state) is
    validated against the severity matrix. Entries targeting UNCONDITIONAL cells
    are rejected with ManifestLoadError — these exceptions should never have been
    granted and indicate register corruption or manual tampering.
    """
```

Discovery convention: `wardline.exceptions.json` lives alongside
`wardline.yaml` (project-level governance, not per-overlay). Absence of
the file is not an error — it means no exceptions are granted.

`governance_path` should be a `StrEnum`. Add `GovernancePath` enum to
`src/wardline/core/severity.py`:

```python
class GovernancePath(StrEnum):
    STANDARD = "standard"
    EXPEDITED = "expedited"
```

**Tests (unit):**
- File exists with valid entries → returns tuple of ExceptionEntry
- File does not exist → returns `()`
- Invalid schema → raises `ManifestLoadError`
- Entry with missing `ast_fingerprint` → loads with default empty string
- Entry targeting UNCONDITIONAL cell → raises `ManifestLoadError`
- Valid entries with optional fields omitted → defaults applied

## Change 2: AST Fingerprint Computation

**File:** `src/wardline/scanner/fingerprint.py` (new)

```python
def compute_ast_fingerprint(file_path: Path, qualname: str) -> str | None:
    """Compute 16-char hex fingerprint for a function's AST structure.

    The fingerprint is rule-independent — it represents the function's code
    structure, not a specific finding. Any structural change to the function
    invalidates ALL exceptions targeting it.

    Algorithm: sha256(f"{sys.version_info.major}.{sys.version_info.minor}|{file_path}|{qualname}|{dump}")[:16]

    Python version is included because AST representations can change between
    minor versions. Python version upgrades require `wardline exception refresh --all`.

    include_attributes=False strips line numbers and column offsets, making
    the fingerprint immune to whitespace/formatting changes but sensitive
    to any structural code change.

    Returns None if the file can't be parsed or qualname is not found.
    """
```

The function:
1. Parses the file to AST
2. Walks the AST to find the function matching `qualname` (using the same
   scope-stack logic as `RuleBase._dispatch`)
3. Computes `ast.dump(func_node, include_attributes=False, annotate_fields=True)`
4. Returns `sha256(f"{sys.version_info.major}.{sys.version_info.minor}|{file_path}|{qualname}|{dump}")[:16]`

**Scope-stack extraction:** Extract qualname resolution into
`src/wardline/scanner/_scope.py`, shared by `RuleBase` and `fingerprint.py`.
This avoids duplicating the scope-stack walk logic across two modules.

**Why rule-independent:** The same function may have multiple exceptions for
different rules. A code change should invalidate all of them — the reviewer
needs to re-assess the entire function, not just one finding pattern.

**Tests (unit):**
- Known function → deterministic 16-char hex string
- Formatting-only change (add whitespace) → same fingerprint
- Structural change (add statement) → different fingerprint
- Nonexistent file → None
- Nonexistent qualname → None
- Class method `"MyClass.handle"` → fingerprint of the method body
- Nested function → correct scope resolution

## Change 3: Exception Matching + Suppression

**File:** `src/wardline/scanner/exceptions.py` (new)

```python
def apply_exceptions(
    findings: list[Finding],
    exceptions: tuple[ExceptionEntry, ...],
    project_root: Path,
) -> tuple[list[Finding], list[Finding]]:
    """Match findings against active exceptions, returning (results, governance_findings).

    For each finding, check for a matching active exception. Match requires ALL:
    1. exception.rule == str(finding.rule_id)
    2. exception.taint_state == str(finding.taint_state)
    3. exception.location == f"{finding.file_path}::{qualname}"
    4. exception.ast_fingerprint == current fingerprint at that location
    5. Exception is not expired
    6. Finding exceptionability is not UNCONDITIONAL

    Finding is frozen (dataclass). Suppressed findings are created via
    `dataclasses.replace()` — the original Finding is never mutated. The
    replacement carries `exception_id` and `exception_expires` fields that
    flow through to SARIF serialization.

    On match: a new Finding is created via `dataclasses.replace(finding,
    severity=SUPPRESS, exceptionability=TRANSPARENT,
    exception_id=exception.id, exception_expires=exception.expires)`.

    On fingerprint mismatch: GOVERNANCE-STALE-EXCEPTION finding emitted (WARNING).
    On agent_originated=None: GOVERNANCE-UNKNOWN-PROVENANCE finding emitted (WARNING).
    On recurrence_count >= 2: GOVERNANCE-RECURRING-EXCEPTION finding emitted (WARNING).
    On expires=null: GOVERNANCE-NO-EXPIRY-EXCEPTION finding emitted (WARNING).
    """
```

**Pipeline placement:** Called in the CLI layer (`scan.py`) between engine
scan and SARIF serialization. The engine does not know about exceptions —
clean separation of concerns.

**New pseudo-rule IDs** (add to `RuleId` enum, 5 total):
- `GOVERNANCE_STALE_EXCEPTION = "GOVERNANCE-STALE-EXCEPTION"`
- `GOVERNANCE_UNKNOWN_PROVENANCE = "GOVERNANCE-UNKNOWN-PROVENANCE"`
- `GOVERNANCE_RECURRING_EXCEPTION = "GOVERNANCE-RECURRING-EXCEPTION"`
- `GOVERNANCE_BATCH_REFRESH = "GOVERNANCE-BATCH-REFRESH"`
- `GOVERNANCE_NO_EXPIRY_EXCEPTION = "GOVERNANCE-NO-EXPIRY-EXCEPTION"`

All five are pseudo-rules: they appear in SARIF `results` but NOT in
`wardline.implementedRules`. Add to `_PSEUDO_RULE_IDS` in `sarif.py`.

`RuleId` enum count goes from 15 to 20 (15 current + 5 new governance IDs).
`test_severity.py` count assertion must be updated accordingly.

**Location format:** `file_path::qualname` (e.g.,
`"src/adapters/client.py::Client.handle"`). The `::` separator is
unambiguous — file paths use `/`, qualnames use `.`, neither uses `::`.

**Qualname extraction from findings:** Findings currently carry `file_path`,
`line`, `col` but not `qualname`. The matching function needs to resolve
line/col back to a qualname. Two options:
- (A) Add `qualname: str | None` to `Finding` — populated during rule execution
  from `self._current_qualname`
- (B) Re-parse the AST and resolve line→qualname at matching time

**Decision: (A)** — add `qualname` to Finding. Rules already have
`self._current_qualname` available. This avoids re-parsing and is O(1) at
match time. The field is optional (`None` for findings not inside a function,
e.g., module-level findings).

**New Finding fields** (all added to `Finding` dataclass in `context.py`):
- `qualname: str | None = None` — populated from `self._current_qualname`
- `exception_id: str | None = None` — set by `apply_exceptions` via `replace()`
- `exception_expires: str | None = None` — set by `apply_exceptions` via `replace()`

Adding these defaulted fields requires `kw_only=True` on Finding's
`@dataclass` decorator to prevent silent positional omission of earlier fields.

**Match index:** Build `dict[tuple[str, str, str], list[ExceptionEntry]]` keyed
on `(rule, taint_state, location)` for O(n+m) matching instead of O(n*m).

**File parse caching:** Cache parsed ASTs per-file within `apply_exceptions` to
avoid re-parsing the same file for multiple findings/exceptions.

**Tests (unit):**
- Finding with matching active exception → SUPPRESS + metadata
- Finding with expired exception → not suppressed
- Finding with fingerprint mismatch → not suppressed + GOVERNANCE-STALE-EXCEPTION
- Finding with UNCONDITIONAL exceptionability → not suppressed (even if exception exists)
- Finding with no matching exception → unchanged
- Exception with `agent_originated=None` → GOVERNANCE-UNKNOWN-PROVENANCE
- Exception with `recurrence_count >= 2` → GOVERNANCE-RECURRING-EXCEPTION
- Exception with `expires: null` → GOVERNANCE-NO-EXPIRY-EXCEPTION (WARNING)
- Multiple findings, some matched, some not → correct partition

## Change 4: CLI Exception Commands

**File:** `src/wardline/cli/exception_cmds.py` (new)

### `wardline exception add`

Creates a new exception entry in `wardline.exceptions.json`:

```
wardline exception add \
  --rule PY-WL-001 \
  --location "src/adapters/client.py::Client.handle" \
  --taint-state EXTERNAL_RAW \
  --rationale "Schema fallback approved by security review" \
  --reviewer "jsmith" \
  --expires 2027-03-23 \
  --governance-path standard
```

The command:
1. Parses the target file's AST
2. Finds the function at the qualname
3. Computes `ast_fingerprint` automatically
4. Validates the taint state is a valid `TaintState` member
5. Validates exceptionability for the (rule, taint) allows exceptions (not UNCONDITIONAL)
6. Generates a UUID for the exception ID
7. Sets `recurrence_count: 0`, `governance_path` from flag
8. Writes the entry to `wardline.exceptions.json` (creates file if absent)

Refuses to create exceptions for:
- UNCONDITIONAL findings (exceptionability check)
- Nonexistent files or qualnames
- Invalid rule IDs or taint states
- Agent-originated exceptions without `--expires` (null expiry disallowed
  for agents; during `apply_exceptions`, exceptions with `expires: null`
  emit GOVERNANCE-NO-EXPIRY-EXCEPTION WARNING regardless of origin)

### `wardline exception refresh`

**The MCP-friendly batch command.** Recomputes AST fingerprints for existing
exceptions against current code:

```
wardline exception refresh EXC-001 EXC-002 EXC-003 \
  --actor jsmith --rationale "Reviewed: whitespace-only change"
wardline exception refresh --all --actor bot-1 --rationale "Post-upgrade recompute" --confirm
```

**Required flags:** `--actor` and `--rationale` are mandatory on every refresh.
Records `last_refreshed_by` and `last_refresh_rationale` on the exception entry.
If the refresher is an agent, sets `refresh_agent_originated: bool = true`.

**`--all` requires `--confirm`** and emits a `GOVERNANCE-BATCH-REFRESH` finding
(WARNING level) to the next scan output as an audit trail.

For each exception:
1. Parse the file at the exception's location
2. Find the function at the qualname
3. Compute the current AST fingerprint
4. If changed: update `ast_fingerprint`. Do NOT increment `recurrence_count` —
   recurrence only increments on an explicit `expire` + `add` renewal cycle.
5. If qualname no longer exists: report as stale (do not update)

**Rule context display:** Before accepting the refresh, the command displays
the rule being excepted, a short explanation of why it matters, and why an
exception requires justification. This is the cognitive forcing function —
an LLM will follow the governance rule if you explain it clearly:

```
Exception EXC-001 for PY-WL-001 (Dict key access with fallback default)

  This rule detects code that silently fabricates values for missing dictionary
  keys, bypassing validation. In a security context, fabricated defaults can
  mask data corruption or inject unvalidated values into trusted pipelines.

  This exception was granted because: "Schema fallback approved by security review"
  Code at: src/adapters/client.py::Client.handle

  The AST fingerprint has changed — the function's code structure was modified
  since this exception was last reviewed.

  To refresh, you must explain why the code change does not affect the security
  finding. If the change alters data flow, validation logic, or the default
  value being fabricated, the exception may no longer be valid.

  --rationale is required.
```

The rule short descriptions come from `_RULE_SHORT_DESCRIPTIONS` in `sarif.py`.
The explanatory paragraph is a new `_RULE_GOVERNANCE_CONTEXT` dict in
`exception_cmds.py` — one paragraph per rule explaining the security
relevance and what to look for when reviewing a code change.

**MCP workflow:**
1. Agent sees `GOVERNANCE-STALE-EXCEPTION` in scan output
2. `wardline exception refresh <id> --dry-run` displays the rule context above
3. Agent reviews the code change in light of the rule explanation
4. Agent must formulate a rationale addressing why the change is safe
5. If safe: `wardline exception refresh <id> --actor agent-name --rationale "..."`
6. If exception no longer valid: `wardline exception expire <id>`

The rationale is the governance gate. An agent that cannot articulate why
a code change is safe with respect to the specific rule should not refresh
the exception.

### `wardline exception expire`

Marks exceptions as expired:

```
wardline exception expire EXC-001 --reason "Code refactored, no longer applicable"
```

Sets `expires` to today's date. The exception remains in the file for
audit trail but no longer suppresses findings.

### `wardline exception review`

Lists exceptions needing attention:

```
wardline exception review
```

Reports:
- **Stale**: fingerprint mismatch (code changed since grant)
- **Expired**: past expiry date
- **Approaching expiry**: within 30 days of expiry
- **Unknown provenance**: `agent_originated` is null
- **Recurring**: `recurrence_count >= 2`
- **Expedited ratio**: proportion of expedited vs standard exceptions

All commands support `--json` for machine consumption.

**Tests (integration):**
- `add` → `review` → `expire` lifecycle
- `add` → code change → `refresh` does NOT increment `recurrence_count`
- `expire` → `add` (renewal) increments `recurrence_count`
- `add` with UNCONDITIONAL finding → refused
- `refresh` without `--actor` or `--rationale` → error
- `refresh --all` without `--confirm` → error
- `refresh --all --confirm` updates all non-expired exceptions + emits GOVERNANCE-BATCH-REFRESH
- `add` agent-originated without `--expires` → refused
- `--json` output is valid JSON

## Change 5: SARIF Integration

**File:** `src/wardline/scanner/sarif.py`

### Finding-level properties

Suppressed findings gain property bag entries:
- `wardline.exceptionId` — the matching exception's ID
- `wardline.exceptionExpires` — expiry date (or null for no-expiry)

### Run-level properties

Add to SARIF run properties:
- `wardline.activeExceptionCount` — number of non-expired exceptions loaded
- `wardline.suppressedFindingCount` — number of findings suppressed by exceptions
- `wardline.staleExceptionCount` — fingerprint mismatches detected
- `wardline.expeditedExceptionRatio` — proportion of expedited exceptions (0.0-1.0)

### Pseudo-rule descriptors

Add short descriptions for the five new governance rule IDs to
`_RULE_SHORT_DESCRIPTIONS` and add them to `_PSEUDO_RULE_IDS`.

## Change 6: CLI Scan Pipeline Wiring

**File:** `src/wardline/cli/scan.py`

After engine scan completes and before SARIF serialization:

```python
# --- Apply exception register ---
exceptions = load_exceptions(manifest_path.parent)
findings, governance_findings = apply_exceptions(
    result.findings, exceptions, project_root=manifest_path.parent
)
result.findings = findings + governance_findings
```

Exception loading errors (`ManifestLoadError`) should abort the scan —
a malformed exception register is a governance error, same as a malformed
manifest.

## Files Changed

| File | Change |
|------|--------|
| `src/wardline/manifest/models.py` | Add `ast_fingerprint`, `recurrence_count`, `governance_path` to `ExceptionEntry` |
| `src/wardline/manifest/schemas/exceptions.schema.json` | Add optional `ast_fingerprint`, add `recurrence_count`, `governance_path` |
| `src/wardline/manifest/exceptions.py` | **New** — `load_exceptions()` |
| `src/wardline/scanner/fingerprint.py` | **New** — `compute_ast_fingerprint()` |
| `src/wardline/scanner/exceptions.py` | **New** — `apply_exceptions()` |
| `src/wardline/scanner/context.py` | Add `qualname`, `exception_id`, `exception_expires` to `Finding`; add `kw_only=True` |
| `src/wardline/scanner/_scope.py` | **New** — extracted qualname scope-stack utility shared by `RuleBase` and `fingerprint.py` |
| `src/wardline/core/severity.py` | Add 5 governance pseudo-rule IDs + `GovernancePath` StrEnum |
| `src/wardline/rules/py_wl_001.py` | Backfill `qualname=self._current_qualname` in all Finding constructions |
| `src/wardline/rules/py_wl_002.py` | Backfill `qualname=self._current_qualname` in all Finding constructions |
| `src/wardline/rules/py_wl_003.py` | Backfill `qualname=self._current_qualname` in all Finding constructions |
| `src/wardline/rules/py_wl_004.py` | Backfill `qualname=self._current_qualname` in all Finding constructions |
| `src/wardline/rules/py_wl_005.py` | Backfill `qualname=self._current_qualname` in all Finding constructions |
| `src/wardline/scanner/sarif.py` | Property bags, pseudo-rule descriptors |
| `src/wardline/cli/exception_cmds.py` | **New** — `add`, `refresh`, `expire`, `review` commands |
| `src/wardline/cli/scan.py` | Wire exception loading + matching into scan pipeline |
| `src/wardline/cli/main.py` | Register exception subcommands |
| `tests/unit/manifest/test_exceptions.py` | **New** — loading tests |
| `tests/unit/scanner/test_fingerprint.py` | **New** — fingerprint computation tests |
| `tests/unit/scanner/test_exception_matching.py` | **New** — matching + suppression tests |
| `tests/integration/test_exception_cmds.py` | **New** — CLI lifecycle tests |
| `tests/unit/core/test_severity.py` | Enum count (15 → 20) + pseudo-rule membership |
| `tests/unit/scanner/test_sarif.py` | Property bag + pseudo-rule exclusion |

## Out of Scope

- Per-overlay exception registers (exceptions are project-level)
- `optional_fields` cross-reference with exceptions (tracked: `wardline-d7be55cfd4`)
- `overlay_for` path verification on exceptions (tracked: `wardline-f132f7cc55`)
- Exception delegation authority enforcement (DelegationConfig exists but
  enforcement is deferred to a governance hardening pass)
- `wardline exception review --migrate-mvp` (deferred to WP 1.7)
- `wardline.propertyBagVersion` increment decision (deferred)
