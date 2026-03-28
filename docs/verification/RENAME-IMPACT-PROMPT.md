# Rename Impact Analysis Prompt

## Purpose

Dispatches an agent to scan the entire codebase and produce a complete,
line-level impact analysis for the two pending renames (ADR-001 taint states,
ADR-002 decorators). The output is a migration manifest — every file and line
that needs to change, grouped by layer, with the exact old→new substitution.

This runs BEFORE any code changes. Its output is the input to the migration
agents.

## The Prompt

---

You are performing a rename impact analysis for the wardline project.

Two ADRs propose renaming core identifiers before v1.0. Your job is to find
every reference to the old names across the entire project and produce a
complete migration manifest.

### The renames

**ADR-001: Taint state tokens**

| Old | New |
|-----|-----|
| `AUDIT_TRAIL` | `INTEGRAL` |
| `PIPELINE` | `ASSURED` |
| `SHAPE_VALIDATED` | `GUARDED` |
| `UNKNOWN_SHAPE_VALIDATED` | `UNKNOWN_GUARDED` |
| `UNKNOWN_SEM_VALIDATED` | `UNKNOWN_ASSURED` |

Unchanged: `EXTERNAL_RAW`, `UNKNOWN_RAW`, `MIXED_RAW`

**ADR-002: Decorator names**

| Old | New |
|-----|-----|
| `audit_writer` | `integral_writer` |
| `audit_critical` | `integrity_critical` |
| `tier1_read` | `integral_read` |
| `authoritative_construction` | `integral_construction` |

Unchanged: `validates_shape`, `validates_semantic`, `validates_external`,
`external_boundary`

### What to scan

Search the ENTIRE project tree (excluding `.venv/`, `.git/`, `__pycache__/`,
`.mypy_cache/`). Include:

- `src/wardline/**/*.py` — all source code
- `tests/**/*.py` — all tests
- `docs/**/*.md` — all documentation (spec, ADRs, plans)
- `corpus/**/*` — specimen files and manifests
- `*.yaml`, `*.yml` — all YAML files (manifests, CI, overlays)
- `*.json` — all JSON files (schemas, exception register, fingerprints, corpus manifest)
- `*.toml` — config files
- `*.md` — root-level markdown (README, CONTRIBUTING, etc.)
- `CLAUDE.md`, `AGENTS.md` — instruction files

### What to find

For each old name, search for:

1. **Exact enum member references:** `TaintState.AUDIT_TRAIL`, `AUDIT_TRAIL`
   as a string literal, `"AUDIT_TRAIL"` in YAML/JSON
2. **Variable/function names containing the old token:** `audit_trail_taint`,
   `_AUDIT_DECORATORS`, `is_audit_scoped`
3. **String literals containing the old name:** error messages, log messages,
   comments, docstrings
4. **Directory/file names:** `corpus/specimens/PY-WL-001/AUDIT_TRAIL/`
5. **YAML/JSON field values:** `taint_state: AUDIT_TRAIL` in manifests,
   exceptions, corpus metadata
6. **Spec prose:** "AUDIT_TRAIL" in spec documents, even in narrative text
7. **Comments and docstrings:** references to old names in documentation

For decorator renames, also search for:
1. **Decorator usage:** `@audit_writer`, `@audit_critical`
2. **Registry keys:** `"audit_writer"` in `REGISTRY`
3. **Test fixtures:** `audit_writer` in test code
4. **Heuristic detection:** PY-WL-006's `_AUDIT_DECORATORS` and name-based detection
5. **Spec references:** "audit_writer" in spec documents

### Output format

```markdown
# Rename Migration Manifest

Generated: YYYY-MM-DD
ADRs: ADR-001 (taint states), ADR-002 (decorators)

## Statistics

- Total files affected: N
- Total lines affected: N
- By layer:
  - Core source: N files, N lines
  - Scanner source: N files, N lines
  - Manifest source: N files, N lines
  - Decorators source: N files, N lines
  - Runtime source: N files, N lines
  - CLI source: N files, N lines
  - Tests: N files, N lines
  - Spec docs: N files, N lines
  - Schemas: N files, N lines
  - Corpus: N files, N lines (+ N directory renames)
  - Config/manifests: N files, N lines
  - Instruction files: N files, N lines

## Layer 1: Core Source (src/wardline/core/)

### core/taints.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 12 | `AUDIT_TRAIL = "AUDIT_TRAIL"` | `INTEGRAL = "INTEGRAL"` | TaintState enum member |
| 13 | `PIPELINE = "PIPELINE"` | `ASSURED = "ASSURED"` | TaintState enum member |
| ... | ... | ... | ... |

### core/tiers.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| ... | ... | ... | ... |

[Continue for every file in every layer]

## Directory Renames

| Old Path | New Path |
|----------|----------|
| `corpus/specimens/PY-WL-001/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-001/INTEGRAL/` |
| ... | ... |

## Ordering Constraints

[List any ordering dependencies — e.g., "rename TaintState enum before
updating TAINT_TO_TIER because the latter references the former"]

## Risk Areas

[Flag anything that's not a simple find-and-replace:
- Partial matches (e.g., `AUDIT_TRAIL` inside `AUDIT_TRAIL_TAINT`)
- Conditional logic keyed on old names
- External-facing strings that adopters might depend on
- Heuristic detection in rules that uses name patterns]
```

### Rules

1. **Be exhaustive.** Miss nothing. A single unrenamed reference breaks the
   build or produces wrong taint assignments.

2. **Use grep/glob, not inference.** Actually search for each old name. Don't
   assume a file is clean because it "probably doesn't reference taint states."

3. **Include comments and docstrings.** A comment saying "AUDIT_TRAIL is T1"
   is wrong after the rename.

4. **Include spec documents.** The spec defines these names — it must be
   updated too.

5. **Flag partial matches.** `AUDIT_TRAIL` appears inside
   `UNKNOWN_SEM_VALIDATED` — make sure partial-match renames don't corrupt
   compound tokens. Document the safe replacement order.

6. **Count directory renames separately.** These require `git mv`, not
   sed/replace.

7. **Note the safe replacement order.** Longer tokens first to avoid
   partial-match corruption:
   - `UNKNOWN_SHAPE_VALIDATED` before `SHAPE_VALIDATED`
   - `UNKNOWN_SEM_VALIDATED` before any shorter match
   - `AUDIT_TRAIL` is safe (no longer token contains it)
   - `authoritative_construction` before any shorter match

---

## Usage

```
Agent type: general-purpose
Model: opus (exhaustive search requires judgment about partial matches)
Input: entire project tree
Output: docs/verification/rename-migration-manifest.md
```

This agent runs once. Its output feeds the migration execution agents.
The manifest should be reviewed by a human before execution begins —
a missed reference here means a broken build after migration.
