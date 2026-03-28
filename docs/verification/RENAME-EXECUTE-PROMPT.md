# Rename Execution Agent Prompt

## Purpose

Dispatches agents to execute the rename migration, one layer at a time,
using the migration manifest as the authoritative checklist. Each agent
handles one layer, commits its changes, and runs verification.

## The Prompt Template

Fill in `{{LAYER}}`, `{{MANIFEST_SECTION}}`, and `{{VERIFICATION}}`.

---

You are executing a rename migration for the wardline project.

**Your layer:** `{{LAYER}}`

**Context:** The project is renaming taint state tokens and decorator names
before v1.0 (ADR-001 and ADR-002). A migration manifest has been produced
listing every file and line that needs to change. You are responsible for
your layer only.

### Rename tables

**Taint states (ADR-001):**

| Old | New |
|-----|-----|
| `AUDIT_TRAIL` | `INTEGRAL` |
| `PIPELINE` | `ASSURED` |
| `SHAPE_VALIDATED` | `GUARDED` |
| `UNKNOWN_SHAPE_VALIDATED` | `UNKNOWN_GUARDED` |
| `UNKNOWN_SEM_VALIDATED` | `UNKNOWN_ASSURED` |

**Decorators (ADR-002):**

| Old | New |
|-----|-----|
| `audit_writer` | `integral_writer` |
| `audit_critical` | `integrity_critical` |
| `tier1_read` | `integral_read` |
| `authoritative_construction` | `integral_construction` |

### Your migration manifest section

{{MANIFEST_SECTION}}

(Paste the relevant layer section from rename-migration-manifest.md)

### Replacement rules

1. **Replace longest tokens first** to avoid partial-match corruption:
   - `UNKNOWN_SHAPE_VALIDATED` → `UNKNOWN_GUARDED` before
   - `SHAPE_VALIDATED` → `GUARDED`
   - `UNKNOWN_SEM_VALIDATED` → `UNKNOWN_ASSURED` before any shorter match
   - `authoritative_construction` → `integral_construction` before
   - `audit_critical` → `integrity_critical` before
   - `audit_writer` → `integral_writer`

2. **Preserve case conventions.** If the old name appears as:
   - `AUDIT_TRAIL` (constant) → `INTEGRAL`
   - `audit_trail` (lowercase) → `integral`
   - `AuditTrail` (PascalCase) → `Integral`
   - `"AUDIT_TRAIL"` (string literal) → `"INTEGRAL"`

3. **Don't rename unchanged tokens.** `EXTERNAL_RAW`, `UNKNOWN_RAW`,
   `MIXED_RAW`, `validates_shape`, `validates_semantic`, `validates_external`,
   `external_boundary` stay as-is.

4. **Update comments and docstrings** that reference old names.

5. **For directory renames** use `git mv` to preserve history.

### Verification

{{VERIFICATION}}

After all changes, run the verification commands. If any fail, investigate
and fix before committing.

### Commit

```bash
git commit -m "rename({{LAYER}}): ADR-001/002 taint state and decorator rename"
```

---

## Dispatch Guide

### Layer execution order

The layers MUST be executed in this order because later layers depend on
earlier ones compiling:

```
Layer 1: Core source        (taints.py, tiers.py, severity.py, matrix.py, registry.py)
    ↓
Layer 2: Scanner source     (engine, rules, taint propagation, context, sarif, exceptions)
    ↓
Layer 3: Manifest source    (models, loader, merge, coherence, resolve, scope, discovery)
    ↓
Layer 4: Decorators source  (decorator definitions)
    ↓
Layer 5: Runtime source     (enforcement, base, descriptors, protocols)
    ↓
Layer 6: CLI source         (all cli/*.py)
    ↓
Layer 7: Tests              (all tests/**/*.py)
    ↓
Layer 8: Schemas            (manifest/schemas/*.json)
    ↓
Layer 9: Corpus             (specimens, corpus_manifest.json — includes directory renames)
    ↓
Layer 10: Config/Manifests  (wardline.yaml, wardline.toml, wardline.exceptions.json,
                             wardline.fingerprint.json, wardline.conformance.json)
    ↓
Layer 11: Documentation     (spec docs, ADRs, README, CONTRIBUTING, CLAUDE.md, AGENTS.md)
```

### Verification commands per layer

| Layer | Verification |
|-------|-------------|
| 1 (Core) | `uv run python3 -c "from wardline.core.taints import TaintState; print(list(TaintState))"` |
| 2 (Scanner) | `uv run python3 -c "from wardline.scanner.engine import ScanEngine; print('OK')"` |
| 3 (Manifest) | `uv run python3 -c "from wardline.manifest.models import WardlineManifest; print('OK')"` |
| 4 (Decorators) | `uv run python3 -c "from wardline.decorators import integral_writer; print('OK')"` |
| 5 (Runtime) | `uv run python3 -c "from wardline.runtime.enforcement import stamp_tier; print('OK')"` |
| 6 (CLI) | `uv run wardline --help` |
| 7 (Tests) | `uv run pytest tests/ -q --tb=short` |
| 8 (Schemas) | `uv run python3 -c "import json, jsonschema; print('OK')"` |
| 9 (Corpus) | `uv run wardline corpus verify --json` (may need manifest regen first) |
| 10 (Config) | `uv run wardline scan src/wardline --manifest wardline.yaml` (smoke test) |
| 11 (Docs) | `grep -r 'AUDIT_TRAIL\|PIPELINE\|SHAPE_VALIDATED\|audit_writer\|audit_critical\|tier1_read\|authoritative_construction' docs/ *.md` (expect zero matches) |

### Model selection

- **Layers 1-6:** Sonnet — mechanical find-and-replace with compilation check
- **Layer 7 (Tests):** Sonnet — largest layer but still mechanical
- **Layer 9 (Corpus):** Sonnet — directory renames + YAML value updates
- **Layer 11 (Docs):** Opus — spec prose requires judgment about context

### Parallelisation

Layers 1-6 are sequential (import dependencies). Layers 7-11 can run in
parallel after Layer 6 completes (they don't import from each other).

### Cost estimate

Each layer agent reads its manifest section (~1-5 pages) + the affected files.
Total across all 11 layers: ~200k-300k tokens.
