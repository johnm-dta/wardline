# Spec Part I Narrative Rename Prompt

## Purpose

Update the framework specification (Part I) to use the posture vocabulary
established by ADR-001. This is prose editing, not mechanical find-and-replace.

## Context

ADR-001 renamed the canonical taint state tokens from prototype-era names to
posture vocabulary:

| Old (prototype) | New (posture) | Tier |
|-----------------|---------------|------|
| Audit Trail | Integral | T1 |
| Pipeline | Assured | T2 |
| Shape-Validated | Guarded | T3 |
| External Raw | External Raw | T4 (unchanged) |
| Unknown Raw | Unknown Raw | (unchanged) |
| Unknown Shape-Validated | Unknown Guarded | |
| Unknown Semantically-Validated | Unknown Assured | |

The Python binding (Part II-A) and Java binding (Part II-B) matrix tables
have already been updated. The Part I spec documents still use the old names
throughout the narrative prose.

## The Prompt

---

You are updating the wardline framework specification (Part I) to use the
posture vocabulary from ADR-001. This is prose editing — the goal is natural,
readable spec text that uses the new names fluently, not mechanical
find-and-replace.

### Files to edit

All files matching `docs/spec/wardline-01-*.md`. Read each file in full
before making changes.

### What to rename

**In tables, headings, and code-like references:**
- `Audit Trail` → `Integral`
- `Pipeline` → `Assured`
- `Shape-Validated` / `Shape Validated` → `Guarded`
- `Unknown Shape-Validated` → `Unknown Guarded`
- `Unknown Semantically-Validated` / `Unknown Sem-Validated` → `Unknown Assured`

**In prose** (more judgment required):
- "the Audit Trail tier" → "the Integral tier"
- "Pipeline data" → "Assured data"
- "shape-validated code" → "guarded code"
- "audit trail zone" → "integral zone"

### What NOT to rename

1. **The taxonomy pattern name "Audit Trail Destruction" (ACF-R1).**
   This is a named anti-pattern in the failure taxonomy, not a tier reference.
   It describes the consequence (destroying the audit trail) not the tier.
   Leave it as-is — it's a domain concept name, like "SQL Injection."

2. **References to actual audit logging.** If the text says "audit log" or
   "audit record" meaning a literal log/record for compliance purposes,
   that's not a tier reference. Leave it.

3. **The word "audit" in general prose** when it means "review" or
   "examination" (e.g., "audit the codebase"). Only rename tier-specific
   uses.

4. **"pipeline" in general prose** when it means "data pipeline" or
   "CI pipeline" rather than the Tier 2 taint state.

5. **Quotations from external standards or references.**

### Prose style guidance

The new names are adjectives describing coding posture:
- INTEGRAL = "essential, must not fail, foundational to correctness"
- ASSURED = "values trusted within their declared validation scope"
- GUARDED = "structure trusted, semantic values not yet verified"

When rewriting prose:
- "In the audit trail zone, code must..." → "In the integral zone, code must..."
- "Data entering the pipeline..." → "Data entering the assured tier..."
- "After shape validation, the data is shape-validated" → "After shape validation, the data is guarded"

The descending-stakes story should read naturally: integral (highest stakes)
→ assured → guarded → external raw (lowest stakes).

### The §5.1 defensive NOTE

ADR-001 specifically calls out this note for deletion:

> NOTE — Token names are canonical labels, not scope restrictions.
> AUDIT_TRAIL encompasses all Tier 1 authoritative internal data [...],
> not only audit trails specifically.

If this note still exists, **delete it entirely**. The whole point of the
rename is that the names no longer need this disclaimer.

### Verification

After all edits:

1. Run: `grep -rn 'Audit Trail\|AUDIT_TRAIL\|Pipeline\|PIPELINE\|Shape.Validated\|SHAPE_VALIDATED' docs/spec/wardline-01-*.md`

   Expected matches: ONLY in these contexts:
   - "Audit Trail Destruction" (taxonomy pattern name — leave)
   - "pipeline" lowercase when meaning data/CI pipeline generically
   - Any quotation from an external standard

   Everything else should be gone.

2. Read the edited sections aloud. Do they read naturally with the new
   vocabulary, or do they feel like find-and-replace artifacts?

### Commit

```bash
git add docs/spec/wardline-01-*.md
git commit -m "docs(spec): update Part I narrative to posture vocabulary (ADR-001)

Renames tier references throughout framework spec:
- Audit Trail → Integral (T1)
- Pipeline → Assured (T2)
- Shape-Validated → Guarded (T3)
- Unknown Shape-Validated → Unknown Guarded
- Unknown Sem-Validated → Unknown Assured

Preserves 'Audit Trail Destruction' taxonomy name (ACF-R1)
and generic uses of 'audit'/'pipeline' not referring to tiers.
Deletes §5.1 defensive NOTE (no longer needed — names are self-explanatory)."
```

---

## Usage

```
Agent type: general-purpose
Model: opus (prose editing requires judgment about context)
Input: docs/spec/wardline-01-*.md (15 files)
Output: edited files in place
```

This agent reads and edits in place. No separate output file.
The key skill is distinguishing tier references from general English
usage of the same words.
