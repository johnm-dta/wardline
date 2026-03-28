# Minispec Extraction Prompt

## Purpose

This prompt is used to dispatch an agent that reads the full wardline specification
and produces a machine-relevant minispec — a structured, flat list of every
normative requirement, stripped of rationale and prose, with code traceability.

The minispec is the single source of truth for all downstream verification agents.
They never read the full spec; they read the minispec.

## The Prompt

---

You are extracting a machine-relevant minispec from the wardline specification.

**Input:** All files in `docs/spec/` (read every `.md` file).

**Output:** A single file `docs/verification/minispec.md` containing every
normative requirement from the specification, formatted for consumption by
verification agents.

### What counts as a normative requirement

A normative requirement is any statement that constrains the implementation.
Look for:

- **Explicit normative language:** MUST, SHALL, MUST NOT, SHALL NOT, SHOULD,
  SHOULD NOT, REQUIRED, RECOMMENDED
- **Defined values:** enumerations, constants, tables with specific values
  (e.g., the severity matrix, taint state names, tier numbers)
- **Structural constraints:** "X contains Y", "X maps to Y", "X is immutable"
- **Behavioural contracts:** "when X happens, Y must follow", "X before Y",
  "X produces Y"
- **Invariants:** commutativity, transitivity, monotonicity, idempotency
  properties stated about operations

### What to exclude

- Rationale, motivation, examples (unless the example IS the specification)
- Forward references to unimplemented features ("future work")
- Non-normative notes (prefixed with "Note:" or in informative sections)
- Language-binding-specific content (Part II) unless it overrides Part I

### Output format

```markdown
# Wardline Minispec

Extracted from: docs/spec/wardline-01-*.md
Extraction date: YYYY-MM-DD

## How to read this document

Each requirement has:
- **ID**: REQ-SECTION-NNN (e.g., REQ-5.1-001)
- **Source**: spec filename and section number
- **Statement**: the normative requirement, one sentence
- **Criterion**: how to verify pass/fail (what to check in code)
- **Subsystem**: which code subsystem(s) this applies to
- **Priority**: MUST / SHOULD / MAY

---

## Section N: [Section Title]

### REQ-N.M-001: [Short name]
- **Source:** wardline-01-0N-section-name.md, §N.M
- **Statement:** [One sentence. Use the spec's own words where possible,
  but compress. No rationale.]
- **Criterion:** [What a verification agent checks. Be specific:
  "TaintState enum has exactly 8 members with these values: ..."
  NOT "TaintState enum is correct"]
- **Subsystem:** core/taints.py
- **Priority:** MUST
```

### Extraction rules

1. **One requirement per normative statement.** If a paragraph contains three
   MUSTs, extract three requirements. Do not merge.

2. **Tables become multiple requirements.** A severity matrix with 72 cells
   becomes 72 requirements (or grouped by row if the pattern is uniform).
   State the exact values.

3. **Preserve exact values.** If the spec says the taint states are
   `INTEGRAL`, `ASSURED`, `GUARDED`, `EXTERNAL_RAW`,
   `UNKNOWN_RAW`, `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`,
   `MIXED_RAW` — list all eight. Don't say "8 taint states."

4. **Criteria must be mechanically checkable.** A verification agent should
   be able to read the criterion and know exactly what to grep/read/assert
   in the code. Bad: "taint join is correct." Good: "taint_join(a, b) ==
   taint_join(b, a) for all pairs; MIXED_RAW is absorbing element;
   self-join is identity."

5. **Map to subsystems.** Use these subsystem paths:
   - `core/taints.py` — taint states, join lattice
   - `core/tiers.py` — authority tiers, TAINT_TO_TIER mapping
   - `core/severity.py` — rule IDs, severity levels, exceptionability
   - `core/matrix.py` — severity matrix lookup
   - `core/registry.py` — decorator registry
   - `scanner/rules/*.py` — individual rule implementations
   - `scanner/taint/*.py` — taint propagation
   - `scanner/engine.py` — scan orchestration
   - `scanner/sarif.py` — SARIF output
   - `scanner/context.py` — Finding dataclass
   - `scanner/exceptions.py` — exception matching
   - `manifest/models.py` — manifest data model
   - `manifest/loader.py` — YAML loading
   - `manifest/merge.py` — overlay merging
   - `manifest/coherence.py` — coherence checks
   - `decorators/*.py` — decorator implementations
   - `runtime/*.py` — runtime enforcement
   - `cli/*.py` — CLI commands

6. **Group by spec section.** Maintain the spec's own section numbering so
   requirements trace back easily.

7. **Flag ambiguities.** If a spec statement is ambiguous or could be read
   two ways, extract it but add `**Ambiguity:**` noting the two readings.
   Do not resolve the ambiguity — flag it for human review.

8. **Count your work.** End the document with a summary:
   ```
   ## Summary
   - Total requirements: NNN
   - MUST: NNN
   - SHOULD: NNN
   - MAY: NNN
   - Ambiguities flagged: NNN
   - Subsystems covered: [list]
   ```

### Quality gate

Before finishing, verify:
- Every requirement has all five fields (Source, Statement, Criterion,
  Subsystem, Priority)
- No requirement says "correct" or "proper" without defining what that means
- No criterion requires reading the spec to understand (the minispec is
  self-contained)
- IDs are sequential within each section with no gaps

---

## Usage

To run this extraction:

```
Agent prompt: [paste the prompt section above]
Agent type: general-purpose or opus-level
Model: opus (this requires judgment about what's normative)
Input context: "Read all files matching docs/spec/wardline-01-*.md"
Output: docs/verification/minispec.md
```

The resulting minispec is then given to per-subsystem verification agents
who never see the original spec documents.
