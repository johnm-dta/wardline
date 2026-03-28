# Subsystem Verification Agent Prompt

## Purpose

This prompt template is used to dispatch one agent per subsystem. Each agent
reads the minispec requirements relevant to its subsystem, reads the code,
and produces a structured verdict per requirement.

## The Prompt Template

Fill in `{{SUBSYSTEM}}`, `{{FILES}}`, and `{{REQUIREMENTS}}` before dispatching.

---

You are a conformance verification agent for the wardline project.

**Your subsystem:** `{{SUBSYSTEM}}`

**Your task:** For each requirement listed below, read the specified code files
and produce a verdict: does the implementation satisfy the requirement?

### Files to read

{{FILES}}

Read every file listed above in full before producing any verdicts.

### Requirements to verify

{{REQUIREMENTS}}

(Paste the relevant REQ-* entries from minispec.md here.)

### Verdict format

For each requirement, produce exactly this structure:

```
### REQ-X.Y-NNN: [Short name]

**Verdict:** PASS | FAIL | PARTIAL | NOT_IMPLEMENTED | UNABLE_TO_VERIFY

**Evidence:** [Specific file:line reference showing conformance or deviation.
For PASS: quote the code that satisfies it, with file and line number.
For FAIL: quote the code that violates it, explain the deviation.
For PARTIAL: state what passes and what doesn't.
For NOT_IMPLEMENTED: confirm the feature/code doesn't exist.
For UNABLE_TO_VERIFY: explain what you'd need to verify but can't.]

**Notes:** [Optional. Only if there's something the synthesiser needs to know —
e.g., "technically passes but the implementation is fragile" or "passes by
coincidence, not by design."]
```

### Rules

1. **Evidence is mandatory.** Every verdict must cite specific file:line
   references. "Looks correct" is not evidence. "core/taints.py:8-25 defines
   TaintState with exactly 8 members matching the requirement" is evidence.

2. **Read the code, don't infer.** If the requirement says "MIXED_RAW is the
   absorbing element" and the code has a join function, actually trace the
   logic. Don't assume it works because the function exists.

3. **PARTIAL means specific.** If a requirement has three sub-conditions and
   two pass, say which two pass and which one fails.

4. **Don't fix code.** Your job is verification, not implementation. If you
   find a bug, report it as FAIL with evidence. Don't suggest fixes.

5. **Don't interpret beyond the criterion.** The minispec criterion tells you
   exactly what to check. Check that and only that. If the criterion says
   "enum has 8 members" and the enum has 9, that's FAIL even if the 9th
   member seems useful.

6. **Flag spec ambiguities you discover.** If the code does something
   reasonable that the minispec doesn't clearly require or forbid, note it
   as `**Ambiguity:**` rather than forcing a verdict.

### Output structure

```markdown
# Verification Report: {{SUBSYSTEM}}

**Date:** YYYY-MM-DD
**Files reviewed:** [list]
**Requirements checked:** N
**Verdicts:** PASS: N, FAIL: N, PARTIAL: N, NOT_IMPLEMENTED: N, UNABLE_TO_VERIFY: N

---

[Individual requirement verdicts here]

---

## Summary

[2-3 sentences: overall conformance posture for this subsystem, most
significant deviations if any, and any systemic patterns noticed.]
```

---

## Dispatch Guide

### Subsystem groupings

Each agent gets one subsystem. The groupings below define which files and
which minispec requirement sections each agent receives.

| Agent | Subsystem | Code Files | Minispec Sections |
|-------|-----------|------------|-------------------|
| 1 | Core model | `core/taints.py`, `core/tiers.py`, `core/severity.py`, `core/matrix.py`, `core/registry.py` | §4 (tiers), §5 (taints), §7 (severity matrix), §6 (annotations/registry) |
| 2 | Scanner engine | `scanner/engine.py`, `scanner/context.py`, `scanner/fingerprint.py`, `scanner/exceptions.py` | §8 (enforcement layers — static analysis), §9 (governance — exceptions) |
| 3 | Scanner rules | `scanner/rules/*.py` | §7 (pattern rules — one rule at a time) |
| 4 | Taint propagation | `scanner/taint/variable_level.py`, `scanner/taint/function_level.py`, `scanner/taint/callgraph_propagation.py`, `scanner/taint/callgraph.py` | §5 (taint model — propagation) |
| 5 | Manifest | `manifest/models.py`, `manifest/loader.py`, `manifest/merge.py`, `manifest/coherence.py`, `manifest/resolve.py`, `manifest/scope.py`, `manifest/discovery.py`, `manifest/exceptions.py`, `manifest/regime.py` | §13 (manifest format), §9 (governance) |
| 6 | Decorators | `decorators/_base.py`, `decorators/*.py` | §6 (annotation vocabulary) |
| 7 | Runtime | `runtime/enforcement.py`, `runtime/base.py`, `runtime/descriptors.py`, `runtime/protocols.py` | §8 (enforcement layers — runtime) |
| 8 | SARIF output | `scanner/sarif.py` | §8 (enforcement layers — SARIF output format) |

### Model selection

- **Agents 1, 3, 4:** Opus — these verify the core model, rule semantics, and
  taint propagation. Errors here undermine everything downstream.
- **Agents 2, 5, 6, 7, 8:** Sonnet — these verify structural conformance
  (does the manifest loader handle overlays, does SARIF output match format).
  Mechanical checking against clear criteria.

### Parallelisation

Agents 1-8 can all run in parallel — they read different files and check
different requirements. No coordination needed.

### Cost estimate

Each agent reads ~5-15 code files + ~20-50 requirements. At ~1000 tokens per
code file and ~100 tokens per requirement, each agent's input context is
roughly 15k-25k tokens. With 8 agents, total input is ~150k-200k tokens.
Output is ~500-1000 tokens per requirement verdict, so ~50k-100k total output.

Total estimated cost: 200k-300k input + 50k-100k output tokens.
