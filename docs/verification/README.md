# Verification Pipeline

Systematic conformance verification of the wardline implementation against its
specification. Three-phase pipeline, each phase feeding the next.

## Pipeline

```
docs/spec/wardline-01-*.md          (15 normative documents)
        │
        ▼
Phase 1: MINISPEC-PROMPT.md         (1 Opus agent)
        │
        ▼
docs/verification/minispec.md       (flat requirements list, ~200-400 reqs)
        │
        ▼
Phase 2: VERIFY-SUBSYSTEM-PROMPT.md (8 agents in parallel, mixed Opus/Sonnet)
        │
        ▼
docs/verification/reports/          (8 per-subsystem verdict files)
        │
        ▼
Phase 3: VERIFY-SYNTHESIS-PROMPT.md (1 Opus agent)
        │
        ▼
docs/verification/conformance-report.md
```

## Files

| File | Purpose |
|------|---------|
| `MINISPEC-PROMPT.md` | Extracts normative requirements from spec into machine-relevant format |
| `VERIFY-SUBSYSTEM-PROMPT.md` | Template + dispatch guide for per-subsystem verification agents |
| `VERIFY-SYNTHESIS-PROMPT.md` | Consolidates all subsystem verdicts into conformance report |
| `minispec.md` | Output of Phase 1 (generated, not committed until reviewed) |
| `reports/*.md` | Output of Phase 2 (generated) |
| `conformance-report.md` | Output of Phase 3 (generated) |

## Running the pipeline

### Phase 1: Extract minispec

Dispatch one Opus agent with the prompt from `MINISPEC-PROMPT.md`. Input is all
`docs/spec/wardline-01-*.md` files. Output is `minispec.md`.

Review the minispec before proceeding — errors here propagate to every
downstream verdict.

### Phase 2: Verify subsystems

See the dispatch guide in `VERIFY-SUBSYSTEM-PROMPT.md` for the 8 subsystem
groupings, file lists, and model selection. All 8 agents can run in parallel.

### Phase 3: Synthesise

After all 8 reports are in, dispatch one Opus agent with
`VERIFY-SYNTHESIS-PROMPT.md`. Paste all reports as input.

## Cost

Estimated total: 300k-400k tokens across all agents. The minispec extraction
(Phase 1) is the cheapest phase. Phase 2 dominates cost.

## When to re-run

- After significant code changes (new rules, refactored subsystems)
- After spec updates (new normative requirements)
- Before releases (conformance gate)

Re-running is incremental: if only one subsystem changed, re-run only that
subsystem's agent + the synthesis.
