# `/panel` — Expert Panel Review Command

## Purpose

A slash command that dispatches a user's question to 5 core expert subagents in
parallel, collects their full responses, and presents a synthesized cross-panel
view. Before dispatching, it suggests at least 2 situationally-appropriate
additional reviewers for the user to optionally include.

## Deliverable

Single file: `.claude/commands/panel.md`

## Core Panel (always dispatched)

| Role | subagent_type |
|------|---------------|
| Solution Architect | `axiom-system-architect:architecture-critic` |
| Systems Thinker | `yzmir-systems-thinking:pattern-recognizer` |
| Python Engineer | `axiom-python-engineering:python-code-reviewer` |
| Quality Engineer | `ordis-quality-engineering:test-suite-reviewer` |
| Security Architect | `ordis-security-architect:threat-analyst` |

## Flow

1. User invokes `/panel <question>`
2. Claude analyzes the question and conversation context
3. Claude suggests at least 2 additional reviewers from the available subagent
   pool, explaining why each is relevant to this specific question
4. User confirms or adjusts the panel composition
5. All confirmed agents are spawned in parallel via the Agent tool, each
   receiving the question and relevant conversation context
6. Results are presented:
   - Each agent's **full, unedited** response under a `## <Role>` heading
   - A final `## Cross-Panel Synthesis` section

## Synthesis Rules

- Every point from every agent must be represented — no filtering, no
  editorialising, no "key takeaways" that drop content
- The synthesis section is **additive**: it maps patterns across responses
  (agreements, disagreements, open questions, recommended next steps)
- It does not replace or summarise the individual responses — it sits
  alongside them as a cross-cutting view

## Situational Reviewer Suggestions

Before dispatching, Claude examines the question topic and suggests at least 2
additional reviewers. The suggestion pool includes all available subagent types.
Examples of situational matches:

- API design → API Architect, API Reviewer
- Documentation → Doc Critic, Structure Analyst
- Compliance/threat → Controls Designer, Accessibility Auditor
- Test strategy → Coverage Gap Analyst, Flaky Test Diagnostician
- UX/interface → UX Critic, Accessibility Auditor
- Debt/refactoring → Debt Cataloger, Leverage Analyst

## What It Does Not Do

- No multi-round conversation with agents — single fire-and-forget dispatch
- No auto-execution of recommendations — advisory only
- No persistent panel state — each invocation is independent
