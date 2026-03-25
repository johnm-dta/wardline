# Audits

## Rule Conformance Audit (2026-03-25)

- [Executive summary](rule-conformance-audit-2026-03-25.md) -- High-level findings, cross-cutting issues, SARIF gaps
- [2026-03-25-rule-conformance/](2026-03-25-rule-conformance/) -- Full audit tree (35-agent, 2-phase)

### Audit Structure

```
2026-03-25-rule-conformance/
  00-process.md          -- Methodology and rules of engagement
  synthesis.md           -- Final consolidated findings (CF-1..4, HC-1..12)
  phase-1/               -- Independent per-rule audits (4 groups x 6 specialist roles)
  phase-2/               -- Cross-cutting deep-dives (f1: taint, f2: boundaries, f3: governance)
```

### Critical Findings

| ID | Summary | Remediation |
|----|---------|-------------|
| CF-1 | Validation boundary bodies eval at OUTPUT tier | audit-remediation-phase1 plan |
| CF-2 | SCN-021 test coverage at 14% | audit-remediation-phase1 plan |
| CF-3 | Bounded context enforcement absent | Tracked in filigree |
| CF-4 | @restoration_boundary not implemented | Tracked in filigree |
