# PY-WL-008 Semantic Equivalents — Validation Boundary with No Rejection Path

**Framework rule:** WL-007
**Pattern:** A declared validation or restoration boundary function that accepts all input

This is a structural verification rule, not a pattern rule. "Semantic equivalents" here are evasion techniques for satisfying the rejection path requirement without providing real validation.

| ID | Technique | Detection | Priority | Agent Likelihood |
|----|-----------|-----------|----------|-----------------|
| EV-001 | No raise, no guarded return — truly missing rejection path | DETECTED | -- | -- |
| EV-002 | `assert` as sole rejection (disabled by `-O`) | DETECTED (assert excluded per spec) | -- | -- |
| EV-003 | `if True: raise ValueError("unreachable")` (constant-True guard) | NOT DETECTED | MEDIUM | LOW |
| EV-004 | `if False: raise ValueError(...)` (constant-False guard) | NOT DETECTED (spec SHOULD) | MEDIUM | LOW |
| EV-005 | Raise after unconditional return (dead code) | NOT DETECTED | MEDIUM | LOW |
| EV-006 | `isinstance(data, object)` guard (always True) | NOT DETECTED | MEDIUM | MODERATE |
| EV-007 | Delegation to helper that raises (`schema.validate(data)`) | NOT DETECTED (spec MUST — two-hop) | HIGH | HIGH |

**Notes:**
- EV-007 is the highest-priority gap — two-hop call-graph analysis is required by spec §8.1 but not yet implemented. This is HC-2 in the remediation plan.
- EV-003/004/005 are spec SHOULD items (constant-expression guard detection)
- EV-006 is vacuous validation — structurally present but semantically empty
