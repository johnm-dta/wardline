# PY-WL-009 Semantic Equivalents — Semantic Validation Without Prior Shape Validation

**Framework rule:** WL-008
**Pattern:** Declared semantic-validation boundary whose inputs have not passed shape validation

This is a structural verification rule. "Semantic equivalents" here are evasion techniques for satisfying the shape evidence requirement without providing real structural validation.

| ID | Technique | Detection | Priority | Agent Likelihood |
|----|-----------|-----------|----------|-----------------|
| EV-001 | No isinstance/hasattr/membership test before semantic check | DETECTED | -- | -- |
| EV-002 | Bare `isinstance(data, dict)` as expression statement (result discarded) | DETECTED (fixed in HC-6) | -- | -- |
| EV-003 | `isinstance(data, object)` in conditional (always True) | NOT DETECTED | MEDIUM | MODERATE |
| EV-004 | isinstance with wrong type (`isinstance(data, str)` before dict subscript) | NOT DETECTED | LOW | LOW |
| EV-005 | Shape check in unreachable branch (`if False: isinstance(...)`) | NOT DETECTED | LOW | LOW |
| EV-006 | Shape check after (not before) the semantic check | NOT DETECTED | MEDIUM | MODERATE |

**Notes:**
- EV-002 was the primary evasion discovered by the C-Security Architect audit agent. Fixed by requiring isinstance/hasattr results to be consumed by a conditional guard (not bare expression statements).
- EV-003 is the next evasion frontier — vacuous isinstance that always returns True. Requires value-aware analysis to detect.
- Combined validation boundaries (`@validates_external`) are correctly exempt — they satisfy shape validation internally per spec §5.2.
