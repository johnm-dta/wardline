# PY-WL-002 Semantic Equivalents — Attribute Access with Fallback Default

**Framework rule:** WL-001 (split — attribute access half)
**Pattern:** Accessing an object attribute with a fabricated default value

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `getattr(obj, name, default)` (3-arg) | DETECTED | -- | -- |
| SE-002 | `obj.attr or default` (or-expression) | DETECTED | -- | -- |
| SE-003 | `obj.attr if hasattr(obj, "attr") else default` | NOT DETECTED (hasattr caught by PY-WL-003) | MEDIUM | MODERATE |
| SE-004 | `try: v=obj.attr except AttributeError: v=default` | NOT DETECTED | HIGH | MODERATE |
| SE-005 | `vars(obj).get(name, default)` | DETECTED by PY-WL-001 (misclassified) | LOW | LOW |
| SE-006 | `obj.__dict__.get(name, default)` | DETECTED by PY-WL-001 (misclassified) | LOW | LOW |
| SE-007 | `obj and obj.attr` (None-guard) | NOT DETECTED | MEDIUM | MODERATE |

**Evasion notes:**
- SE-003 provides partial coverage via PY-WL-003 (the hasattr is flagged, not the default fabrication)
- SE-005/006 are detected by PY-WL-001 as dict-like `.get()` calls — technically correct detection but misattributed rule
