# PY-WL-003 Semantic Equivalents — Existence-Checking as Structural Gate

**Framework rule:** WL-002
**Pattern:** Using existence-checking to probe data structure instead of trusting declared contracts

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `key in d` / `key not in d` | DETECTED | -- | -- |
| SE-002 | `hasattr(obj, name)` | DETECTED | -- | -- |
| SE-003 | `match/case` with MatchMapping | DETECTED | -- | -- |
| SE-004 | `match/case` with MatchClass | DETECTED | -- | -- |
| SE-005 | `try: d[k] except KeyError` (existence probe) | NOT DETECTED | HIGH | MODERATE |
| SE-006 | `try: obj.attr except AttributeError` | NOT DETECTED | HIGH | MODERATE |
| SE-007 | `required_keys - d.keys()` (set difference) | NOT DETECTED | MEDIUM | LOW |
| SE-008 | `d.keys() & expected_keys` (set intersection) | NOT DETECTED | LOW | LOW |
| SE-009 | `any(k == "field" for k in d)` (generator probe) | NOT DETECTED | LOW | LOW |

**Evasion notes:**
- SE-005/006 (try/except probes) are the primary evasion path — natural Python idiom
- The `in` operator detection has a known false positive surface on non-dict containers (list, string, set membership)
