# PY-WL-001 Semantic Equivalents — Dict Key Access with Fallback Default

**Framework rule:** WL-001 (split — dict access half)
**Pattern:** Accessing a dict key with a fabricated default value

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `d.get(key, default)` | DETECTED | -- | -- |
| SE-002 | `d.setdefault(key, default)` | DETECTED | -- | -- |
| SE-003 | `defaultdict(factory)` / `collections.defaultdict(factory)` | DETECTED | -- | -- |
| SE-004 | `d[k] if k in d else default` (ternary fallback) | NOT DETECTED | HIGH | MODERATE |
| SE-005 | `try: v=d[k] except KeyError: v=default` | NOT DETECTED | HIGH | MODERATE |
| SE-006 | `d.pop(key, default)` | NOT DETECTED | MEDIUM | LOW |
| SE-007 | `d.get(key) or default` (or-expression, 1-arg get) | NOT DETECTED | HIGH | HIGH |
| SE-008 | `ChainMap(overrides, defaults)[key]` | NOT DETECTED | LOW | LOW |
| SE-009 | Custom `__missing__` on dict subclass | NOT DETECTED | LOW | LOW |
| SE-010 | `v if (v := d.get(k)) is not None else default` (walrus) | NOT DETECTED | MEDIUM | MODERATE |
| SE-011 | `{**defaults, **actual_data}[key]` (spread merge) | NOT DETECTED | LOW | LOW |

**Evasion notes:**
- SE-004 (ternary) fires PY-WL-003 on the `k in d` part, providing partial coverage
- SE-007 is the highest-risk undetected pattern — extremely natural Python idiom that agents produce frequently
- SE-006 has the same AST shape as SE-001 and is straightforward to add
