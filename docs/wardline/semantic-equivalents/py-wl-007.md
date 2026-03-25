# PY-WL-007 Semantic Equivalents — Runtime Type-Checking Internal Data

**Framework rule:** WL-006
**Pattern:** isinstance() or type() comparisons on data whose type should be guaranteed by construction

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `isinstance(data, T)` | DETECTED | -- | -- |
| SE-002 | `type(data) == T` / `type(data) is T` | DETECTED | -- | -- |
| SE-003 | `type(data).__name__ == "dict"` (string-based) | NOT DETECTED | MEDIUM | LOW |
| SE-004 | `data.__class__ is dict` (class attribute) | NOT DETECTED | MEDIUM | LOW |
| SE-005 | `typing.get_type_hints()` at runtime | NOT DETECTED | LOW | LOW |
| SE-006 | `match/case` MatchClass patterns (implicit isinstance) | NOT DETECTED | MEDIUM | MODERATE |
| SE-007 | TypeGuard/TypeIs function bodies (isinstance is their purpose) | FALSE POSITIVE | MEDIUM | MODERATE |

**Suppression categories (correctly suppressed, not evasion):**
- AST type dispatch (`isinstance(node, ast.Assign)`) — tagged union dispatch
- Dunder comparison protocol (`isinstance(other, Cls)` in `__eq__`)
- Frozen dataclass construction (`isinstance(self.x, dict)` in `__post_init__`)
- Declared boundary functions — isinstance is the boundary's implementation

**Evasion notes:**
- SE-006 (match/case) is a growing surface as Python 3.10+ adoption increases
- SE-007 is a false positive, not an evasion — TypeGuard functions SHOULD use isinstance
