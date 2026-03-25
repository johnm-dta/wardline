# PY-WL-005 Semantic Equivalents — Silent Exception Handling

**Framework rule:** WL-004
**Pattern:** Catching exceptions with no meaningful action taken in the handler

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `except: pass` | DETECTED | -- | -- |
| SE-002 | `except: ...` (Ellipsis) | DETECTED | -- | -- |
| SE-003 | `except: continue` | DETECTED | -- | -- |
| SE-004 | `except: break` | DETECTED | -- | -- |
| SE-005 | `contextlib.suppress(SpecificError)` — silent suppression of specific types | NOT DETECTED | HIGH | HIGH |
| SE-006 | Docstring-only handler body (`except: "reason"`) | NOT DETECTED | MEDIUM | LOW |
| SE-007 | `None`-expression handler body (`except: None`) | NOT DETECTED | LOW | LOW |
| SE-008 | Multi-statement all-no-op body (`except: pass; pass`) | NOT DETECTED | NEGLIGIBLE | NEGLIGIBLE |
| SE-009 | Underscore assignment (`except Exception as e: _ = e`) | NOT DETECTED | LOW | MODERATE |
| SE-010 | `logging.debug()` as near-silent handler | NOT DETECTED (by design) | -- | -- |
| SE-011 | `warnings.warn()` as only handler action | NOT DETECTED | LOW | LOW |

**Evasion notes:**
- SE-005 (`contextlib.suppress` for specific types) is the highest-risk gap — standard Python idiom
- SE-009 is a common agent pattern — assigns to `_` to appear to "use" the exception
- The single-statement body check (`len(handler.body) != 1`) is the precision gate — adding any second statement defeats detection
