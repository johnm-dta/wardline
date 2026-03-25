# PY-WL-004 Semantic Equivalents — Broad Exception Handlers

**Framework rule:** WL-003
**Pattern:** Catching all exceptions broadly, preventing errors from being recorded

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `except Exception:` / `except BaseException:` | DETECTED | -- | -- |
| SE-002 | Bare `except:` | DETECTED | -- | -- |
| SE-003 | `except (Exception, ValueError):` (tuple with broad member) | DETECTED | -- | -- |
| SE-004 | `contextlib.suppress(Exception)` | DETECTED | -- | -- |
| SE-005 | Imported `suppress(Exception)` (bare name) | DETECTED | -- | -- |
| SE-006 | `except*` (TryStar) with broad type | DETECTED | -- | -- |
| SE-007 | `suppress` imported under alias | NOT DETECTED | LOW | LOW |
| SE-008 | Exception type aliased via assignment (`E = Exception; except E:`) | NOT DETECTED | LOW | LOW |
| SE-009 | Exception type from `type()` call or metaclass | NOT DETECTED | NEGLIGIBLE | NEGLIGIBLE |
| SE-010 | `sys.excepthook` override (global broad catch) | NOT DETECTED | LOW | LOW |
| SE-011 | `asyncio.set_exception_handler(lambda: None)` | NOT DETECTED | LOW | LOW |

**Evasion notes:**
- Primary evasion is exception enumeration: `except (ValueError, TypeError, KeyError, ...)` — covers most practical cases without using `Exception`
- Detection coverage is strong for the common patterns
