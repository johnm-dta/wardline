"""PY-WL-006: Audit-critical writes in broad exception handlers.

Detects code that performs audit-critical writes (logging, database
recording, audit trail operations) inside broad exception handlers
(``except Exception``, ``except BaseException``, bare ``except:``).

The concern: if the audit write itself raises, the broad handler masks
the failure — the audit trail silently loses a record and the program
continues as if everything were fine.
"""

from __future__ import annotations

import ast

from wardline.core import matrix
from wardline.core.severity import RuleId
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

_BROAD_NAMES = frozenset({"Exception", "BaseException"})

# Method-name prefixes that indicate audit-critical writes.
# Matched against ``obj.method(...)`` where method starts with one of these.
_AUDIT_ATTR_PREFIXES = (
    "log",       # logger.log, logger.info, logger.error, etc.
    "debug",     # logger.debug(...)
    "info",      # logger.info(...)
    "warning",   # logger.warning(...)
    "warn",      # logger.warn(...)
    "error",     # logger.error(...)
    "critical",  # logger.critical(...)
    "fatal",     # logger.fatal(...)
    "exception", # logger.exception(...)
    "record",    # db.record_failure, audit.record_event
    "audit",     # audit.audit_event(...)
    "emit",      # emitter.emit(...)
    "write",     # writer.write(...)
    "persist",   # store.persist(...)
    "save",      # store.save(...)
    "insert",    # db.insert(...)
    "store",     # cache.store(...)
)

# Bare function names that are audit-critical.
_AUDIT_FUNC_NAMES = frozenset({
    "log",
    "audit",
    "record",
    "emit",
    "print",
})


def _is_broad_handler(handler: ast.ExceptHandler) -> bool:
    """Check if handler catches broadly (Exception, BaseException, bare)."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id in _BROAD_NAMES:
        return True
    if isinstance(handler.type, ast.Attribute) and handler.type.attr in _BROAD_NAMES:
        return True
    if isinstance(handler.type, ast.Tuple):
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name) and elt.id in _BROAD_NAMES:
                return True
            if isinstance(elt, ast.Attribute) and elt.attr in _BROAD_NAMES:
                return True
    return False


def _is_audit_call(call: ast.Call) -> bool:
    """Check if a Call node looks like an audit-critical write."""
    # obj.method(...) — attribute call
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        for prefix in _AUDIT_ATTR_PREFIXES:
            if attr == prefix or attr.startswith(prefix + "_"):
                return True
        return False
    # bare_func(...) — name call
    if isinstance(call.func, ast.Name):
        return call.func.id in _AUDIT_FUNC_NAMES
    return False


class RulePyWl006(RuleBase):
    """Detect audit-critical writes inside broad exception handlers.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_006

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk function body for broad handlers containing audit writes."""
        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.ExceptHandler):
                continue
            if not _is_broad_handler(child):
                continue
            # Walk the handler body for audit-critical calls
            for handler_node in ast.walk(child):
                if isinstance(handler_node, ast.Call) and _is_audit_call(handler_node):
                    self._emit_finding(handler_node)

    def _emit_finding(self, call: ast.Call) -> None:
        """Emit a PY-WL-006 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_006,
                file_path=self._file_path,
                line=call.lineno,
                col=call.col_offset,
                end_line=call.end_lineno,
                end_col=call.end_col_offset,
                message=(
                    "Audit-critical write in broad exception handler — "
                    "if the write fails, the broad handler masks the failure"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )
