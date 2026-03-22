"""PY-WL-004: Broad exception handler detection (tracer bullet).

Detects bare `except:` and `except Exception:` handlers. Hardcodes
EXTERNAL_RAW taint and looks up severity from the matrix.
"""

from __future__ import annotations

import ast
from typing import final

from spike.rule_base import Finding, RuleBase
from wardline.core.matrix import lookup
from wardline.core.severity import RuleId
from wardline.core.taints import TaintState


@final
class RulePyWl004(RuleBase):
    """Detect broad exception handlers (bare except / except Exception)."""

    HARDCODED_TAINT = TaintState.EXTERNAL_RAW

    def rule_id(self) -> RuleId:
        return RuleId.PY_WL_004

    def visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for child in ast.walk(node):
            if not isinstance(child, ast.ExceptHandler):
                continue
            # Bare except (type is None) or except Exception
            if child.type is None or (
                isinstance(child.type, ast.Name) and child.type.id == "Exception"
            ):
                handler_desc = (
                    "bare except"
                    if child.type is None
                    else f"except {child.type.id}"
                )
                # Look up severity from the matrix
                cell = lookup(RuleId.PY_WL_004, self.HARDCODED_TAINT)
                findings.append(
                    Finding(
                        rule_id=RuleId.PY_WL_004,
                        message=(
                            f"Broad exception handler ({handler_desc}) "
                            f"at taint level {self.HARDCODED_TAINT.value}: "
                            f"severity={cell.severity.value}, "
                            f"exceptionability={cell.exceptionability.value}"
                        ),
                        file_path=file_path,
                        line=child.lineno,
                        col=child.col_offset,
                        taint=self.HARDCODED_TAINT,
                    )
                )
        return findings
