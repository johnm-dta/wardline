"""Scanner data models — Finding, ScanContext, and WardlineAnnotation.

All models are frozen to prevent accidental mutation during rule execution.
ScanContext's function_level_taint_map is deeply frozen via MappingProxyType.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity

if TYPE_CHECKING:
    from wardline.core.taints import TaintState
    from wardline.manifest.models import BoundaryEntry


@dataclass(frozen=True, kw_only=True)
class Finding:
    """A single scanner finding — maps to one SARIF result.

    Frozen because findings are immutable records; mutation after
    creation is a bug.
    """

    rule_id: RuleId
    file_path: str
    line: int
    col: int
    end_line: int | None
    end_col: int | None
    message: str
    severity: Severity
    exceptionability: Exceptionability
    taint_state: TaintState | None
    analysis_level: int
    source_snippet: str | None
    qualname: str | None = None
    exception_id: str | None = None
    exception_expires: str | None = None
    original_rule: str | None = None


@dataclass(frozen=True)
class WardlineAnnotation:
    """Discovered decorator metadata per call site.

    Captures what the decorator discovery pass found on a decorated
    function/method, consumed by taint assignment and rule execution.
    """

    canonical_name: str
    group: int
    attrs: MappingProxyType[str, object]

    def __post_init__(self) -> None:
        if isinstance(self.attrs, dict):
            object.__setattr__(
                self, "attrs", MappingProxyType(self.attrs)
            )


@dataclass(frozen=True)
class ScanContext:
    """Per-file context built once after pass 1 (decorator discovery + taint).

    Construction timing: built once after pass 1 completes with the
    finalized taint map. NOT constructed incrementally during pass 1.

    The function_level_taint_map is deeply frozen via MappingProxyType
    to prevent mutation during rule execution. ``frozen=True`` prevents
    attribute rebinding but does NOT prevent mutation of mutable
    containers — MappingProxyType makes the map truly read-only.
    """

    file_path: str
    # Maps (module_path, qualname) -> TaintState for each function
    function_level_taint_map: MappingProxyType[str, TaintState] | dict[str, TaintState]
    boundaries: tuple[BoundaryEntry, ...] = ()
    # Level 2: maps qualname -> {variable_name: TaintState}. None when L2 is off.
    variable_taint_map: (
        MappingProxyType[str, MappingProxyType[str, TaintState]] | None
    ) = None

    def __post_init__(self) -> None:
        if isinstance(self.function_level_taint_map, dict):
            object.__setattr__(
                self,
                "function_level_taint_map",
                MappingProxyType(self.function_level_taint_map),
            )
        if isinstance(self.variable_taint_map, dict):
            frozen = {
                k: MappingProxyType(v) if isinstance(v, dict) else v
                for k, v in self.variable_taint_map.items()
            }
            object.__setattr__(
                self,
                "variable_taint_map",
                MappingProxyType(frozen),
            )


def make_governance_finding(
    rule_id: RuleId,
    message: str,
    *,
    file_path: str = "<governance>",
    line: int = 1,
    severity: Severity = Severity.WARNING,
    qualname: str | None = None,
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
    """Create a governance pseudo-rule finding.

    Unified factory for governance findings used by both the scan CLI
    (run-level diagnostics) and the exception matcher (register-level
    diagnostics).
    """
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=0,
        end_line=None,
        end_col=None,
        message=message,
        severity=severity,
        exceptionability=Exceptionability.UNCONDITIONAL,
        taint_state=None,
        analysis_level=0,
        source_snippet=None,
        qualname=qualname,
        exception_id=exception_id,
        original_rule=original_rule,
    )
