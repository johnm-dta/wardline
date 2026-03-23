"""Scanner data models — Finding, ScanContext, and WardlineAnnotation.

All models are frozen to prevent accidental mutation during rule execution.
ScanContext's function_level_taint_map is deeply frozen via MappingProxyType.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wardline.core.severity import Exceptionability, RuleId, Severity
    from wardline.core.taints import TaintState
    from wardline.manifest.models import BoundaryEntry


@dataclass(frozen=True)
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

    def __post_init__(self) -> None:
        if isinstance(self.function_level_taint_map, dict):
            object.__setattr__(
                self,
                "function_level_taint_map",
                MappingProxyType(self.function_level_taint_map),
            )
