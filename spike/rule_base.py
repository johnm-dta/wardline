"""RuleBase proof-of-concept — abstract rule contract with enforcement guards.

Validates three architectural properties:
1. @typing.final prevents further subclassing of concrete rules (static check)
2. __init_subclass__ guard prevents runtime multi-level inheritance
3. @abstractmethod enforcement fires at instantiation, not definition
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ast

    from wardline.core.severity import RuleId
    from wardline.core.taints import TaintState


@dataclass(frozen=True)
class Finding:
    """A single scanner finding — maps to one SARIF result."""

    rule_id: RuleId
    message: str
    file_path: str
    line: int
    col: int
    taint: TaintState
    # Severity is looked up from the matrix, not stored here


class RuleBase(ABC):
    """Abstract base for all wardline scanner rules.

    Concrete rules must:
    - Subclass RuleBase directly (enforced by __init_subclass__)
    - Implement visit_function (enforced by @abstractmethod at instantiation)
    - Not be further subclassed (enforced by @typing.final on concrete classes)
    """

    _concrete_rules: set[type[RuleBase]] = set()

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Only allow direct subclasses of RuleBase
        if cls.__bases__ != (RuleBase,):
            for base in cls.__bases__:
                if base is not RuleBase and issubclass(base, RuleBase):
                    raise TypeError(
                        f"{cls.__name__} cannot subclass {base.__name__}: "
                        f"rules must subclass RuleBase directly"
                    )
        RuleBase._concrete_rules.add(cls)

    @abstractmethod
    def rule_id(self) -> RuleId:
        """The canonical rule ID for this rule."""
        ...

    @abstractmethod
    def visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> list[Finding]:
        """Visit a function definition and return any findings."""
        ...
