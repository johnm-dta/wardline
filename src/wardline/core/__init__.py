"""wardline.core — Core domain model: taints, tiers, severity, matrix, registry."""

from wardline.core.matrix import SEVERITY_MATRIX, SeverityCell, lookup
from wardline.core.registry import REGISTRY, REGISTRY_VERSION, RegistryEntry
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState, taint_join
from wardline.core.tiers import AuthorityTier

__all__ = [
    "AuthorityTier",
    "Exceptionability",
    "REGISTRY",
    "REGISTRY_VERSION",
    "RegistryEntry",
    "RuleId",
    "SEVERITY_MATRIX",
    "Severity",
    "SeverityCell",
    "TaintState",
    "lookup",
    "taint_join",
]
