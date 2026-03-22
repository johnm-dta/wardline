"""Severity, exceptionability, and rule ID enumerations."""

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity levels."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    SUPPRESS = "SUPPRESS"


class Exceptionability(StrEnum):
    """Exception governance classes."""

    UNCONDITIONAL = "UNCONDITIONAL"
    STANDARD = "STANDARD"
    RELAXED = "RELAXED"
    TRANSPARENT = "TRANSPARENT"


class RuleId(StrEnum):
    """Rule identifiers — canonical and pseudo-rule-IDs.

    Member names use underscores; string values use hyphens per
    the spec's SARIF format. All IDs that appear as Finding.rule_id
    must be members of this enum.
    """

    # Canonical rules (Python binding)
    PY_WL_001 = "PY-WL-001"
    PY_WL_002 = "PY-WL-002"
    PY_WL_003 = "PY-WL-003"
    PY_WL_004 = "PY-WL-004"
    PY_WL_005 = "PY-WL-005"
    PY_WL_006 = "PY-WL-006"
    PY_WL_007 = "PY-WL-007"
    PY_WL_008 = "PY-WL-008"
    PY_WL_009 = "PY-WL-009"

    # Pseudo-rule-IDs (diagnostic signals, not analysis rules)
    PY_WL_001_UNVERIFIED_DEFAULT = "PY-WL-001-UNVERIFIED-DEFAULT"
    WARDLINE_UNRESOLVED_DECORATOR = "WARDLINE-UNRESOLVED-DECORATOR"
    TOOL_ERROR = "TOOL-ERROR"
    GOVERNANCE_REGISTRY_MISMATCH_ALLOWED = "GOVERNANCE-REGISTRY-MISMATCH-ALLOWED"
    GOVERNANCE_RULE_DISABLED = "GOVERNANCE-RULE-DISABLED"
    GOVERNANCE_PERMISSIVE_DISTRIBUTION = "GOVERNANCE-PERMISSIVE-DISTRIBUTION"
