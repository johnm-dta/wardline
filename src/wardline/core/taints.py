"""Taint state model — 8 canonical taint state tokens."""

from enum import StrEnum


class TaintState(StrEnum):
    """Canonical taint states per spec §5.

    Values are explicit uppercase strings — do NOT use auto() which
    produces lowercase and would silently break SARIF output, matrix
    lookups, and corpus matching.
    """

    AUDIT_TRAIL = "AUDIT_TRAIL"
    PIPELINE = "PIPELINE"
    SHAPE_VALIDATED = "SHAPE_VALIDATED"
    EXTERNAL_RAW = "EXTERNAL_RAW"
    UNKNOWN_RAW = "UNKNOWN_RAW"
    UNKNOWN_SHAPE_VALIDATED = "UNKNOWN_SHAPE_VALIDATED"
    UNKNOWN_SEM_VALIDATED = "UNKNOWN_SEM_VALIDATED"
    MIXED_RAW = "MIXED_RAW"
