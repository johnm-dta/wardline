"""Group 1 decorators — Authority Tier Flow.

These decorators mark functions with taint state transitions and
tier source annotations for the wardline scanner.
"""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.decorators._base import wardline_decorator

__all__ = [
    "audit_writer",
    "authoritative_construction",
    "external_boundary",
    "tier1_read",
    "validates_external",
    "validates_semantic",
    "validates_shape",
]

external_boundary = wardline_decorator(
    1,
    "external_boundary",
    _wardline_tier_source=TaintState.EXTERNAL_RAW,
)

validates_shape = wardline_decorator(
    1,
    "validates_shape",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.SHAPE_VALIDATED),
)

validates_semantic = wardline_decorator(
    1,
    "validates_semantic",
    _wardline_transition=(TaintState.SHAPE_VALIDATED, TaintState.PIPELINE),
)

validates_external = wardline_decorator(
    1,
    "validates_external",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.PIPELINE),
)

tier1_read = wardline_decorator(
    1,
    "tier1_read",
    _wardline_tier_source=TaintState.AUDIT_TRAIL,
)

audit_writer = wardline_decorator(
    1,
    "audit_writer",
    _wardline_tier_source=TaintState.AUDIT_TRAIL,
    _wardline_audit_writer=True,
)

authoritative_construction = wardline_decorator(
    1,
    "authoritative_construction",
    _wardline_transition=(TaintState.PIPELINE, TaintState.AUDIT_TRAIL),
)
