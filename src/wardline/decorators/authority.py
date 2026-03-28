"""Group 1 decorators — Authority Tier Flow.

These decorators mark functions with taint state transitions and
tier source annotations for the wardline scanner.
"""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.decorators._base import wardline_decorator

__all__ = [
    "integral_writer",
    "integral_construction",
    "external_boundary",
    "integral_read",
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
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.GUARDED),
)

validates_semantic = wardline_decorator(
    1,
    "validates_semantic",
    _wardline_transition=(TaintState.GUARDED, TaintState.ASSURED),
)

validates_external = wardline_decorator(
    1,
    "validates_external",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.ASSURED),
)

integral_read = wardline_decorator(
    1,
    "integral_read",
    _wardline_tier_source=TaintState.INTEGRAL,
)

integral_writer = wardline_decorator(
    1,
    "integral_writer",
    _wardline_tier_source=TaintState.INTEGRAL,
    _wardline_integral_writer=True,
)

integral_construction = wardline_decorator(
    1,
    "integral_construction",
    _wardline_transition=(TaintState.ASSURED, TaintState.INTEGRAL),
)
