"""Tests for TaintState enum."""

import json

from wardline.core.taints import TaintState


def test_taint_state_count() -> None:
    assert len(TaintState) == 8


def test_taint_state_values_are_uppercase() -> None:
    """All taint state values must be explicit uppercase strings."""
    for member in TaintState:
        assert member.value == member.value.upper(), (
            f"{member.name} has non-uppercase value: {member.value}"
        )


def test_serialisation_round_trip() -> None:
    """str(member) produces the canonical uppercase token."""
    assert str(TaintState.AUDIT_TRAIL) == "AUDIT_TRAIL"
    assert str(TaintState.PIPELINE) == "PIPELINE"
    assert str(TaintState.SHAPE_VALIDATED) == "SHAPE_VALIDATED"
    assert str(TaintState.EXTERNAL_RAW) == "EXTERNAL_RAW"
    assert str(TaintState.UNKNOWN_RAW) == "UNKNOWN_RAW"
    assert str(TaintState.UNKNOWN_SHAPE_VALIDATED) == "UNKNOWN_SHAPE_VALIDATED"
    assert str(TaintState.UNKNOWN_SEM_VALIDATED) == "UNKNOWN_SEM_VALIDATED"
    assert str(TaintState.MIXED_RAW) == "MIXED_RAW"


def test_json_serialisation() -> None:
    """StrEnum members serialise as plain strings via json.dumps."""
    assert json.dumps(TaintState.AUDIT_TRAIL) == '"AUDIT_TRAIL"'
    assert json.dumps(TaintState.MIXED_RAW) == '"MIXED_RAW"'
