"""Tests for TaintState enum and taint_join lattice."""

import json

import pytest

from wardline.core.taints import TaintState, taint_join


# --- TaintState enum tests ---


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


# --- taint_join lattice tests ---

ALL_STATES = list(TaintState)


def test_idempotency() -> None:
    """join(a, a) == a for all taint states."""
    for state in ALL_STATES:
        assert taint_join(state, state) is state, (
            f"join({state}, {state}) should be {state}"
        )


def test_commutativity_exhaustive() -> None:
    """join(a, b) == join(b, a) for all 64 ordered pairs."""
    for a in ALL_STATES:
        for b in ALL_STATES:
            assert taint_join(a, b) is taint_join(b, a), (
                f"join({a}, {b}) != join({b}, {a})"
            )


def test_mixed_raw_absorbing() -> None:
    """MIXED_RAW is the absorbing element: join(MIXED_RAW, X) == MIXED_RAW for all X."""
    for state in ALL_STATES:
        assert taint_join(TaintState.MIXED_RAW, state) is TaintState.MIXED_RAW, (
            f"join(MIXED_RAW, {state}) should be MIXED_RAW"
        )
        assert taint_join(state, TaintState.MIXED_RAW) is TaintState.MIXED_RAW, (
            f"join({state}, MIXED_RAW) should be MIXED_RAW"
        )


def test_associativity_spot_check() -> None:
    """Associativity: join(a, join(b, c)) == join(join(a, b), c) for representative triples."""
    triples = [
        (TaintState.AUDIT_TRAIL, TaintState.PIPELINE, TaintState.EXTERNAL_RAW),
        (TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_SHAPE_VALIDATED, TaintState.UNKNOWN_SEM_VALIDATED),
        (TaintState.SHAPE_VALIDATED, TaintState.MIXED_RAW, TaintState.AUDIT_TRAIL),
        (TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.PIPELINE),
        (TaintState.UNKNOWN_SHAPE_VALIDATED, TaintState.AUDIT_TRAIL, TaintState.UNKNOWN_SEM_VALIDATED),
    ]
    for a, b, c in triples:
        left = taint_join(a, taint_join(b, c))
        right = taint_join(taint_join(a, b), c)
        assert left is right, (
            f"Associativity failed: join({a}, join({b}, {c})) = {left} != {right} = join(join({a}, {b}), {c})"
        )


# --- Specific join results from spec §5 ---


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        # Cross-classification: always MIXED_RAW
        (TaintState.AUDIT_TRAIL, TaintState.PIPELINE, TaintState.MIXED_RAW),
        (TaintState.PIPELINE, TaintState.EXTERNAL_RAW, TaintState.MIXED_RAW),
        (TaintState.SHAPE_VALIDATED, TaintState.PIPELINE, TaintState.MIXED_RAW),
        (TaintState.AUDIT_TRAIL, TaintState.EXTERNAL_RAW, TaintState.MIXED_RAW),
        # Any classified + UNKNOWN_RAW: MIXED_RAW
        (TaintState.PIPELINE, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW),
        (TaintState.AUDIT_TRAIL, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW),
        (TaintState.SHAPE_VALIDATED, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW),
        # Any classified + UNKNOWN_SHAPE_VALIDATED: MIXED_RAW
        (TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_SHAPE_VALIDATED, TaintState.MIXED_RAW),
        (TaintState.PIPELINE, TaintState.UNKNOWN_SHAPE_VALIDATED, TaintState.MIXED_RAW),
        # Any classified + UNKNOWN_SEM_VALIDATED: MIXED_RAW
        (TaintState.SHAPE_VALIDATED, TaintState.UNKNOWN_SEM_VALIDATED, TaintState.MIXED_RAW),
        (TaintState.AUDIT_TRAIL, TaintState.UNKNOWN_SEM_VALIDATED, TaintState.MIXED_RAW),
        # Within UNKNOWN family: demote to weaker validation
        (TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_SHAPE_VALIDATED, TaintState.UNKNOWN_RAW),
        (TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_SEM_VALIDATED, TaintState.UNKNOWN_RAW),
        (TaintState.UNKNOWN_SHAPE_VALIDATED, TaintState.UNKNOWN_SEM_VALIDATED, TaintState.UNKNOWN_SHAPE_VALIDATED),
    ],
    ids=lambda x: x.value if isinstance(x, TaintState) else str(x),
)
def test_specific_join_results(a: TaintState, b: TaintState, expected: TaintState) -> None:
    """Verify specific join results from the spec's join table."""
    assert taint_join(a, b) is expected
    assert taint_join(b, a) is expected  # commutativity
