"""Tests for AuthoritativeField descriptor."""

from __future__ import annotations

import pytest

from wardline.runtime.descriptors import (
    AuthoritativeAccessError,
    AuthoritativeField,
)


class _SampleEntity:
    """Test entity with AuthoritativeField descriptors."""

    value = AuthoritativeField()
    score = AuthoritativeField()


# ── Access-before-set ─────────────────────────────────────────


class TestAccessBeforeSet:
    """Accessing an AuthoritativeField before setting raises."""

    def test_raises_authoritative_access_error(self) -> None:
        obj = _SampleEntity()
        with pytest.raises(AuthoritativeAccessError, match="value"):
            _ = obj.value

    def test_error_is_attribute_error(self) -> None:
        """AuthoritativeAccessError is an AttributeError subclass."""
        obj = _SampleEntity()
        with pytest.raises(AttributeError):
            _ = obj.value

    def test_hasattr_returns_false_before_set(self) -> None:
        """hasattr() returns False for unset AuthoritativeField."""
        obj = _SampleEntity()
        assert not hasattr(obj, "value")

    def test_error_includes_field_name(self) -> None:
        obj = _SampleEntity()
        with pytest.raises(AuthoritativeAccessError, match="score"):
            _ = obj.score


# ── Normal set/get ────────────────────────────────────────────


class TestNormalSetGet:
    """Normal set then get works correctly."""

    def test_set_then_get(self) -> None:
        obj = _SampleEntity()
        obj.value = 42
        assert obj.value == 42

    def test_set_none_is_valid(self) -> None:
        """Setting None is a valid explicit assignment."""
        obj = _SampleEntity()
        obj.value = None
        assert obj.value is None

    def test_overwrite(self) -> None:
        obj = _SampleEntity()
        obj.value = 1
        obj.value = 2
        assert obj.value == 2

    def test_independent_instances(self) -> None:
        """Each instance has independent storage."""
        a = _SampleEntity()
        b = _SampleEntity()
        a.value = "a"
        b.value = "b"
        assert a.value == "a"
        assert b.value == "b"

    def test_multiple_fields_independent(self) -> None:
        """Different AuthoritativeFields on the same class are independent."""
        obj = _SampleEntity()
        obj.value = "v"
        with pytest.raises(AuthoritativeAccessError):
            _ = obj.score
        obj.score = "s"
        assert obj.value == "v"
        assert obj.score == "s"


# ── __dict__ bypass (known residual) ──────────────────────────


class TestDictBypass:
    """Direct __dict__ writes bypass the descriptor — known residual."""

    def test_dict_bypass_read(self) -> None:
        """Writing to the storage key directly bypasses the descriptor."""
        obj = _SampleEntity()
        obj.__dict__["_wd_auth__SampleEntity_value"] = "sneaky"
        # Descriptor reads from the same key, so this returns the value
        assert obj.value == "sneaky"

    def test_dict_bypass_is_known_residual(self) -> None:
        """Confirm this is a Python limitation, not a bug.

        The descriptor protocol does not intercept direct __dict__
        writes. This test documents the known residual.
        """
        obj = _SampleEntity()
        # Direct write without going through __set__
        obj.__dict__["_wd_auth__SampleEntity_value"] = "bypassed"
        assert obj.value == "bypassed"


# ── _wd_auth_ prefix collision ────────────────────────────────


class TestPrefixCollision:
    """The _wd_auth_ prefix must not collide with raw attributes."""

    def test_raw_attribute_independent(self) -> None:
        """A raw attribute named _wd_auth__SampleEntity_value doesn't interfere
        with the descriptor when accessed through the descriptor protocol."""
        obj = _SampleEntity()
        obj.value = "via_descriptor"

        # The storage key is _wd_auth__SampleEntity_value in __dict__
        assert obj.__dict__["_wd_auth__SampleEntity_value"] == "via_descriptor"

    def test_no_collision_with_regular_attr(self) -> None:
        """An attribute without the _wd_auth_ prefix is independent."""
        obj = _SampleEntity()
        obj.__dict__["value_raw"] = "raw"
        obj.value = "authoritative"
        assert obj.__dict__["value_raw"] == "raw"
        assert obj.value == "authoritative"


# ── __set_name__ auto-naming ──────────────────────────────────


class TestSetName:
    """__set_name__ correctly captures the attribute name."""

    def test_auto_naming(self) -> None:
        """Descriptor knows its name after __set_name__."""
        descriptor = _SampleEntity.__dict__["value"]
        assert isinstance(descriptor, AuthoritativeField)
        assert descriptor.name == "value"
        assert descriptor.storage_name == "_wd_auth__SampleEntity_value"

    def test_class_access_returns_descriptor(self) -> None:
        """Accessing the descriptor on the class returns the descriptor."""
        assert isinstance(_SampleEntity.value, AuthoritativeField)
