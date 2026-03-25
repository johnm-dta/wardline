"""Tests for Group 11 sensitivity decorators."""

from __future__ import annotations

from wardline.decorators.sensitivity import (
    declassifies,
    handles_classified,
    handles_pii,
)


class TestHandlesPii:
    """@handles_pii decorator behaviour."""

    def test_sets_handles_pii_attrs(self) -> None:
        @handles_pii(fields=["email", "name"])
        def f() -> int:
            return 1

        assert f._wardline_handles_pii is True  # type: ignore[attr-defined]
        assert f._wardline_pii_fields == ("email", "name")  # type: ignore[attr-defined]

    def test_sets_group_11(self) -> None:
        @handles_pii(fields=["email"])
        def f() -> int:
            return 1

        assert 11 in f._wardline_groups  # type: ignore[attr-defined]


class TestHandlesClassified:
    """@handles_classified decorator behaviour."""

    def test_sets_handles_classified_attrs(self) -> None:
        @handles_classified(level="PROTECTED")
        def f() -> int:
            return 1

        assert f._wardline_handles_classified is True  # type: ignore[attr-defined]
        assert f._wardline_classification_level == "PROTECTED"  # type: ignore[attr-defined]

    def test_sets_group_11(self) -> None:
        @handles_classified(level="PROTECTED")
        def f() -> int:
            return 1

        assert 11 in f._wardline_groups  # type: ignore[attr-defined]


class TestDeclassifies:
    """@declassifies decorator behaviour."""

    def test_sets_declassifies_attrs(self) -> None:
        @declassifies(from_level="SECRET", to_level="PROTECTED")
        def f() -> int:
            return 1

        assert f._wardline_declassifies is True  # type: ignore[attr-defined]
        assert f._wardline_from_level == "SECRET"  # type: ignore[attr-defined]
        assert f._wardline_to_level == "PROTECTED"  # type: ignore[attr-defined]

    def test_sets_group_11(self) -> None:
        @declassifies(from_level="SECRET", to_level="PROTECTED")
        def f() -> int:
            return 1

        assert 11 in f._wardline_groups  # type: ignore[attr-defined]
