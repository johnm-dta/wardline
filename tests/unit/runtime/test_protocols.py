"""Tests for ValidatedRecord Protocol."""

from __future__ import annotations

from wardline.runtime.protocols import ValidatedRecord


class _ConformingRecord:
    """A class that satisfies the ValidatedRecord protocol."""

    @property
    def _wardline_tier(self) -> int:
        return 1

    @property
    def _wardline_groups(self) -> tuple[int, ...]:
        return (1, 2)


class _NonConformingRecord:
    """A class that does NOT satisfy the ValidatedRecord protocol."""

    pass


class _PartialRecord:
    """Has _wardline_tier but not _wardline_groups."""

    @property
    def _wardline_tier(self) -> int:
        return 2


class TestValidatedRecord:
    """ValidatedRecord is a runtime-checkable structural protocol."""

    def test_conforming_isinstance(self) -> None:
        record = _ConformingRecord()
        assert isinstance(record, ValidatedRecord)

    def test_non_conforming_isinstance(self) -> None:
        record = _NonConformingRecord()
        assert not isinstance(record, ValidatedRecord)

    def test_partial_not_conforming(self) -> None:
        record = _PartialRecord()
        assert not isinstance(record, ValidatedRecord)

    def test_conforming_attributes(self) -> None:
        record = _ConformingRecord()
        assert record._wardline_tier == 1
        assert record._wardline_groups == (1, 2)
