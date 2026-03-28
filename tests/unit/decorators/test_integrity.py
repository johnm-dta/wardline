"""Tests for Group 2 audit decorators."""

from __future__ import annotations

from wardline.decorators.integrity import integrity_critical


class TestAuditCritical:
    """@integrity_critical decorator behaviour."""

    def test_sets_integrity_critical_attr(self) -> None:
        @integrity_critical
        def f() -> int:
            return 1

        assert f._wardline_integrity_critical is True  # type: ignore[attr-defined]

    def test_sets_group_2(self) -> None:
        @integrity_critical
        def f() -> int:
            return 1

        assert 2 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @integrity_critical
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @integrity_critical
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
