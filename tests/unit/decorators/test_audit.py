"""Tests for Group 2 audit decorators."""

from __future__ import annotations

from wardline.decorators.audit import audit_critical


class TestAuditCritical:
    """@audit_critical decorator behaviour."""

    def test_sets_audit_critical_attr(self) -> None:
        @audit_critical
        def f() -> int:
            return 1

        assert f._wardline_audit_critical is True  # type: ignore[attr-defined]

    def test_sets_group_2(self) -> None:
        @audit_critical
        def f() -> int:
            return 1

        assert 2 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @audit_critical
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @audit_critical
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
