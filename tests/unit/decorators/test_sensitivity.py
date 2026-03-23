"""Tests for Group 10 sensitivity decorators."""

from __future__ import annotations

from wardline.decorators.sensitivity import financial_data, phi_handler, pii_handler


class TestPiiHandler:
    """@pii_handler decorator behaviour."""

    def test_sets_pii_handler_attr(self) -> None:
        @pii_handler
        def f() -> int:
            return 1

        assert f._wardline_pii_handler is True  # type: ignore[attr-defined]

    def test_sets_group_10(self) -> None:
        @pii_handler
        def f() -> int:
            return 1

        assert 10 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @pii_handler
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @pii_handler
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestPhiHandler:
    """@phi_handler decorator behaviour."""

    def test_sets_phi_handler_attr(self) -> None:
        @phi_handler
        def f() -> int:
            return 1

        assert f._wardline_phi_handler is True  # type: ignore[attr-defined]

    def test_sets_group_10(self) -> None:
        @phi_handler
        def f() -> int:
            return 1

        assert 10 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @phi_handler
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @phi_handler
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"


class TestFinancialData:
    """@financial_data decorator behaviour."""

    def test_sets_financial_data_attr(self) -> None:
        @financial_data
        def f() -> int:
            return 1

        assert f._wardline_financial_data is True  # type: ignore[attr-defined]

    def test_sets_group_10(self) -> None:
        @financial_data
        def f() -> int:
            return 1

        assert 10 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @financial_data
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @financial_data
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
