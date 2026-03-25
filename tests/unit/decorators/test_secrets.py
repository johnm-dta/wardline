"""Tests for Group 8 secret-handling decorators."""

from __future__ import annotations

from wardline.decorators.secrets import handles_secrets


class TestHandlesSecrets:
    """@handles_secrets decorator behaviour."""

    def test_sets_handles_secrets_attr(self) -> None:
        @handles_secrets
        def f() -> int:
            return 1

        assert f._wardline_handles_secrets is True  # type: ignore[attr-defined]

    def test_sets_group_8(self) -> None:
        @handles_secrets
        def f() -> int:
            return 1

        assert 8 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @handles_secrets
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @handles_secrets
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
