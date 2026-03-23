"""Tests for Group 3 plugin decorators."""

from __future__ import annotations

from wardline.decorators.plugin import system_plugin


class TestSystemPlugin:
    """@system_plugin decorator behaviour."""

    def test_sets_system_plugin_attr(self) -> None:
        @system_plugin
        def f() -> int:
            return 1

        assert f._wardline_system_plugin is True  # type: ignore[attr-defined]

    def test_sets_group_3(self) -> None:
        @system_plugin
        def f() -> int:
            return 1

        assert 3 in f._wardline_groups  # type: ignore[attr-defined]

    def test_callable(self) -> None:
        @system_plugin
        def f() -> int:
            return 42

        assert f() == 42

    def test_preserves_name(self) -> None:
        @system_plugin
        def my_func() -> int:
            return 1

        assert my_func.__name__ == "my_func"
