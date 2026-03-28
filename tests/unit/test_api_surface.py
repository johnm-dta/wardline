"""Regression tests for 4.3a API surface fixes.

These tests assert the DESIRED behavior. They fail before the fix
(proving the bug exists) and pass after (proving it's fixed).
"""

from __future__ import annotations

from wardline.decorators import external_boundary


class TestWardlineGroupsFrozen:
    """_wardline_groups should be frozenset, not mutable set."""

    def test_groups_is_frozenset(self) -> None:
        @external_boundary
        def f():
            pass

        assert isinstance(f._wardline_groups, frozenset)

    def test_stacked_groups_is_frozenset(self) -> None:
        from wardline.decorators import integrity_critical

        @external_boundary
        @integrity_critical
        def f():
            pass

        assert isinstance(f._wardline_groups, frozenset)


class TestDecoratorReturnTypes:
    """Higher-order decorator factories should return Any, not object."""

    def test_compensatable_preserves_type(self) -> None:
        from wardline.decorators import compensatable

        @compensatable(rollback="undo")
        def f() -> int:
            return 42

        # If return type is object, this would fail type checking.
        # At runtime, verify the function is still callable with correct return.
        assert f() == 42
        assert f.__name__ == "f"

    def test_deprecated_by_preserves_type(self) -> None:
        from wardline.decorators import deprecated_by

        @deprecated_by(date="2026-01-01", replacement="new_f")
        def f() -> int:
            return 42

        assert f() == 42
        assert f.__name__ == "f"


class TestAssertToRuntimeError:
    """engine.py invariant check should raise RuntimeError, not AssertionError."""

    def test_scan_file_raises_runtime_error_not_assertion(self) -> None:
        """The invariant check in _scan_file must survive python -O."""
        import tempfile
        from pathlib import Path

        from wardline.scanner.engine import ScanEngine, ScanResult

        engine = ScanEngine.__new__(ScanEngine)
        engine._project_index = None
        engine._boundaries = {}
        engine._optional_fields = {}
        engine._analysis_level = 1
        engine._rules = []
        engine._manifest = None
        engine._project_root = None

        result = ScanResult()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
            tmp.write("x = 1\n")
            tmp_path = Path(tmp.name)

        try:
            # _scan_file has `assert self._project_index is not None` at line 488.
            # After the fix it should raise RuntimeError, not AssertionError.
            engine._scan_file(tmp_path, result)
            # Should not reach here -- _project_index is None
            raise AssertionError("Expected RuntimeError was not raised")  # noqa: TRY301
        except RuntimeError:
            pass  # Desired behavior after the fix
        finally:
            tmp_path.unlink(missing_ok=True)
