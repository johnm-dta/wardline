"""Integration tests for wardline explain command."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from click.testing import CliRunner

from wardline.cli.main import cli


@pytest.mark.integration
class TestExplainDecorated:
    """Explain shows decorator-based taint resolution."""

    def test_decorated_function(self, tmp_path: Path) -> None:
        """A function with @external_boundary shows decorator resolution."""
        py_file = tmp_path / "service.py"
        py_file.write_text(
            textwrap.dedent("""\
                from wardline.decorators.authority import external_boundary

                @external_boundary
                def ingest(data):
                    return data
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "ingest", "--path", str(tmp_path)]
        )

        assert result.exit_code == 0, result.output
        assert "EXTERNAL_RAW" in result.output
        assert "decorator" in result.output.lower()
        assert "external_boundary" in result.output


@pytest.mark.integration
class TestExplainUndeclaredModule:
    """Explain shows UNKNOWN_RAW for undeclared modules."""

    def test_undeclared_module_no_manifest(self, tmp_path: Path) -> None:
        """A function with no manifest shows UNKNOWN_RAW fallback."""
        py_file = tmp_path / "unknown_module.py"
        py_file.write_text(
            textwrap.dedent("""\
                def helper():
                    pass
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "helper", "--path", str(tmp_path)]
        )

        assert result.exit_code == 0, result.output
        assert "UNKNOWN_RAW" in result.output
        assert "no manifest loaded" in result.output.lower()

    def test_undeclared_module_with_manifest(self, tmp_path: Path) -> None:
        """A function in a module not in module_tiers shows UNKNOWN_RAW."""
        py_file = tmp_path / "unknown_module.py"
        py_file.write_text(
            textwrap.dedent("""\
                def helper():
                    pass
            """)
        )

        # Create a minimal valid manifest that doesn't cover this module
        manifest_file = tmp_path / "wardline.yaml"
        manifest_file.write_text(
            textwrap.dedent("""\
                $id: "https://wardline.dev/schemas/wardline/0.1"
                tiers:
                  - id: core
                    tier: 1
                    description: Core tier
                module_tiers:
                  - path: /some/other/path
                    default_taint: PIPELINE
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "explain",
                "helper",
                "--path",
                str(tmp_path),
                "--manifest",
                str(manifest_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "UNKNOWN_RAW" in result.output
        assert "module not declared" in result.output.lower()


@pytest.mark.integration
class TestExplainUnresolvedDecorator:
    """Explain shows unresolved decorator info."""

    def test_unresolved_decorator(self, tmp_path: Path) -> None:
        """A function with an unknown wardline decorator reports it."""
        py_file = tmp_path / "deco_test.py"
        py_file.write_text(
            textwrap.dedent("""\
                from wardline.decorators.authority import external_boundary
                from wardline.decorators.audit import audit_critical

                @external_boundary
                @audit_critical
                def process(data):
                    return data
            """)
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "process", "--path", str(tmp_path)]
        )

        assert result.exit_code == 0, result.output
        # Should show EXTERNAL_RAW from external_boundary
        assert "EXTERNAL_RAW" in result.output
        assert "decorator" in result.output.lower()
        # audit_critical is not in DECORATOR_TAINT_MAP but IS in registry,
        # so it appears as an unresolved decorator
        assert "unresolved" in result.output.lower()
        assert "audit_critical" in result.output


@pytest.mark.integration
class TestExplainNotFound:
    """Explain exits 1 for unknown functions."""

    def test_function_not_found(self, tmp_path: Path) -> None:
        """A nonexistent function produces exit 1."""
        py_file = tmp_path / "empty.py"
        py_file.write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", "nonexistent", "--path", str(tmp_path)]
        )

        assert result.exit_code == 1
        assert "not found" in result.output
