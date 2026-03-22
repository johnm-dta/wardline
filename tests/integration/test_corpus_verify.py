"""Integration tests for ``wardline corpus verify`` CLI command."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE_CORPUS = (
    Path(__file__).parent.parent / "fixtures" / "corpus"
)


@pytest.mark.integration
class TestCorpusVerifyIntegration:
    """End-to-end tests for corpus verify."""

    def test_verify_fixture_corpus(self) -> None:
        """Run verify on fixture corpus and check output."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
        )
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}.\n"
            f"output: {result.output}\n"
        )
        assert "Lite bootstrap:" in result.output
        # Should report at least 1 specimen
        assert "Lite bootstrap: 0 specimens" not in result.output

    def test_verify_help(self) -> None:
        """Verify --help works for corpus verify."""
        runner = CliRunner()
        result = runner.invoke(cli, ["corpus", "verify", "--help"])
        assert result.exit_code == 0
        assert "--corpus-dir" in result.output
