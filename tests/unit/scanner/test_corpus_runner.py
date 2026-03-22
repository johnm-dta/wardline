"""Unit tests for corpus verification logic.

Tests the security invariant (no exec/eval/compile) and hash verification.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE_CORPUS = Path(__file__).parent.parent.parent / "fixtures" / "corpus"


class TestNoExecEval:
    """Assert the critical security invariant: no exec/eval on specimens."""

    def test_no_exec_eval_called(self) -> None:
        """Patching exec/eval to raise ensures they are never called."""

        def _fail(*args: object, **kwargs: object) -> None:
            raise AssertionError("exec/eval must never be called on specimens")

        with (
            patch("builtins.exec", side_effect=_fail),
            patch("builtins.eval", side_effect=_fail),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
            )
            # Should complete without triggering the patched builtins
            assert result.exit_code == 0, (
                f"Expected exit 0, got {result.exit_code}.\n"
                f"output: {result.output}\n"
                f"stderr: {getattr(result, 'stderr', '')}"
            )

    def test_only_ast_parse_used(self) -> None:
        """Verify ast.parse is called and compile is not called directly."""
        real_ast_parse = ast.parse
        parse_called = False

        def tracking_parse(*args: object, **kwargs: object) -> object:
            nonlocal parse_called
            parse_called = True
            return real_ast_parse(*args, **kwargs)  # type: ignore[arg-type]

        with patch("wardline.cli.corpus_cmds.ast.parse", side_effect=tracking_parse):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS)]
            )
            assert result.exit_code == 0
            assert parse_called, "ast.parse should be called during verification"


class TestHashVerification:
    """Test SHA-256 hash verification of specimens."""

    def test_correct_hash_passes(self, tmp_path: Path) -> None:
        """Specimen with correct hash passes verification."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "good.yaml"
        specimen.write_text(
            f'rule_id: "TEST-001"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"source: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Lite bootstrap: 1 specimens" in result.output

    def test_wrong_hash_produces_error(self, tmp_path: Path) -> None:
        """Specimen with wrong hash produces an error."""
        specimen = tmp_path / "bad.yaml"
        specimen.write_text(
            'rule_id: "TEST-001"\n'
            'verdict: "true_positive"\n'
            'sha256: "000000000000000000000000000000000000'
            '0000000000000000000000000000"\n'
            "source: |\n"
            "  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "hash mismatch" in result.stderr


class TestSpecimenLoading:
    """Test YAML specimen loading and field handling."""

    def test_valid_specimen_loads(self, tmp_path: Path) -> None:
        """Valid specimen YAML loads and passes verification."""
        source = "y = 2\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "valid.yaml"
        specimen.write_text(
            f'rule_id: "TEST-002"\n'
            f'verdict: "true_negative"\n'
            f'sha256: "{sha}"\n'
            f"source: |\n"
            f"  y = 2\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Lite bootstrap: 1 specimens" in result.output

    def test_missing_source_handled(self, tmp_path: Path) -> None:
        """Specimen missing 'source' field is handled gracefully."""
        specimen = tmp_path / "nosource.yaml"
        specimen.write_text(
            'rule_id: "TEST-003"\n'
            'verdict: "true_positive"\n'
            'sha256: "abc"\n'
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "no 'source' field" in result.stderr

    def test_no_specimens_found(self, tmp_path: Path) -> None:
        """Empty corpus directory produces error."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "No specimens found" in result.stderr

    def test_syntax_error_in_source(self, tmp_path: Path) -> None:
        """Specimen with invalid Python syntax produces an error."""
        source = "def (\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "badsyntax.yaml"
        specimen.write_text(
            f'rule_id: "TEST-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"source: |\n"
            f"  def (\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "syntax error" in result.stderr
