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
        """Patching exec/eval to raise ensures they are never called.

        compile is tested separately because ast.parse() internally
        calls builtins.compile at the C level on CPython.
        """

        def _fail(*args: object, **kwargs: object) -> None:
            raise AssertionError(
                "exec/eval must never be called on specimens"
            )

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

    def test_no_compile_in_source(self) -> None:
        """corpus_cmds.py must not call compile() directly."""
        import wardline.cli.corpus_cmds as mod

        source = Path(mod.__file__).read_text()  # type: ignore[arg-type]
        # Allow "ast.parse" but not bare "compile("
        assert "compile(" not in source, (
            "corpus_cmds.py must not call compile() directly"
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

    def test_missing_fragment_handled(self, tmp_path: Path) -> None:
        """Specimen missing 'fragment' field is handled gracefully."""
        specimen = tmp_path / "nofragment.yaml"
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
        assert "no 'fragment' field" in result.stderr

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


class TestVerdictEvaluation:
    """Test specimen verdict evaluation against scanner results."""

    def test_true_positive_rule_fires(self, tmp_path: Path) -> None:
        """TP specimen where expected rule fires."""
        source = (
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TP" in result.output

    def test_true_negative_no_rule_fires(
        self, tmp_path: Path
    ) -> None:
        """TN specimen where no rule fires."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_negative"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TN" in result.output

    def test_known_false_negative_tracked(
        self, tmp_path: Path
    ) -> None:
        """KFN specimen is tracked separately."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "kfn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "known_false_negative"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 KFN" in result.output

    def test_false_negative_detected(self, tmp_path: Path) -> None:
        """TP specimen where rule does NOT fire → counted as FN."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "fn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 FN" in result.output


class TestPrecisionRecall:
    """Test precision/recall calculation and output."""

    def _make_tp_specimen(
        self, tmp_path: Path, idx: int
    ) -> None:
        """Create a TP specimen for PY-WL-004."""
        source = (
            f"def f{idx}():\n"
            f"    try:\n"
            f"        pass\n"
            f"    except Exception:\n"
            f"        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / f"tp_{idx}.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f{idx}():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )

    def test_precision_recall_printed_when_ge_5(
        self, tmp_path: Path
    ) -> None:
        """Precision/recall printed for rules with >= 5 specimens."""
        for i in range(5):
            self._make_tp_specimen(tmp_path, i)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "PY-WL-004" in result.output
        assert "precision=" in result.output

    def test_precision_recall_skipped_when_lt_5(
        self, tmp_path: Path
    ) -> None:
        """Precision/recall NOT printed for < 5 specimens."""
        self._make_tp_specimen(tmp_path, 0)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "precision=" not in result.output

    def test_kfn_excluded_from_recall(
        self, tmp_path: Path
    ) -> None:
        """KFN excluded from recall denominator."""
        # 3 TP specimens
        for i in range(3):
            self._make_tp_specimen(tmp_path, i)
        # 2 KFN specimens (total=5 but recall denom stays 3)
        for i in range(2):
            source = f"y{i} = 1\n"
            sha = hashlib.sha256(
                source.encode("utf-8")
            ).hexdigest()
            specimen = tmp_path / f"kfn_{i}.yaml"
            specimen.write_text(
                f'rule: "PY-WL-004"\n'
                f'verdict: "known_false_negative"\n'
                f'sha256: "{sha}"\n'
                f"fragment: |\n"
                f"  y{i} = 1\n"
            )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "2 KFN" in result.output
        # With 3 TP and 0 FN, recall should be 100%
        assert "recall=100.0%" in result.output
