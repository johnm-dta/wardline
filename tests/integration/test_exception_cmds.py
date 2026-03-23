"""Integration tests for wardline exception CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli


def _make_project(tmp_path: Path) -> tuple[Path, Path]:
    """Create a minimal wardline project with a Python file containing a function.

    Returns (manifest_path, python_file_path).
    """
    manifest = tmp_path / "wardline.yaml"
    manifest.write_text(
        "tiers:\n"
        '  - id: "test"\n'
        "    tier: 1\n"
        '    description: "test tier"\n'
        "module_tiers: []\n"
        "metadata:\n"
        '  organisation: "TestOrg"\n'
    )
    py_file = tmp_path / "example.py"
    py_file.write_text(
        "def process_data(x):\n"
        "    return x + 1\n"
    )
    return manifest, py_file


@pytest.mark.integration
class TestExceptionAdd:
    """Tests for `wardline exception add`."""

    def test_add_creates_entry(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add creates an entry with a computed fingerprint."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        location = f"{py_file}::process_data"
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", location,
                "--taint-state", "PIPELINE",
                "--rationale", "Test rationale",
                "--reviewer", "tester",
                "--governance-path", "standard",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, f"stdout: {result.output}\nstderr: {result.stderr}"
        assert "Added exception EXC-" in result.output

        # Verify the file was created
        exc_file = tmp_path / "wardline.exceptions.json"
        assert exc_file.exists()

        data = json.loads(exc_file.read_text())
        assert len(data["exceptions"]) == 1
        entry = data["exceptions"][0]
        assert entry["rule"] == "PY-WL-001"
        assert entry["taint_state"] == "PIPELINE"
        assert entry["ast_fingerprint"] is not None
        assert len(entry["ast_fingerprint"]) == 16
        assert entry["recurrence_count"] == 0
        assert entry["governance_path"] == "standard"
        assert entry["provenance"] == "cli"

    def test_add_unconditional_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add with UNCONDITIONAL rule+taint combination is refused."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        # PY-WL-001 + AUDIT_TRAIL is UNCONDITIONAL per matrix
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", f"{py_file}::process_data",
                "--taint-state", "AUDIT_TRAIL",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "UNCONDITIONAL" in result.stderr

    def test_add_invalid_rule(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add with invalid rule ID is refused."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "INVALID-RULE",
                "--location", f"{py_file}::process_data",
                "--taint-state", "PIPELINE",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "invalid rule ID" in result.stderr

    def test_add_bad_location_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """add with missing :: in location is refused."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", "no_separator",
                "--taint-state", "PIPELINE",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "file_path::qualname" in result.stderr


@pytest.mark.integration
class TestExceptionRefresh:
    """Tests for `wardline exception refresh`."""

    def test_refresh_requires_actor(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh without --actor is an error."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "refresh", "EXC-12345678", "--rationale", "safe"],
        )
        assert result.exit_code != 0
        assert "actor" in (result.output + result.stderr).lower()

    def test_refresh_requires_rationale(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh without --rationale is an error."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "refresh", "EXC-12345678", "--actor", "dev"],
        )
        assert result.exit_code != 0
        assert "rationale" in (result.output + result.stderr).lower()

    def test_refresh_all_requires_confirm(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh --all without --confirm is an error."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "refresh",
                "--all", "--actor", "dev", "--rationale", "safe",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "--confirm" in result.stderr

    def test_refresh_no_ids_no_all_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh with neither IDs nor --all is an error."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "exception", "refresh",
                "--actor", "dev", "--rationale", "safe",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "provide exception IDs" in result.stderr


@pytest.mark.integration
class TestExceptionExpire:
    """Tests for `wardline exception expire`."""

    def test_expire_sets_date(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """expire sets the expires field to today."""
        _manifest, py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        # First add an exception
        runner = CliRunner()
        location = f"{py_file}::process_data"
        result = runner.invoke(
            cli,
            [
                "exception", "add",
                "--rule", "PY-WL-001",
                "--location", location,
                "--taint-state", "PIPELINE",
                "--rationale", "Test",
                "--reviewer", "tester",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

        # Get the exception ID from the output
        exc_id = result.output.split("Added exception ")[1].split(" ")[0]

        # Now expire it
        result = runner.invoke(
            cli,
            ["exception", "expire", exc_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "Expired" in result.output

        # Verify the file
        data = json.loads((tmp_path / "wardline.exceptions.json").read_text())
        entry = data["exceptions"][0]
        assert entry["expires"] is not None

    def test_expire_unknown_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """expire with unknown exception ID is an error."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "expire", "EXC-NONEXIST"],
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        assert "not found" in result.stderr


@pytest.mark.integration
class TestExceptionReview:
    """Tests for `wardline exception review`."""

    def test_review_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """review --json returns valid JSON."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "review", "--json"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "stale" in data
        assert "expired" in data
        assert "approaching_expiry" in data
        assert "unknown_provenance" in data
        assert "recurring" in data
        assert "expedited_ratio" in data
        assert "total" in data

    def test_review_text_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """review without --json shows human-readable summary."""
        _manifest, _py_file = _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["exception", "review"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "Exception Register Review" in result.output
