"""Full integration tests for ``wardline scan --preview-phase2``.

Exercises the complete pipeline:
  manifest loading → overlay resolution → rule execution →
  exception register → preview report building → JSON output.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from wardline.cli.main import cli

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixture construction helpers
# ---------------------------------------------------------------------------

def _write_manifest(tmp_path: Path) -> Path:
    """Write a wardline.yaml that declares src/ as a module tier."""
    manifest = tmp_path / "wardline.yaml"
    manifest.write_text(
        "tiers:\n"
        '  - id: "app"\n'
        "    tier: 1\n"
        '    description: "application tier"\n'
        "module_tiers:\n"
        '  - path: "src/"\n'
        '    default_taint: "EXTERNAL_RAW"\n'
        "metadata:\n"
        '  organisation: "TestOrg"\n',
        encoding="utf-8",
    )
    return manifest


def _write_source_file(src_dir: Path) -> Path:
    """Write src/app.py with three test functions."""
    src_dir.mkdir(parents=True, exist_ok=True)
    app_py = src_dir / "app.py"
    app_py.write_text(
        '"""Test fixture for preview-phase2 integration tests."""\n'
        "\n"
        "from wardline import schema_default\n"
        "\n"
        "def ungoverned_fn(data):\n"
        "    \"\"\"schema_default() with no overlay boundary → PY-WL-001-UNGOVERNED-DEFAULT.\"\"\"\n"
        "    return schema_default(data.get(\"key\", \"\"))\n"
        "\n"
        "\n"
        "def governed_fn(data):\n"
        "    \"\"\"schema_default() covered by overlay boundary → PY-WL-001-GOVERNED-DEFAULT (SUPPRESS).\"\"\"\n"
        "    return schema_default(data.get(\"key\", \"\"))\n"
        "\n"
        "\n"
        "def get_fn(data):\n"
        "    \"\"\"Regular .get() with literal default → PY-WL-001 (not UNGOVERNED-DEFAULT).\"\"\"\n"
        "    return data.get(\"key\", 42)\n",
        encoding="utf-8",
    )
    return app_py


def _write_overlay(src_dir: Path) -> None:
    """Write src/wardline.overlay.yaml governing governed_fn."""
    overlay = src_dir / "wardline.overlay.yaml"
    overlay.write_text(
        "overlay_for: src\n"
        "boundaries:\n"
        "  - function: governed_fn\n"
        "    transition: shape_validation\n"
        "optional_fields:\n"
        "  - field: key\n"
        "    approved_default: \"\"\n"
        "    rationale: Approved empty default in validation boundary\n",
        encoding="utf-8",
    )


def _write_exceptions(
    tmp_path: Path,
    *,
    fingerprint_a: str,
    fingerprint_b: str,
) -> None:
    """Write wardline.exceptions.json with two exceptions.

    Exception A: wrong fingerprint (stale) + no expiry → stale_fingerprint + no_expiry.
    Exception B: unknown provenance + recurring              → unknown_provenance + recurring.
    """
    exceptions = {
        "exceptions": [
            {
                "id": "EXC-A",
                "rule": "PY-WL-001",
                "taint_state": "UNKNOWN_RAW",
                "location": "src/app.py::get_fn",
                "exceptionability": "STANDARD",
                "severity_at_grant": "ERROR",
                "rationale": "Grandfathered for testing.",
                "reviewer": "test-reviewer",
                "expires": None,
                "agent_originated": True,
                "ast_fingerprint": fingerprint_a,
                "recurrence_count": 0,
            },
            {
                "id": "EXC-B",
                "rule": "PY-WL-001",
                "taint_state": "UNKNOWN_RAW",
                "location": "src/app.py::ungoverned_fn",
                "exceptionability": "STANDARD",
                "severity_at_grant": "ERROR",
                "rationale": "Agent-created exception with recurrence.",
                "reviewer": "test-reviewer",
                "expires": "2027-01-01",
                "agent_originated": None,
                "ast_fingerprint": fingerprint_b,
                "recurrence_count": 3,
            },
        ]
    }
    exc_file = tmp_path / "wardline.exceptions.json"
    exc_file.write_text(json.dumps(exceptions), encoding="utf-8")


def _build_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """Build the complete test fixture, returning (manifest_path, app_py_path).

    Fingerprint for EXC-A is deliberately wrong ("0000000000000000").
    Fingerprint for EXC-B uses an empty string (always-stale, no match needed).
    """
    manifest = _write_manifest(tmp_path)
    src_dir = tmp_path / "src"
    app_py = _write_source_file(src_dir)
    _write_overlay(src_dir)

    # EXC-A: wrong fingerprint → stale_fingerprint will be emitted when it
    # tries to match the get_fn PY-WL-001 finding.
    fingerprint_a = "0000000000000000"

    # EXC-B: empty fingerprint is also stale, but we only care about the
    # register-level governance (unknown_provenance + recurring) which fires
    # regardless of finding matches.
    fingerprint_b = ""

    _write_exceptions(tmp_path, fingerprint_a=fingerprint_a, fingerprint_b=fingerprint_b)

    return manifest, app_py


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestPreviewPhase2FullPipeline:
    """Full integration tests for --preview-phase2 report generation."""

    def _run_preview(
        self,
        tmp_path: Path,
        extra_args: list[str] | None = None,
    ) -> dict:
        """Run ``wardline scan --preview-phase2`` and return parsed JSON."""
        manifest, _app_py = _build_fixture(tmp_path)
        runner = CliRunner()
        args = [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--preview-phase2",
        ]
        if extra_args:
            args.extend(extra_args)
        result = runner.invoke(cli, args)
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"Unexpected exception: {result.exception}\n{result.output}"
        )
        return json.loads(result.stdout)

    # --- Output format ---

    def test_output_is_valid_json(self, tmp_path: Path) -> None:
        """--preview-phase2 output parses as valid JSON."""
        report = self._run_preview(tmp_path)
        assert isinstance(report, dict)

    def test_output_has_required_top_level_keys(self, tmp_path: Path) -> None:
        """Report contains all required top-level keys."""
        report = self._run_preview(tmp_path)
        assert "version" in report
        assert "scan_metadata" in report
        assert "unverified_default_count" in report
        assert "exception_rereview_count" in report
        assert "total_phase2_impact" in report
        assert "details" in report

    def test_output_is_not_sarif(self, tmp_path: Path) -> None:
        """Report does NOT contain SARIF '$schema' or 'runs' keys."""
        report = self._run_preview(tmp_path)
        assert "$schema" not in report
        assert "runs" not in report

    def test_scan_metadata_fields_populated(self, tmp_path: Path) -> None:
        """scan_metadata has wardline_version, scanned_path, and timestamp."""
        report = self._run_preview(tmp_path)
        meta = report["scan_metadata"]
        assert meta["wardline_version"]  # non-empty string
        assert meta["scanned_path"]      # non-empty string
        assert meta["timestamp"]         # non-empty string

    # --- Unverified defaults ---

    def test_unverified_default_count_is_one(self, tmp_path: Path) -> None:
        """Only the ungoverned schema_default() call appears as unverified default."""
        report = self._run_preview(tmp_path)
        assert report["unverified_default_count"] == 1

    def test_unverified_defaults_contains_ungoverned_fn(
        self, tmp_path: Path
    ) -> None:
        """unverified_defaults list has exactly one entry for ungoverned_fn."""
        report = self._run_preview(tmp_path)
        defaults = report["details"]["unverified_defaults"]
        assert len(defaults) == 1
        assert defaults[0]["qualname"] == "ungoverned_fn"

    def test_governed_fn_not_in_unverified_defaults(
        self, tmp_path: Path
    ) -> None:
        """governed_fn (covered by overlay boundary) does NOT appear in unverified_defaults."""
        report = self._run_preview(tmp_path)
        defaults = report["details"]["unverified_defaults"]
        qualnames = [d["qualname"] for d in defaults]
        assert "governed_fn" not in qualnames

    def test_get_fn_not_in_unverified_defaults(
        self, tmp_path: Path
    ) -> None:
        """.get() with literal default emits PY-WL-001, NOT in unverified_defaults."""
        report = self._run_preview(tmp_path)
        defaults = report["details"]["unverified_defaults"]
        qualnames = [d["qualname"] for d in defaults]
        assert "get_fn" not in qualnames

    # --- Exception rereview ---

    def test_exception_rereview_count_is_two(self, tmp_path: Path) -> None:
        """Two distinct exception IDs appear in the rereview list."""
        report = self._run_preview(tmp_path)
        assert report["exception_rereview_count"] == 2

    def test_exception_a_reasons_include_stale_fingerprint(
        self, tmp_path: Path
    ) -> None:
        """Exception A (wrong fingerprint) has 'stale_fingerprint' in reasons."""
        report = self._run_preview(tmp_path)
        rerereview = report["details"]["exceptions_needing_rereview"]
        exc_a = next(
            (e for e in rerereview if e["exception_id"] == "EXC-A"), None
        )
        assert exc_a is not None, "EXC-A not found in exceptions_needing_rereview"
        assert "stale_fingerprint" in exc_a["reasons"]

    def test_exception_a_reasons_include_no_expiry(
        self, tmp_path: Path
    ) -> None:
        """Exception A (no expires field) has 'no_expiry' in reasons."""
        report = self._run_preview(tmp_path)
        rerereview = report["details"]["exceptions_needing_rereview"]
        exc_a = next(
            (e for e in rerereview if e["exception_id"] == "EXC-A"), None
        )
        assert exc_a is not None, "EXC-A not found in exceptions_needing_rereview"
        assert "no_expiry" in exc_a["reasons"]

    def test_exception_b_reasons_include_unknown_provenance(
        self, tmp_path: Path
    ) -> None:
        """Exception B (agent_originated=null) has 'unknown_provenance' in reasons."""
        report = self._run_preview(tmp_path)
        rerereview = report["details"]["exceptions_needing_rereview"]
        exc_b = next(
            (e for e in rerereview if e["exception_id"] == "EXC-B"), None
        )
        assert exc_b is not None, "EXC-B not found in exceptions_needing_rereview"
        assert "unknown_provenance" in exc_b["reasons"]

    def test_exception_b_reasons_include_recurring(
        self, tmp_path: Path
    ) -> None:
        """Exception B (recurrence_count=3) has 'recurring' in reasons."""
        report = self._run_preview(tmp_path)
        rerereview = report["details"]["exceptions_needing_rereview"]
        exc_b = next(
            (e for e in rerereview if e["exception_id"] == "EXC-B"), None
        )
        assert exc_b is not None, "EXC-B not found in exceptions_needing_rereview"
        assert "recurring" in exc_b["reasons"]

    # --- total_phase2_impact ---

    def test_total_phase2_impact_is_three(self, tmp_path: Path) -> None:
        """total_phase2_impact == unverified_default_count + exception_rereview_count."""
        report = self._run_preview(tmp_path)
        assert report["total_phase2_impact"] == (
            report["unverified_default_count"] + report["exception_rereview_count"]
        )

    # --- --output flag ---

    def test_output_flag_writes_to_file(self, tmp_path: Path) -> None:
        """--output writes the preview report JSON to a file."""
        manifest, _app_py = _build_fixture(tmp_path)
        output_file = tmp_path / "preview.json"
        runner = CliRunner()
        runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
            "--preview-phase2",
            "--output", str(output_file),
        ])
        assert output_file.exists()
        report = json.loads(output_file.read_text(encoding="utf-8"))
        assert "version" in report
        assert "scan_metadata" in report
        assert report["unverified_default_count"] == 1
        assert report["exception_rereview_count"] == 2
