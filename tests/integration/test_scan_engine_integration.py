"""Integration test: ScanEngine end-to-end with fixture project.

Validates rule execution end-to-end: ScanEngine discovers files,
parses AST, and runs all 5 rules against a fixture project.
Manifest loading and taint assignment are NOT wired into this
test — that integration is deferred to T-6.4a.

Marked ``@pytest.mark.integration`` — excluded from default
``uv run pytest`` via addopts in pyproject.toml.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.severity import RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.py_wl_001 import RulePyWl001
from wardline.scanner.rules.py_wl_002 import RulePyWl002
from wardline.scanner.rules.py_wl_003 import RulePyWl003
from wardline.scanner.rules.py_wl_004 import RulePyWl004
from wardline.scanner.rules.py_wl_005 import RulePyWl005

FIXTURE_ROOT = (
    Path(__file__).parent.parent
    / "fixtures"
    / "integration"
    / "sample_project"
)


@pytest.mark.integration
class TestScanEngineIntegration:
    """End-to-end: ScanEngine on fixture project produces correct findings."""

    def _scan_fixture(self) -> list[Finding]:
        """Run all rules against the fixture project."""
        rules = (
            RulePyWl001(file_path=""),
            RulePyWl002(file_path=""),
            RulePyWl003(file_path=""),
            RulePyWl004(file_path=""),
            RulePyWl005(file_path=""),
        )
        engine = ScanEngine(
            target_paths=(FIXTURE_ROOT,),
            rules=rules,
        )
        result = engine.scan()
        return result.findings

    def test_fixture_project_exists(self) -> None:
        """Sanity: fixture project directory exists."""
        assert FIXTURE_ROOT.is_dir()
        assert (FIXTURE_ROOT / "wardline.yaml").is_file()
        assert (FIXTURE_ROOT / "adapters" / "partner_client.py").is_file()
        assert (FIXTURE_ROOT / "core" / "processor.py").is_file()

    def test_engine_scans_fixture_files(self) -> None:
        """Engine scans .py files in the fixture project."""
        engine = ScanEngine(
            target_paths=(FIXTURE_ROOT,),
            rules=(),
        )
        result = engine.scan()
        # adapters/__init__.py, adapters/partner_client.py,
        # core/__init__.py, core/processor.py
        assert result.files_scanned >= 4
        assert result.files_skipped == 0

    def test_findings_are_produced(self) -> None:
        """Engine produces findings from the fixture project."""
        findings = self._scan_fixture()
        assert len(findings) > 0

    def test_all_findings_have_required_keys(self) -> None:
        """Every finding has all required Finding fields populated."""
        findings = self._scan_fixture()
        for f in findings:
            assert isinstance(f, Finding)
            assert isinstance(f.rule_id, RuleId)
            assert isinstance(f.severity, Severity)
            assert isinstance(f.file_path, str)
            assert f.file_path != ""
            assert isinstance(f.line, int)
            assert f.line > 0
            assert isinstance(f.col, int)
            assert isinstance(f.message, str)
            assert f.message != ""
            assert isinstance(f.analysis_level, int)

    def test_py_wl_001_fires_on_dict_get(self) -> None:
        """PY-WL-001 fires on config.get("timeout", 30) in partner_client."""
        findings = self._scan_fixture()
        wl001 = [f for f in findings if f.rule_id == RuleId.PY_WL_001]
        assert len(wl001) >= 1
        assert any("partner_client" in f.file_path for f in wl001)

    def test_py_wl_002_fires_on_getattr(self) -> None:
        """PY-WL-002 fires on getattr(record, "status", "unknown") in processor."""
        findings = self._scan_fixture()
        wl002 = [f for f in findings if f.rule_id == RuleId.PY_WL_002]
        assert len(wl002) >= 1
        assert any("processor" in f.file_path for f in wl002)

    def test_py_wl_003_fires_on_existence_checks(self) -> None:
        """PY-WL-003 fires on 'in' and hasattr in processor."""
        findings = self._scan_fixture()
        wl003 = [f for f in findings if f.rule_id == RuleId.PY_WL_003]
        assert len(wl003) >= 2
        assert any("processor" in f.file_path for f in wl003)

    def test_py_wl_004_fires_on_broad_except(self) -> None:
        """PY-WL-004 fires on except Exception in partner_client."""
        findings = self._scan_fixture()
        wl004 = [f for f in findings if f.rule_id == RuleId.PY_WL_004]
        assert len(wl004) >= 2
        assert any("partner_client" in f.file_path for f in wl004)

    def test_py_wl_005_fires_on_silent_handler(self) -> None:
        """PY-WL-005 fires on except: pass in partner_client."""
        findings = self._scan_fixture()
        wl005 = [f for f in findings if f.rule_id == RuleId.PY_WL_005]
        assert len(wl005) >= 1
        assert any("partner_client" in f.file_path for f in wl005)

    def test_finding_severity_is_error(self) -> None:
        """All rule findings (non-TOOL-ERROR) are ERROR severity."""
        findings = self._scan_fixture()
        rule_findings = [f for f in findings if f.rule_id != RuleId.TOOL_ERROR]
        for f in rule_findings:
            assert f.severity == Severity.ERROR

    def test_no_tool_errors(self) -> None:
        """No rules crash during execution."""
        findings = self._scan_fixture()
        tool_errors = [f for f in findings if f.rule_id == RuleId.TOOL_ERROR]
        assert tool_errors == []

    def test_finding_line_numbers_are_valid(self) -> None:
        """All line numbers reference actual source lines."""
        findings = self._scan_fixture()
        for f in findings:
            file_path = Path(f.file_path)
            if file_path.is_file():
                source_lines = file_path.read_text().splitlines()
                assert 1 <= f.line <= len(source_lines), (
                    f"Finding {f.rule_id} line {f.line} out of range "
                    f"for {f.file_path} ({len(source_lines)} lines)"
                )
