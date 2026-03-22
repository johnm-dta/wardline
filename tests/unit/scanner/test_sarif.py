"""Tests for SARIF v2.1.0 output module."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity

if TYPE_CHECKING:
    from pathlib import Path
from wardline.scanner.context import Finding
from wardline.scanner.sarif import SarifReport


def _make_finding(
    *,
    rule_id: RuleId = RuleId.PY_WL_001,
    file_path: str = "src/example.py",
    line: int = 10,
    col: int = 4,
    end_line: int | None = 10,
    end_col: int | None = 30,
    message: str = "Use .get() with a default",
    severity: Severity = Severity.ERROR,
    exceptionability: Exceptionability = Exceptionability.STANDARD,
    taint_state: object = None,
    analysis_level: int = 1,
    source_snippet: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
        message=message,
        severity=severity,
        exceptionability=exceptionability,
        taint_state=taint_state,
        analysis_level=analysis_level,
        source_snippet=source_snippet,
    )


# ---------------------------------------------------------------------------
# TestSarifStructure
# ---------------------------------------------------------------------------


class TestSarifStructure:
    def test_empty_report_valid_structure(self) -> None:
        report = SarifReport(findings=[], verification_mode=True)
        d = report.to_dict()
        assert d["version"] == "2.1.0"
        assert len(d["runs"]) == 1
        assert d["runs"][0]["results"] == []

    def test_schema_version(self) -> None:
        report = SarifReport(findings=[], verification_mode=True)
        d = report.to_dict()
        assert d["$schema"].endswith("sarif-schema-2.1.0.json")
        assert d["version"] == "2.1.0"

    def test_tool_info(self) -> None:
        report = SarifReport(findings=[], tool_version="1.2.3")
        d = report.to_dict()
        driver = d["runs"][0]["tool"]["driver"]
        assert driver["name"] == "wardline"
        assert driver["version"] == "1.2.3"
        assert driver["informationUri"] == "https://wardline.dev"


# ---------------------------------------------------------------------------
# TestSarifResults
# ---------------------------------------------------------------------------


class TestSarifResults:
    def test_single_finding_produces_result(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        d = report.to_dict()
        assert len(d["runs"][0]["results"]) == 1

    def test_result_has_required_fields(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        result = report.to_dict()["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

    def test_result_property_bag(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert "wardline.rule" in props
        assert "wardline.severity" in props
        assert "wardline.exceptionability" in props
        assert "wardline.analysisLevel" in props

    def test_sarif_level_mapping(self) -> None:
        err = _make_finding(severity=Severity.ERROR)
        warn = _make_finding(severity=Severity.WARNING, line=20)
        report = SarifReport(findings=[err, warn])
        results = report.to_dict()["runs"][0]["results"]
        # Both have same ruleId; check by line instead.
        level_by_line = {
            r["locations"][0]["physicalLocation"]["region"]["startLine"]: r["level"]
            for r in results
        }
        assert level_by_line[10] == "error"
        assert level_by_line[20] == "warning"

    def test_column_is_1_based(self) -> None:
        finding = _make_finding(col=0, end_col=5)
        report = SarifReport(findings=[finding])
        region = (
            report.to_dict()["runs"][0]["results"][0]["locations"][0][
                "physicalLocation"
            ]["region"]
        )
        assert region["startColumn"] == 1
        assert region["endColumn"] == 6


# ---------------------------------------------------------------------------
# TestSarifDeterminism
# ---------------------------------------------------------------------------


class TestSarifDeterminism:
    def test_results_sorted_by_file_and_line(self) -> None:
        f1 = _make_finding(file_path="z.py", line=1)
        f2 = _make_finding(file_path="a.py", line=5)
        f3 = _make_finding(file_path="a.py", line=2)
        report = SarifReport(findings=[f1, f2, f3])
        results = report.to_dict()["runs"][0]["results"]
        locations = [
            (
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]["region"]["startLine"],
            )
            for r in results
        ]
        assert locations == [("a.py", 2), ("a.py", 5), ("z.py", 1)]

    def test_same_input_same_output(self) -> None:
        findings = [_make_finding(), _make_finding(line=20)]
        r1 = SarifReport(findings=findings, verification_mode=True)
        r2 = SarifReport(findings=findings, verification_mode=True)
        assert r1.to_json_string() == r2.to_json_string()

    def test_verification_mode_omits_timestamps(self) -> None:
        report = SarifReport(
            findings=[_make_finding()], verification_mode=True
        )
        text = report.to_json_string()
        assert "timestamp" not in text.lower()
        assert "invocationStartTimeUtc" not in text
        assert "invocationEndTimeUtc" not in text


# ---------------------------------------------------------------------------
# TestSarifRuleDescriptors
# ---------------------------------------------------------------------------


class TestSarifRuleDescriptors:
    def test_rule_descriptors_generated(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        rules = report.to_dict()["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "PY-WL-001"

    def test_unverified_default_not_in_implemented_rules(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        implemented = props["wardline.implementedRules"]
        assert "PY-WL-001-UNVERIFIED-DEFAULT" not in implemented
        # But canonical rules are present.
        assert "PY-WL-001" in implemented


# ---------------------------------------------------------------------------
# TestSarifPropertyBags
# ---------------------------------------------------------------------------


class TestSarifPropertyBags:
    def test_run_level_property_bag(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.propertyBagVersion" in props
        assert "wardline.implementedRules" in props
        assert "wardline.conformanceGaps" in props
        assert "wardline.unknownRawFunctionCount" in props
        assert "wardline.unresolvedDecoratorCount" in props

    def test_unknown_raw_count_defaults_to_zero(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.unknownRawFunctionCount"] == 0
        assert props["wardline.unresolvedDecoratorCount"] == 0

    def test_unknown_raw_count_wired(self) -> None:
        report = SarifReport(
            findings=[], unknown_raw_count=5, unresolved_decorator_count=3
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.unknownRawFunctionCount"] == 5
        assert props["wardline.unresolvedDecoratorCount"] == 3

    def test_property_bag_version(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.propertyBagVersion"] == "1"


# ---------------------------------------------------------------------------
# TestSarifOutput
# ---------------------------------------------------------------------------


class TestSarifOutput:
    def test_to_json_writes_file(self, tmp_path: Path) -> None:
        report = SarifReport(findings=[_make_finding()])
        out = tmp_path / "report.sarif"
        report.to_json(out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"

    def test_to_json_string(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        text = report.to_json_string()
        data = json.loads(text)
        assert data["version"] == "2.1.0"

    def test_json_breaking_characters(self) -> None:
        finding = _make_finding(
            message='He said "hello"\nand then\ttabbed'
        )
        report = SarifReport(findings=[finding])
        text = report.to_json_string()
        # Must parse cleanly — no broken JSON from special chars.
        data = json.loads(text)
        result = data["runs"][0]["results"][0]
        assert '"hello"' in result["message"]["text"]
        assert "\n" in result["message"]["text"]
