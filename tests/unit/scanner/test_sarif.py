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
    qualname: str | None = None,
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
        qualname=qualname,
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
        assert "wardline.taintState" in props
        assert "wardline.severity" in props
        assert "wardline.exceptionability" in props
        assert "wardline.analysisLevel" in props

    def test_result_property_bag_contains_explicit_taint_state(self) -> None:
        report = SarifReport(findings=[_make_finding(taint_state="PIPELINE")])
        result = report.to_dict()["runs"][0]["results"][0]
        assert result["properties"]["wardline.taintState"] == "PIPELINE"

    def test_result_property_bag_defaults_taint_state_when_missing(self) -> None:
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert props["wardline.taintState"] == "UNKNOWN"

    def test_mandatory_properties_never_omitted(self) -> None:
        """All 5 mandatory properties (§A.3) present even when taint_state is None."""
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        mandatory = [
            "wardline.rule",
            "wardline.taintState",
            "wardline.severity",
            "wardline.exceptionability",
            "wardline.analysisLevel",
        ]
        for key in mandatory:
            assert key in props, f"mandatory key {key!r} missing from properties"
            assert props[key] is not None, f"mandatory key {key!r} is None"

    def test_result_property_bag_qualname_and_snippet(self) -> None:
        """wardline.qualname and wardline.sourceSnippet appear when set."""
        finding = _make_finding(qualname="MyClass.handle", source_snippet="x = 1")
        report = SarifReport(findings=[finding])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert props["wardline.qualname"] == "MyClass.handle"
        assert props["wardline.sourceSnippet"] == "x = 1"

    def test_result_property_bag_omits_none_qualname(self) -> None:
        """None-valued qualname and sourceSnippet are omitted (not serialized as null)."""
        report = SarifReport(findings=[_make_finding()])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert "wardline.qualname" not in props
        assert "wardline.sourceSnippet" not in props

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

    def test_absolute_file_path_is_made_relative_to_base_path(self) -> None:
        report = SarifReport(
            findings=[
                _make_finding(file_path="/repo/src/example.py"),
            ],
            base_path="/repo",
        )
        result = report.to_dict()["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/example.py"


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

    def test_governed_default_not_in_implemented_rules(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        implemented = props["wardline.implementedRules"]
        assert "PY-WL-001-GOVERNED-DEFAULT" not in implemented
        # But canonical rules are present.
        assert "PY-WL-001" in implemented

    def test_conformance_gaps_empty(self) -> None:
        """Conformance gaps must remain empty after WP 1.3."""
        report = SarifReport(findings=[])
        output = report.to_dict()
        gaps = output["runs"][0]["properties"]["wardline.conformanceGaps"]
        assert gaps == []

    def test_canonical_rule_short_descriptions_are_authoritative(self) -> None:
        findings = [
            _make_finding(rule_id=RuleId.PY_WL_001),
            _make_finding(rule_id=RuleId.PY_WL_002, line=20),
            _make_finding(rule_id=RuleId.PY_WL_003, line=30),
            _make_finding(rule_id=RuleId.PY_WL_004, line=40),
            _make_finding(rule_id=RuleId.PY_WL_005, line=50),
            _make_finding(rule_id=RuleId.PY_WL_006, line=60),
            _make_finding(rule_id=RuleId.PY_WL_007, line=70),
            _make_finding(rule_id=RuleId.PY_WL_008, line=80),
            _make_finding(rule_id=RuleId.PY_WL_009, line=90),
        ]
        report = SarifReport(findings=findings)
        rules = report.to_dict()["runs"][0]["tool"]["driver"]["rules"]
        descriptions = {rule["id"]: rule["shortDescription"]["text"] for rule in rules}

        assert descriptions["PY-WL-001"] == "Dict key access with fallback default"
        assert descriptions["PY-WL-002"] == "Attribute access with fallback default"
        assert descriptions["PY-WL-003"] == "Existence-checking as structural gate"
        assert descriptions["PY-WL-004"] == "Broad exception handler"
        assert descriptions["PY-WL-005"] == "Silent exception handler"
        assert descriptions["PY-WL-006"] == "Audit-critical write in broad exception handler"
        assert descriptions["PY-WL-007"] == "Runtime type-checking on internal data"
        assert descriptions["PY-WL-008"] == "Validation boundary with no rejection path"
        assert descriptions["PY-WL-009"] == "Semantic validation without prior shape validation"


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

    def test_files_with_degraded_taint_defaults_to_zero(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.filesWithDegradedTaint"] == 0

    def test_files_with_degraded_taint_wired(self) -> None:
        report = SarifReport(findings=[], files_with_degraded_taint=2)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.filesWithDegradedTaint"] == 2

    def test_property_bag_version(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.propertyBagVersion"] == "0.2"


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


# ---------------------------------------------------------------------------
# TestSarifGovernanceMetadata
# ---------------------------------------------------------------------------


class TestSarifGovernanceMetadata:
    """Tests for WP 2.4 governance metadata fields in run-level properties."""

    def test_analysis_level_in_run_properties(self) -> None:
        report = SarifReport(findings=[], analysis_level=3)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.analysisLevel"] == 3

    def test_analysis_level_defaults_to_1(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.analysisLevel"] == 1

    def test_manifest_hash_present_when_set(self) -> None:
        report = SarifReport(findings=[], manifest_hash="abc123def")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.manifestHash"] == "abc123def"

    def test_manifest_hash_none_when_not_set(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.manifestHash" not in props

    def test_scan_timestamp_present_when_not_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=False,
            scan_timestamp="2026-03-24T12:00:00Z",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.scanTimestamp"] == "2026-03-24T12:00:00Z"

    def test_scan_timestamp_absent_in_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=True,
            scan_timestamp="2026-03-24T12:00:00Z",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.scanTimestamp" not in props

    def test_commit_ref_present_when_not_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=False,
            commit_ref="a1b2c3d4",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.commitRef"] == "a1b2c3d4"

    def test_commit_ref_absent_in_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=True,
            commit_ref="a1b2c3d4",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.commitRef" not in props

    def test_control_law_defaults_to_normal(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.controlLaw"] == "normal"

    def test_control_law_propagated_to_run_properties(self) -> None:
        report = SarifReport(findings=[], control_law="alternate")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.controlLaw"] == "alternate"

    def test_defaults_all_none_except_analysis_level(self) -> None:
        report = SarifReport(findings=[])
        assert report.analysis_level == 1
        assert report.control_law == "normal"
        assert report.manifest_hash is None
        assert report.scan_timestamp is None
        assert report.commit_ref is None
