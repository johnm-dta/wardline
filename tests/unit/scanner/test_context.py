"""Tests for scanner data models — Finding, ScanContext, WardlineAnnotation."""

from __future__ import annotations

import datetime
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import ExceptionEntry
from wardline.scanner.context import Finding, ScanContext, WardlineAnnotation, make_governance_finding
from wardline.scanner.exceptions import apply_exceptions

# ── Finding ───────────────────────────────────────────────────────


class TestFinding:
    """Finding is a frozen dataclass — no mutation allowed."""

    @pytest.fixture()
    def finding(self) -> Finding:
        return Finding(
            rule_id=RuleId.PY_WL_004,
            file_path="src/example.py",
            line=10,
            col=4,
            end_line=12,
            end_col=0,
            message="Broad exception handler",
            severity=Severity.WARNING,
            exceptionability=Exceptionability.RELAXED,
            taint_state=TaintState.EXTERNAL_RAW,
            analysis_level=1,
            source_snippet="except Exception:",
        )

    def test_fields_accessible(self, finding: Finding) -> None:
        assert finding.rule_id == RuleId.PY_WL_004
        assert finding.file_path == "src/example.py"
        assert finding.line == 10
        assert finding.col == 4
        assert finding.end_line == 12
        assert finding.end_col == 0
        assert finding.severity == Severity.WARNING
        assert finding.exceptionability == Exceptionability.RELAXED
        assert finding.taint_state == TaintState.EXTERNAL_RAW
        assert finding.analysis_level == 1
        assert finding.source_snippet == "except Exception:"

    def test_frozen_rejects_mutation(self, finding: Finding) -> None:
        with pytest.raises(FrozenInstanceError):
            finding.line = 99  # type: ignore[misc]

    def test_frozen_rejects_new_attr(self, finding: Finding) -> None:
        with pytest.raises(FrozenInstanceError):
            finding.extra = "nope"  # type: ignore[attr-defined]

    def test_optional_fields_accept_none(self) -> None:
        f = Finding(
            rule_id=RuleId.PY_WL_001,
            file_path="test.py",
            line=1,
            col=0,
            end_line=None,
            end_col=None,
            message="test",
            severity=Severity.ERROR,
            exceptionability=Exceptionability.UNCONDITIONAL,
            taint_state=TaintState.AUDIT_TRAIL,
            analysis_level=1,
            source_snippet=None,
        )
        assert f.end_line is None
        assert f.end_col is None
        assert f.source_snippet is None


# ── ScanContext ───────────────────────────────────────────────────


class TestScanContext:
    """ScanContext is frozen with deeply frozen taint map."""

    @pytest.fixture()
    def context(self) -> ScanContext:
        return ScanContext(
            file_path="src/example.py",
            function_level_taint_map={
                "example.handler": TaintState.EXTERNAL_RAW,
                "example.process": TaintState.PIPELINE,
            },
        )

    def test_fields_accessible(self, context: ScanContext) -> None:
        assert context.file_path == "src/example.py"
        assert len(context.function_level_taint_map) == 2

    def test_taint_map_is_mapping_proxy(self, context: ScanContext) -> None:
        assert isinstance(
            context.function_level_taint_map, MappingProxyType
        )

    def test_taint_map_lookup_works(self, context: ScanContext) -> None:
        assert (
            context.function_level_taint_map["example.handler"]
            is TaintState.EXTERNAL_RAW
        )

    def test_taint_map_rejects_mutation(self, context: ScanContext) -> None:
        with pytest.raises(TypeError):
            context.function_level_taint_map["new_key"] = TaintState.MIXED_RAW  # type: ignore[index]

    def test_taint_map_rejects_deletion(self, context: ScanContext) -> None:
        with pytest.raises(TypeError):
            del context.function_level_taint_map["example.handler"]  # type: ignore[arg-type]

    def test_frozen_rejects_attr_rebinding(self, context: ScanContext) -> None:
        with pytest.raises(FrozenInstanceError):
            context.file_path = "other.py"  # type: ignore[misc]

    def test_frozen_rejects_map_rebinding(self, context: ScanContext) -> None:
        with pytest.raises(FrozenInstanceError):
            context.function_level_taint_map = {}  # type: ignore[misc]

    def test_empty_taint_map(self) -> None:
        ctx = ScanContext(file_path="empty.py", function_level_taint_map={})
        assert isinstance(ctx.function_level_taint_map, MappingProxyType)
        assert len(ctx.function_level_taint_map) == 0

    def test_accepts_mapping_proxy_directly(self) -> None:
        mp = MappingProxyType({"f": TaintState.PIPELINE})
        ctx = ScanContext(file_path="test.py", function_level_taint_map=mp)
        assert ctx.function_level_taint_map is mp

    def test_project_maps_are_deeply_frozen(self) -> None:
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},
            project_annotations_map={
                ("test.py", "target"): (
                    WardlineAnnotation(
                        canonical_name="test_only",
                        group=15,
                        attrs={},
                    ),
                )
            },
            module_file_map={"pkg.mod": "pkg/mod.py"},
            string_literal_counts={"beta": 2},
        )

        assert isinstance(ctx.project_annotations_map, MappingProxyType)
        assert isinstance(ctx.module_file_map, MappingProxyType)
        assert isinstance(ctx.string_literal_counts, MappingProxyType)
        with pytest.raises(TypeError):
            ctx.module_file_map["pkg.other"] = "pkg/other.py"  # type: ignore[index]


# ── WardlineAnnotation ────────────────────────────────────────────


class TestWardlineAnnotation:
    """WardlineAnnotation is frozen with deeply frozen attrs."""

    def test_construction_from_dict(self) -> None:
        ann = WardlineAnnotation(
            canonical_name="external_boundary",
            group=1,
            attrs={"_wardline_tier_source": TaintState.EXTERNAL_RAW},
        )
        assert ann.canonical_name == "external_boundary"
        assert ann.group == 1
        assert isinstance(ann.attrs, MappingProxyType)

    def test_attrs_deeply_frozen(self) -> None:
        ann = WardlineAnnotation(
            canonical_name="audit_critical",
            group=2,
            attrs={"_wardline_audit_critical": True},
        )
        with pytest.raises(TypeError):
            ann.attrs["new"] = "val"  # type: ignore[index]

    def test_frozen_rejects_mutation(self) -> None:
        ann = WardlineAnnotation(
            canonical_name="test",
            group=1,
            attrs={},
        )
        with pytest.raises(FrozenInstanceError):
            ann.canonical_name = "other"  # type: ignore[misc]

    def test_accepts_mapping_proxy_directly(self) -> None:
        mp = MappingProxyType({"_wardline_tier_source": TaintState.PIPELINE})
        ann = WardlineAnnotation(
            canonical_name="tier1_read", group=1, attrs=mp
        )
        assert ann.attrs is mp


# ── make_governance_finding ───────────────────────────────────────


def test_make_governance_finding_with_exception_id():
    f = make_governance_finding(
        RuleId.GOVERNANCE_STALE_EXCEPTION,
        "test message",
        exception_id="EXC-abc12345",
        original_rule="PY-WL-001",
    )
    assert f.exception_id == "EXC-abc12345"
    assert f.original_rule == "PY-WL-001"


def test_make_governance_finding_defaults_none():
    f = make_governance_finding(
        RuleId.GOVERNANCE_STALE_EXCEPTION,
        "test message",
    )
    assert f.exception_id is None
    assert f.original_rule is None


def test_governance_findings_carry_exception_id_and_original_rule():
    """Verify _emit_register_governance forwards exception_id and original_rule."""
    exc = ExceptionEntry(
        id="EXC-test0001",
        rule="PY-WL-001",
        taint_state="UNKNOWN_RAW",
        location="src/app.py::App.handle",
        exceptionability="STANDARD",
        severity_at_grant="ERROR",
        rationale="accepted risk",
        reviewer="alice",
        ast_fingerprint="",
        expires=None,
        recurrence_count=0,
        governance_path="standard",
        agent_originated=None,
        last_refreshed_by=None,
        last_refresh_rationale=None,
        last_refreshed_at=None,
    )
    _, governance = apply_exceptions(
        [],
        (exc,),
        project_root=Path("."),
        now=datetime.date(2026, 3, 23),
    )
    assert len(governance) >= 1
    for gf in governance:
        assert gf.exception_id == "EXC-test0001", f"{gf.rule_id} missing exception_id"
        assert gf.original_rule == "PY-WL-001", f"{gf.rule_id} missing original_rule"
