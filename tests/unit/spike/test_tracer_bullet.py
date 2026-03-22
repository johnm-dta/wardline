"""Tests for T-1.8 Tracer Bullet — validates all 4 integration points."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import final

import jsonschema
import pytest
from spike.registry_validation import (
    validate_factory_assertion,
    validate_registry_lookup,
)
from spike.rule_base import Finding, RuleBase
from spike.rule_py_wl_004 import RulePyWl004
from spike.sarif_emitter import findings_to_sarif, validate_sarif

from wardline.core.matrix import lookup
from wardline.core.registry import REGISTRY
from wardline.core.severity import RuleId, Severity
from wardline.core.taints import TaintState

FIXTURE_PATH = Path(__file__).parents[3] / "spike" / "fixture_broad_except.py"


# ── Validation Point 1: AST Parsing + Rule Detection ──────────────


class TestAstParsingAndRuleDetection:
    """PY-WL-004 finds broad exception handlers via AST."""

    def test_fixture_parses(self) -> None:
        source = FIXTURE_PATH.read_text()
        tree = ast.parse(source, filename=str(FIXTURE_PATH))
        assert tree is not None

    def test_finds_broad_handlers(self) -> None:
        source = FIXTURE_PATH.read_text()
        tree = ast.parse(source, filename=str(FIXTURE_PATH))
        rule = RulePyWl004()
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                findings.extend(rule.visit_function(node, str(FIXTURE_PATH)))

        # 3 broad handlers: bare except, except Exception, except Exception as e
        assert len(findings) == 3

    def test_does_not_flag_specific_handlers(self) -> None:
        """Specific exception handlers should not trigger PY-WL-004."""
        source = """
def specific() -> None:
    try:
        pass
    except ValueError:
        pass
"""
        tree = ast.parse(source)
        rule = RulePyWl004()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                findings = rule.visit_function(node, "test.py")
                assert findings == []

    def test_async_function_detected(self) -> None:
        """Scanner handles async functions."""
        source = FIXTURE_PATH.read_text()
        tree = ast.parse(source, filename=str(FIXTURE_PATH))
        rule = RulePyWl004()

        async_findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                async_findings.extend(rule.visit_function(node, str(FIXTURE_PATH)))

        # async_broad_exception has one broad handler
        assert len(async_findings) == 1

    def test_severity_lookup_from_matrix(self) -> None:
        """Severity comes from the matrix, not hardcoded in the rule."""
        cell = lookup(RuleId.PY_WL_004, TaintState.EXTERNAL_RAW)
        assert cell.severity == Severity.WARNING  # Per matrix row


# ── Validation Point 2: SARIF Output + Schema Validation ─────────


class TestSarifOutput:
    """SARIF output validates against the vendored 2.1.0 schema."""

    @pytest.fixture()
    def sample_findings(self) -> list[Finding]:
        source = FIXTURE_PATH.read_text()
        tree = ast.parse(source, filename=str(FIXTURE_PATH))
        rule = RulePyWl004()
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                findings.extend(rule.visit_function(node, str(FIXTURE_PATH)))
        return findings

    def test_sarif_validates(self, sample_findings: list[Finding]) -> None:
        sarif_log = findings_to_sarif(sample_findings)
        # Should not raise
        validate_sarif(sarif_log)

    def test_sarif_has_property_bags(self, sample_findings: list[Finding]) -> None:
        sarif_log = findings_to_sarif(sample_findings)
        for result in sarif_log["runs"][0]["results"]:
            props = result["properties"]["wardline"]
            assert "taintState" in props
            assert "severity" in props
            assert "exceptionability" in props

    def test_sarif_has_correct_structure(self, sample_findings: list[Finding]) -> None:
        sarif_log = findings_to_sarif(sample_findings)
        assert sarif_log["version"] == "2.1.0"
        assert len(sarif_log["runs"]) == 1
        run = sarif_log["runs"][0]
        assert run["tool"]["driver"]["name"] == "wardline"
        assert len(run["results"]) == 3

    def test_invalid_sarif_rejected(self) -> None:
        """Schema validation catches invalid SARIF."""
        bad_sarif = {"version": "2.1.0", "runs": "not-an-array"}
        with pytest.raises(jsonschema.ValidationError):
            validate_sarif(bad_sarif)


# ── Validation Point 3: Registry Lookup + Factory Assertion ───────


class TestRegistryValidation:
    """Registry supports decorator discovery and factory assertion."""

    def test_lookup_known_decorator(self) -> None:
        entry = validate_registry_lookup("external_boundary")
        assert entry.canonical_name == "external_boundary"
        assert entry.group == 1

    def test_lookup_unknown_raises(self) -> None:
        with pytest.raises(KeyError):
            validate_registry_lookup("nonexistent_decorator")

    def test_factory_assertion_valid_attrs(self) -> None:
        """Factory assertion passes for declared attrs."""
        validate_factory_assertion(
            "external_boundary",
            {"_wardline_tier_source": TaintState.EXTERNAL_RAW},
        )

    def test_factory_assertion_undeclared_attrs(self) -> None:
        """Factory assertion rejects attrs not in the registry contract."""
        with pytest.raises(ValueError, match="does not declare attrs"):
            validate_factory_assertion(
                "external_boundary",
                {"_wardline_bogus_attr": "value"},
            )

    def test_factory_assertion_unknown_name(self) -> None:
        with pytest.raises(KeyError):
            validate_factory_assertion("nonexistent", {})

    def test_registry_attrs_are_frozen(self) -> None:
        """Registry entries use MappingProxyType — no post-construction mutation."""
        entry = REGISTRY["external_boundary"]
        with pytest.raises(TypeError):
            entry.attrs["_new_key"] = str  # type: ignore[index]


# ── Validation Point 4: RuleBase Pattern ──────────────────────────


class TestRuleBasePattern:
    """RuleBase enforcement: @typing.final, __init_subclass__, @abstractmethod."""

    def test_abstractmethod_enforcement_at_instantiation(self) -> None:
        """@abstractmethod fires at instantiation, NOT definition."""

        # Defining a class without visit_function should NOT raise
        class IncompleteRule(RuleBase):
            def rule_id(self) -> RuleId:
                return RuleId.PY_WL_004

        # Instantiating it SHOULD raise
        with pytest.raises(TypeError, match="visit_function"):
            IncompleteRule()  # type: ignore[abstract]

    def test_concrete_rule_instantiates(self) -> None:
        """A fully implemented rule can be instantiated."""
        rule = RulePyWl004()
        assert rule.rule_id() == RuleId.PY_WL_004

    def test_multi_level_inheritance_blocked(self) -> None:
        """__init_subclass__ prevents subclassing a concrete rule."""
        with pytest.raises(TypeError, match="must subclass RuleBase directly"):

            @final
            class SubRule(RulePyWl004):  # type: ignore[misc]
                pass

    def test_rule_registered_in_concrete_rules(self) -> None:
        """Concrete rules are tracked in RuleBase._concrete_rules."""
        assert RulePyWl004 in RuleBase._concrete_rules


# ── End-to-End ────────────────────────────────────────────────────


class TestEndToEnd:
    """Full tracer bullet runs without error."""

    def test_run_tracer_bullet(self) -> None:
        from spike.run_tracer import run_tracer_bullet

        results = run_tracer_bullet()
        assert results["findings_count"] == 3
        assert results["sarif_valid"] is True
        assert results["registry_lookup_ok"] is True
        assert results["factory_assertion_ok"] is True
