"""Tests for manifest coherence checks."""

from __future__ import annotations

import datetime
import json
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.manifest.coherence import (
    check_agent_originated_exceptions,
    check_expired_exceptions,
    check_first_scan_perimeter,
    check_orphaned_annotations,
    check_stale_contract_bindings,
    check_tier_distribution,
    check_tier_downgrades,
    check_tier_topology_consistency,
    check_tier_upgrade_without_evidence,
    check_undeclared_boundaries,
    check_unmatched_contracts,
)
from wardline.manifest.models import (
    BoundaryEntry,
    ContractBinding,
    ExceptionEntry,
    ModuleTierEntry,
    TierEntry,
)
from wardline.scanner.context import WardlineAnnotation

if TYPE_CHECKING:
    from pathlib import Path


def _annot(name: str, group: int = 1) -> WardlineAnnotation:
    """Helper to create a WardlineAnnotation with minimal boilerplate."""
    return WardlineAnnotation(
        canonical_name=name,
        group=group,
        attrs=MappingProxyType({}),
    )


def _tier(tid: str, tier: int) -> TierEntry:
    """Helper to create a TierEntry."""
    return TierEntry(id=tid, tier=tier)


def _module_tier(path: str, default_taint: str) -> ModuleTierEntry:
    """Helper to create a ModuleTierEntry."""
    return ModuleTierEntry(path=path, default_taint=default_taint)


def _exception(
    *,
    exc_id: str = "EXC-001",
    agent_originated: bool | None = None,
    expires: str | None = None,
    location: str = "src/foo.py",
) -> ExceptionEntry:
    """Helper to create an ExceptionEntry with minimal boilerplate."""
    return ExceptionEntry(
        id=exc_id,
        rule="PY-WL-001",
        taint_state="UNTRUSTED",
        location=location,
        exceptionability="STANDARD",
        severity_at_grant="WARNING",
        rationale="test",
        reviewer="test-reviewer",
        expires=expires,
        agent_originated=agent_originated,
    )


# ── Orphaned annotation tests ──────────────────────────────────────


class TestOrphanedAnnotations:
    """Tests for check_orphaned_annotations."""

    def test_no_orphans_when_all_declared(self) -> None:
        """All annotated functions have matching boundary declarations."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
            ("src/validate.py", "validate_input"): [_annot("validates_shape")],
        }
        boundaries = (
            BoundaryEntry(function="handle_request", transition="INGRESS"),
            BoundaryEntry(function="validate_input", transition="SHAPE_VALIDATE"),
        )
        issues = check_orphaned_annotations(annotations, boundaries)
        assert issues == []

    def test_orphan_detected(self) -> None:
        """Annotated function with no boundary declaration is flagged."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
        }
        boundaries: tuple[BoundaryEntry, ...] = ()
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].kind == "orphaned_annotation"
        assert issues[0].function == "handle_request"
        assert issues[0].file_path == "src/api.py"
        assert "external_boundary" in issues[0].detail

    def test_multiple_orphans(self) -> None:
        """Multiple orphaned annotations are all reported."""
        annotations = {
            ("src/a.py", "func_a"): [_annot("external_boundary")],
            ("src/b.py", "func_b"): [_annot("validates_shape")],
            ("src/c.py", "func_c"): [_annot("tier1_read")],
        }
        boundaries = (
            BoundaryEntry(function="func_b", transition="SHAPE_VALIDATE"),
        )
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 2
        orphan_names = {i.function for i in issues}
        assert orphan_names == {"func_a", "func_c"}

    def test_multiple_decorators_on_orphan(self) -> None:
        """All decorator names appear in the detail message."""
        annotations = {
            ("src/api.py", "handler"): [
                _annot("external_boundary"),
                _annot("validates_shape"),
            ],
        }
        boundaries: tuple[BoundaryEntry, ...] = ()
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 1
        assert "external_boundary" in issues[0].detail
        assert "validates_shape" in issues[0].detail

    def test_empty_inputs(self) -> None:
        """No annotations and no boundaries produces no issues."""
        issues = check_orphaned_annotations({}, ())
        assert issues == []

    def test_partial_match(self) -> None:
        """Only the unmatched annotation is flagged."""
        annotations = {
            ("src/a.py", "declared_fn"): [_annot("external_boundary")],
            ("src/b.py", "orphan_fn"): [_annot("validates_shape")],
        }
        boundaries = (
            BoundaryEntry(function="declared_fn", transition="INGRESS"),
        )
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].function == "orphan_fn"


# ── Undeclared boundary tests ──────────────────────────────────────


class TestUndeclaredBoundaries:
    """Tests for check_undeclared_boundaries."""

    def test_no_undeclared_when_all_have_code(self) -> None:
        """All boundary functions have matching annotations in code."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(function="handle_request", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert issues == []

    def test_undeclared_detected(self) -> None:
        """Boundary with no matching annotation is flagged."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        boundaries = (
            BoundaryEntry(function="ghost_function", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].kind == "undeclared_boundary"
        assert issues[0].function == "ghost_function"
        assert "ghost_function" in issues[0].detail
        assert "INGRESS" in issues[0].detail

    def test_multiple_undeclared(self) -> None:
        """Multiple undeclared boundaries are all reported."""
        annotations = {
            ("src/api.py", "real_fn"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(function="real_fn", transition="INGRESS"),
            BoundaryEntry(function="phantom_a", transition="SHAPE_VALIDATE"),
            BoundaryEntry(function="phantom_b", transition="EGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert len(issues) == 2
        undeclared_names = {i.function for i in issues}
        assert undeclared_names == {"phantom_a", "phantom_b"}

    def test_empty_inputs(self) -> None:
        """No annotations and no boundaries produces no issues."""
        issues = check_undeclared_boundaries({}, ())
        assert issues == []

    def test_boundary_matches_any_file(self) -> None:
        """Boundary function matches annotation regardless of file path."""
        annotations = {
            ("src/deep/nested/module.py", "handler"): [
                _annot("external_boundary")
            ],
        }
        boundaries = (
            BoundaryEntry(function="handler", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert issues == []

    def test_qualname_match(self) -> None:
        """Boundary function with class-qualified name matches annotation."""
        annotations = {
            ("src/api.py", "MyClass.handle"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(function="MyClass.handle", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert issues == []


# ── Tier distribution tests ───────────────────────────────────────


class TestTierDistribution:
    """Tests for check_tier_distribution."""

    def test_threshold_boundary_fires_at_61_percent(self) -> None:
        """61% permissive tiers exceeds default 60% threshold."""
        tiers = (
            _tier("strict", 1),
            _tier("moderate", 2),
            _tier("permissive", 3),
            _tier("open", 4),
        )
        # 61 permissive out of 100 total
        module_tiers = tuple(
            _module_tier(f"mod_{i}", "permissive") for i in range(61)
        ) + tuple(
            _module_tier(f"safe_{i}", "strict") for i in range(39)
        )
        issues = check_tier_distribution(tiers, module_tiers)
        assert len(issues) == 1
        assert issues[0].kind == "tier_distribution"

    def test_threshold_boundary_does_not_fire_at_60_percent(self) -> None:
        """Exactly 60% permissive tiers does not exceed threshold."""
        tiers = (
            _tier("strict", 1),
            _tier("permissive", 3),
        )
        # 60 permissive out of 100 total
        module_tiers = tuple(
            _module_tier(f"mod_{i}", "permissive") for i in range(60)
        ) + tuple(
            _module_tier(f"safe_{i}", "strict") for i in range(40)
        )
        issues = check_tier_distribution(tiers, module_tiers)
        assert issues == []

    def test_custom_threshold(self) -> None:
        """Custom threshold is respected."""
        tiers = (_tier("strict", 1), _tier("permissive", 3))
        module_tiers = (
            _module_tier("a", "permissive"),
            _module_tier("b", "strict"),
        )
        # 50% permissive — fires with 40% threshold
        issues = check_tier_distribution(
            tiers, module_tiers, max_permissive_percent=40.0
        )
        assert len(issues) == 1

    def test_empty_inputs(self) -> None:
        """Empty inputs produce no issues."""
        assert check_tier_distribution((), ()) == []

    def test_tier_4_counted_as_permissive(self) -> None:
        """Tier 4 modules are counted as permissive."""
        tiers = (_tier("strict", 1), _tier("open", 4))
        module_tiers = (
            _module_tier("a", "open"),
            _module_tier("b", "open"),
            _module_tier("c", "strict"),
        )
        # 66.7% > 60%
        issues = check_tier_distribution(tiers, module_tiers)
        assert len(issues) == 1


# ── Tier downgrade tests ──────────────────────────────────────────


class TestTierDowngrades:
    """Tests for check_tier_downgrades."""

    def test_downgrade_detected(self, tmp_path: Path) -> None:
        """Module moving from tier 1 to tier 3 is flagged."""
        baseline = {
            "tiers": [{"id": "strict", "tier": 1}, {"id": "permissive", "tier": 3}],
            "module_tiers": [{"path": "src/core", "default_taint": "strict"}],
        }
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (_tier("strict", 1), _tier("permissive", 3))
        module_tiers = (_module_tier("src/core", "permissive"),)

        issues = check_tier_downgrades(tiers, module_tiers, baseline_path)
        assert len(issues) == 1
        assert issues[0].kind == "tier_downgrade"
        assert "src/core" in issues[0].detail
        assert "tier 1" in issues[0].detail
        assert "tier 3" in issues[0].detail

    def test_no_downgrade_when_unchanged(self, tmp_path: Path) -> None:
        """No warning when tier remains the same."""
        baseline = {
            "tiers": [{"id": "strict", "tier": 1}],
            "module_tiers": [{"path": "src/core", "default_taint": "strict"}],
        }
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (_tier("strict", 1),)
        module_tiers = (_module_tier("src/core", "strict"),)

        issues = check_tier_downgrades(tiers, module_tiers, baseline_path)
        assert issues == []

    def test_no_baseline_file(self, tmp_path: Path) -> None:
        """No issues when baseline file does not exist."""
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        tiers = (_tier("strict", 1),)
        module_tiers = (_module_tier("src/core", "strict"),)
        issues = check_tier_downgrades(tiers, module_tiers, baseline_path)
        assert issues == []

    def test_added_module_not_flagged(self, tmp_path: Path) -> None:
        """New module not in baseline is not flagged as downgrade."""
        baseline = {
            "tiers": [{"id": "strict", "tier": 1}],
            "module_tiers": [],
        }
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (_tier("strict", 1), _tier("permissive", 3))
        module_tiers = (_module_tier("src/new_module", "permissive"),)

        issues = check_tier_downgrades(tiers, module_tiers, baseline_path)
        assert issues == []

    def test_removed_module_not_flagged(self, tmp_path: Path) -> None:
        """Module in baseline but not in current is not flagged."""
        baseline = {
            "tiers": [{"id": "strict", "tier": 1}],
            "module_tiers": [{"path": "src/old", "default_taint": "strict"}],
        }
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (_tier("strict", 1),)
        module_tiers: tuple[ModuleTierEntry, ...] = ()

        issues = check_tier_downgrades(tiers, module_tiers, baseline_path)
        assert issues == []


# ── Tier upgrade without evidence tests ───────────────────────────


class TestTierUpgradeWithoutEvidence:
    """Tests for check_tier_upgrade_without_evidence."""

    def test_upgrade_without_evidence_detected(self, tmp_path: Path) -> None:
        """Tier upgrade with no covering boundary fires warning."""
        baseline = {
            "tiers": [{"id": "strict", "tier": 1}, {"id": "permissive", "tier": 3}],
            "module_tiers": [{"path": "src/core", "default_taint": "permissive"}],
        }
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (_tier("strict", 1), _tier("permissive", 3))
        module_tiers = (_module_tier("src/core", "strict"),)
        boundaries: tuple[BoundaryEntry, ...] = ()

        issues = check_tier_upgrade_without_evidence(
            tiers, module_tiers, boundaries, baseline_path
        )
        assert len(issues) == 1
        assert issues[0].kind == "tier_upgrade_without_evidence"
        assert "without evidence" in issues[0].detail

    def test_upgrade_with_evidence_no_warning(self, tmp_path: Path) -> None:
        """Tier upgrade with a covering boundary does not fire."""
        baseline = {
            "tiers": [{"id": "strict", "tier": 1}, {"id": "permissive", "tier": 3}],
            "module_tiers": [{"path": "src/core", "default_taint": "permissive"}],
        }
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        baseline_path.write_text(json.dumps(baseline))

        tiers = (_tier("strict", 1), _tier("permissive", 3))
        module_tiers = (_module_tier("src/core", "strict"),)
        # Boundary overlay_scope covers the module path
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                overlay_scope="/project/src/core",
            ),
        )

        issues = check_tier_upgrade_without_evidence(
            tiers, module_tiers, boundaries, baseline_path
        )
        assert issues == []

    def test_no_baseline_file(self, tmp_path: Path) -> None:
        """No issues when baseline file does not exist."""
        baseline_path = tmp_path / "wardline.manifest.baseline.json"
        issues = check_tier_upgrade_without_evidence(
            (), (), (), baseline_path
        )
        assert issues == []


# ── Agent-originated exception tests ──────────────────────────────


class TestAgentOriginatedException:
    """Tests for check_agent_originated_exceptions."""

    def test_null_agent_originated_fires_warning(self) -> None:
        """Exception with agent_originated=None fires WARNING."""
        exceptions = (
            _exception(exc_id="EXC-TRUE", agent_originated=True),
            _exception(exc_id="EXC-FALSE", agent_originated=False),
            _exception(exc_id="EXC-NULL", agent_originated=None),
        )
        issues = check_agent_originated_exceptions(exceptions)
        assert len(issues) == 1
        assert issues[0].kind == "agent_originated_exception"
        assert "EXC-NULL" in issues[0].detail

    def test_explicit_true_no_warning(self) -> None:
        """Exception with agent_originated=True does not fire."""
        exceptions = (_exception(agent_originated=True),)
        issues = check_agent_originated_exceptions(exceptions)
        assert issues == []

    def test_explicit_false_no_warning(self) -> None:
        """Exception with agent_originated=False does not fire."""
        exceptions = (_exception(agent_originated=False),)
        issues = check_agent_originated_exceptions(exceptions)
        assert issues == []

    def test_empty_exceptions(self) -> None:
        """No exceptions produce no issues."""
        issues = check_agent_originated_exceptions(())
        assert issues == []


# ── Expired exception tests ───────────────────────────────────────


class TestExpiredExceptions:
    """Tests for check_expired_exceptions."""

    def test_expired_exception_fires_warning(self) -> None:
        """Exception past max_exception_duration_days fires WARNING."""
        now = datetime.date(2026, 3, 23)
        exceptions = (
            _exception(expires="2026-03-22"),  # expired yesterday
        )
        issues = check_expired_exceptions(exceptions, now=now)
        assert len(issues) == 1
        assert issues[0].kind == "expired_exception"
        assert "expired" in issues[0].detail.lower()

    def test_far_future_expiry_rejected(self) -> None:
        """Far-future expiry exceeding max_exception_duration_days fires."""
        now = datetime.date(2026, 3, 23)
        exceptions = (
            _exception(expires="2099-12-31"),
        )
        issues = check_expired_exceptions(
            exceptions, max_exception_duration_days=365, now=now
        )
        assert len(issues) == 1
        assert issues[0].kind == "expired_exception"
        assert "far-future" in issues[0].detail.lower()

    def test_valid_exception_no_warning(self) -> None:
        """Exception within allowed duration does not fire."""
        now = datetime.date(2026, 3, 23)
        exceptions = (
            _exception(expires="2026-09-23"),  # ~6 months, within 365 days
        )
        issues = check_expired_exceptions(
            exceptions, max_exception_duration_days=365, now=now
        )
        assert issues == []

    def test_no_expiry_no_warning(self) -> None:
        """Exception with no expiry date does not fire."""
        exceptions = (_exception(expires=None),)
        issues = check_expired_exceptions(exceptions, now=datetime.date(2026, 3, 23))
        assert issues == []

    def test_clock_injection(self) -> None:
        """Clock injection via now parameter controls date comparison."""
        exceptions = (_exception(expires="2026-06-01"),)
        # Before expiry — no warning
        issues_before = check_expired_exceptions(
            exceptions, now=datetime.date(2026, 5, 1)
        )
        assert issues_before == []
        # After expiry — fires
        issues_after = check_expired_exceptions(
            exceptions, now=datetime.date(2026, 7, 1)
        )
        assert len(issues_after) == 1

    def test_custom_max_duration(self) -> None:
        """Custom max_exception_duration_days is respected."""
        now = datetime.date(2026, 3, 23)
        # 100 days from now = 2026-07-01
        exceptions = (_exception(expires="2026-08-01"),)
        issues = check_expired_exceptions(
            exceptions, max_exception_duration_days=100, now=now
        )
        assert len(issues) == 1
        assert "far-future" in issues[0].detail.lower()


# ── First-scan perimeter tests ────────────────────────────────────


class TestFirstScanPerimeter:
    """Tests for check_first_scan_perimeter."""

    def test_no_baseline_fires_info(self, tmp_path: Path) -> None:
        """Missing perimeter baseline fires first_scan_perimeter."""
        perimeter_path = tmp_path / "wardline.perimeter.baseline.json"
        issues = check_first_scan_perimeter(perimeter_path)
        assert len(issues) == 1
        assert issues[0].kind == "first_scan_perimeter"
        assert "first scan" in issues[0].detail.lower()

    def test_existing_baseline_no_issue(self, tmp_path: Path) -> None:
        """Existing perimeter baseline produces no issues."""
        perimeter_path = tmp_path / "wardline.perimeter.baseline.json"
        perimeter_path.write_text("{}")
        issues = check_first_scan_perimeter(perimeter_path)
        assert issues == []


# ── Unmatched contract tests ─────────────────────────────────────


class TestUnmatchedContracts:
    """Tests for check_unmatched_contracts."""

    def test_matched_contract_no_issue(self) -> None:
        """Boundary with bounded_context contracts and matching annotation is clean."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(
                function="handle_request",
                transition="INGRESS",
                bounded_context={
                    "contracts": [
                        {"name": "UserInput", "data_tier": 3, "direction": "inbound"},
                    ]
                },
            ),
        )
        issues = check_unmatched_contracts(annotations, boundaries)
        assert issues == []

    def test_unmatched_contract_detected(self) -> None:
        """Boundary with contracts but no code annotation is flagged."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        boundaries = (
            BoundaryEntry(
                function="ghost_handler",
                transition="INGRESS",
                bounded_context={
                    "contracts": [
                        {"name": "RawPayload", "data_tier": 4, "direction": "inbound"},
                    ]
                },
                overlay_path="overlays/api/wardline.overlay.yaml",
            ),
        )
        issues = check_unmatched_contracts(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].kind == "unmatched_contract"
        assert issues[0].function == "ghost_handler"
        assert "RawPayload" in issues[0].detail

    def test_boundary_without_bounded_context_ignored(self) -> None:
        """Boundaries without bounded_context are silently skipped."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        boundaries = (
            BoundaryEntry(function="handler", transition="INGRESS"),
        )
        issues = check_unmatched_contracts(annotations, boundaries)
        assert issues == []

    def test_empty_contracts_list_ignored(self) -> None:
        """Boundary with empty contracts list is silently skipped."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                bounded_context={"contracts": []},
            ),
        )
        issues = check_unmatched_contracts(annotations, boundaries)
        assert issues == []

    def test_multiple_contracts_reported_together(self) -> None:
        """All contract names appear in the detail message."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                bounded_context={
                    "contracts": [
                        {"name": "ContractA", "data_tier": 2, "direction": "inbound"},
                        {"name": "ContractB", "data_tier": 3, "direction": "outbound"},
                    ]
                },
            ),
        )
        issues = check_unmatched_contracts(annotations, boundaries)
        assert len(issues) == 1
        assert "ContractA" in issues[0].detail
        assert "ContractB" in issues[0].detail

    def test_empty_inputs(self) -> None:
        """No annotations and no boundaries produces no issues."""
        issues = check_unmatched_contracts({}, ())
        assert issues == []


# ── Stale contract binding tests ─────────────────────────────────


class TestStaleContractBindings:
    """Tests for check_stale_contract_bindings."""

    def test_valid_binding_no_issue(self) -> None:
        """All bound functions exist in annotations."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
            ("src/validate.py", "validate_input"): [_annot("validates_shape")],
        }
        bindings = (
            ContractBinding(
                contract="UserInput",
                functions=("handle_request", "validate_input"),
            ),
        )
        issues = check_stale_contract_bindings(annotations, bindings)
        assert issues == []

    def test_stale_binding_detected(self) -> None:
        """Binding referencing non-existent function is flagged."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
        }
        bindings = (
            ContractBinding(
                contract="UserInput",
                functions=("handle_request", "deleted_function"),
            ),
        )
        issues = check_stale_contract_bindings(annotations, bindings)
        assert len(issues) == 1
        assert issues[0].kind == "stale_contract_binding"
        assert issues[0].function == "deleted_function"
        assert "UserInput" in issues[0].detail

    def test_multiple_stale_bindings(self) -> None:
        """Multiple stale functions across bindings are all reported."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        bindings = (
            ContractBinding(
                contract="ContractA",
                functions=("missing_a",),
            ),
            ContractBinding(
                contract="ContractB",
                functions=("missing_b",),
            ),
        )
        issues = check_stale_contract_bindings(annotations, bindings)
        assert len(issues) == 2
        stale_names = {i.function for i in issues}
        assert stale_names == {"missing_a", "missing_b"}

    def test_empty_inputs(self) -> None:
        """No annotations and no bindings produces no issues."""
        issues = check_stale_contract_bindings({}, ())
        assert issues == []

    def test_empty_functions_list(self) -> None:
        """Binding with empty functions list produces no issues."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        bindings = (
            ContractBinding(contract="EmptyContract", functions=()),
        )
        issues = check_stale_contract_bindings(annotations, bindings)
        assert issues == []


# ── Tier topology consistency tests ──────────────────────────────


class TestTierTopologyConsistency:
    """Tests for check_tier_topology_consistency."""

    def test_valid_topology_no_issue(self) -> None:
        """Boundary with valid from_tier and to_tier produces no issues."""
        tiers = (_tier("strict", 1), _tier("moderate", 2), _tier("permissive", 3))
        module_tiers = (_module_tier("src/api", "permissive"),)
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                from_tier=3,
                to_tier=1,
                overlay_scope="/project/src/api",
            ),
        )
        issues = check_tier_topology_consistency(boundaries, tiers, module_tiers)
        assert issues == []

    def test_invalid_from_tier_detected(self) -> None:
        """Boundary referencing non-existent from_tier is flagged."""
        tiers = (_tier("strict", 1), _tier("moderate", 2))
        module_tiers: tuple[ModuleTierEntry, ...] = ()
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                from_tier=5,
                overlay_path="overlays/api/wardline.overlay.yaml",
            ),
        )
        issues = check_tier_topology_consistency(boundaries, tiers, module_tiers)
        assert len(issues) == 1
        assert issues[0].kind == "tier_topology_inconsistency"
        assert "from_tier=5" in issues[0].detail
        assert "not a valid tier" in issues[0].detail

    def test_invalid_to_tier_detected(self) -> None:
        """Boundary referencing non-existent to_tier is flagged."""
        tiers = (_tier("strict", 1), _tier("moderate", 2))
        module_tiers: tuple[ModuleTierEntry, ...] = ()
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                to_tier=99,
                overlay_path="overlays/api/wardline.overlay.yaml",
            ),
        )
        issues = check_tier_topology_consistency(boundaries, tiers, module_tiers)
        assert len(issues) == 1
        assert issues[0].kind == "tier_topology_inconsistency"
        assert "to_tier=99" in issues[0].detail

    def test_from_tier_module_mismatch_detected(self) -> None:
        """Boundary from_tier mismatching module tier is flagged."""
        tiers = (_tier("strict", 1), _tier("permissive", 3))
        module_tiers = (_module_tier("src/api", "permissive"),)  # tier 3
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                from_tier=1,  # claims tier 1 but module is tier 3
                overlay_scope="/project/src/api",
                overlay_path="overlays/api/wardline.overlay.yaml",
            ),
        )
        issues = check_tier_topology_consistency(boundaries, tiers, module_tiers)
        assert len(issues) == 1
        assert issues[0].kind == "tier_topology_inconsistency"
        assert "from_tier=1" in issues[0].detail
        assert "tier 3" in issues[0].detail

    def test_no_tiers_no_issues(self) -> None:
        """Empty tiers produces no issues."""
        boundaries = (
            BoundaryEntry(function="handler", transition="INGRESS", from_tier=1),
        )
        issues = check_tier_topology_consistency(boundaries, (), ())
        assert issues == []

    def test_boundary_without_tier_fields_ignored(self) -> None:
        """Boundaries without from_tier/to_tier are silently skipped."""
        tiers = (_tier("strict", 1),)
        module_tiers: tuple[ModuleTierEntry, ...] = ()
        boundaries = (
            BoundaryEntry(function="handler", transition="INGRESS"),
        )
        issues = check_tier_topology_consistency(boundaries, tiers, module_tiers)
        assert issues == []

    def test_empty_inputs(self) -> None:
        """No boundaries, tiers, or module_tiers produces no issues."""
        issues = check_tier_topology_consistency((), (), ())
        assert issues == []

    def test_both_tiers_invalid(self) -> None:
        """Both from_tier and to_tier invalid produces two issues."""
        tiers = (_tier("strict", 1),)
        module_tiers: tuple[ModuleTierEntry, ...] = ()
        boundaries = (
            BoundaryEntry(
                function="handler",
                transition="INGRESS",
                from_tier=7,
                to_tier=8,
            ),
        )
        issues = check_tier_topology_consistency(boundaries, tiers, module_tiers)
        assert len(issues) == 2
        kinds = {i.kind for i in issues}
        assert kinds == {"tier_topology_inconsistency"}
