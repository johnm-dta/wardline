"""SARIF v2.1.0 output for wardline scan results.

Converts Finding dataclasses into SARIF-compliant JSON for
integration with code-analysis dashboards and CI pipelines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core.severity import RuleId, Severity

if TYPE_CHECKING:
    from wardline.scanner.context import Finding

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.SUPPRESS: "note",
}

# Short descriptions for each canonical rule ID.
_RULE_SHORT_DESCRIPTIONS: dict[RuleId, str] = {
    RuleId.PY_WL_001: "Dict key access with fallback default",
    RuleId.PY_WL_002: "Attribute access with fallback default",
    RuleId.PY_WL_003: "Existence-checking as structural gate",
    RuleId.PY_WL_004: "Broad exception handler",
    RuleId.PY_WL_005: "Silent exception handler",
    RuleId.PY_WL_006: "Audit-critical write in broad exception handler",
    RuleId.PY_WL_007: "Runtime type-checking on internal data",
    RuleId.PY_WL_008: "Validation boundary with no rejection path",
    RuleId.PY_WL_009: "Semantic validation without prior shape validation",
    RuleId.SCN_021: "Contradictory or suspicious wardline decorator combination",
    RuleId.SUP_001: "Supplementary decorator contract violation",
    RuleId.PY_WL_001_GOVERNED_DEFAULT: "Governed default value (diagnostic)",
    RuleId.PY_WL_001_UNGOVERNED_DEFAULT: "Ungoverned schema_default() — no overlay boundary (diagnostic)",
    RuleId.WARDLINE_UNRESOLVED_DECORATOR: "Unresolved decorator (diagnostic)",
    RuleId.TOOL_ERROR: "Internal tool error",
    RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED: (
        "Registry mismatch allowed (diagnostic)"
    ),
    RuleId.GOVERNANCE_RULE_DISABLED: "Rule disabled by configuration (governance)",
    RuleId.GOVERNANCE_PERMISSIVE_DISTRIBUTION: (
        "Permissive distribution allowed (governance)"
    ),
    RuleId.GOVERNANCE_STALE_EXCEPTION: "Stale exception — AST fingerprint mismatch (governance)",
    RuleId.GOVERNANCE_UNKNOWN_PROVENANCE: "Unknown agent provenance on exception (governance)",
    RuleId.GOVERNANCE_RECURRING_EXCEPTION: "Recurring exception — multiple renewals (governance)",
    RuleId.GOVERNANCE_BATCH_REFRESH: "Batch exception refresh performed (governance)",
    RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION: "Exception has no expiry date (governance)",
    RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT: "Exception taint state no longer matches function's effective taint",
    RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE: "Exception granted at lower analysis level than active scan",
    RuleId.GOVERNANCE_EXCEPTION_SEVERITY_DRIFT: "Exception severity_at_grant differs from current finding severity",
    RuleId.L3_LOW_RESOLUTION: "L3 call-graph taint based on minority of call edges (>70% unresolved)",
    RuleId.L3_CONVERGENCE_BOUND: "L3 propagation hit iteration safety bound — results may be incomplete",
}

# Pseudo-rule-IDs that should NOT appear in implementedRules.
_PSEUDO_RULE_IDS: frozenset[RuleId] = frozenset(
    {
        RuleId.PY_WL_001_GOVERNED_DEFAULT,
        RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
        RuleId.WARDLINE_UNRESOLVED_DECORATOR,
        RuleId.TOOL_ERROR,
        RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED,
        RuleId.GOVERNANCE_RULE_DISABLED,
        RuleId.GOVERNANCE_PERMISSIVE_DISTRIBUTION,
        RuleId.GOVERNANCE_STALE_EXCEPTION,
        RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
        RuleId.GOVERNANCE_RECURRING_EXCEPTION,
        RuleId.GOVERNANCE_BATCH_REFRESH,
        RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
        RuleId.GOVERNANCE_EXCEPTION_TAINT_DRIFT,
        RuleId.GOVERNANCE_EXCEPTION_LEVEL_STALE,
        RuleId.GOVERNANCE_EXCEPTION_SEVERITY_DRIFT,
        RuleId.L3_LOW_RESOLUTION,
        RuleId.L3_CONVERGENCE_BOUND,
    }
)


def _severity_rank(severity: Severity) -> int:
    """Return a numeric rank for severity (higher = worse)."""
    return {Severity.SUPPRESS: 0, Severity.WARNING: 1, Severity.ERROR: 2}.get(
        severity, -1
    )


def _clean_none(d: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *d* with all ``None``-valued keys removed."""
    return {k: v for k, v in d.items() if v is not None}


def _make_region(finding: Finding) -> dict[str, Any]:
    """Build a SARIF region dict, omitting None fields."""
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.col + 1,  # SARIF uses 1-based columns
    }
    if finding.end_line is not None:
        region["endLine"] = finding.end_line
    if finding.end_col is not None:
        region["endColumn"] = finding.end_col + 1
    return region


def _make_result(finding: Finding) -> dict[str, Any]:
    """Convert a single Finding to a SARIF result entry."""
    properties = _clean_none(
        {
            "wardline.rule": str(finding.rule_id),
            # Defensive fallback: canonical rules always carry taint, but
            # keeping the property present avoids fragile downstream handling.
            "wardline.taintState": (
                str(finding.taint_state)
                if finding.taint_state is not None
                else "UNKNOWN_RAW"
            ),
            "wardline.severity": str(finding.severity),
            "wardline.exceptionability": str(finding.exceptionability),
            "wardline.analysisLevel": finding.analysis_level,
            "wardline.qualname": finding.qualname,
            "wardline.sourceSnippet": finding.source_snippet,
        }
    )
    if finding.exception_id is not None:
        properties["wardline.exceptionId"] = finding.exception_id
    if finding.exception_expires is not None:
        properties["wardline.exceptionExpires"] = finding.exception_expires
    return {
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "note"),
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": _make_region(finding),
                },
            }
        ],
        "message": {"text": finding.message},
        "properties": properties,
        "ruleId": str(finding.rule_id),
    }


def _make_rule_descriptor(rule_id: RuleId, severity: Severity) -> dict[str, Any]:
    """Build a SARIF rule descriptor for a given rule ID."""
    return {
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
        },
        "id": str(rule_id),
        "shortDescription": {
            "text": _RULE_SHORT_DESCRIPTIONS.get(
                rule_id, f"Wardline rule {rule_id}"
            ),
        },
    }


@dataclass
class SarifReport:
    """Holds scan results and produces SARIF v2.1.0 output."""

    findings: list[Finding] = field(default_factory=list)
    tool_version: str = "0.1.0"
    verification_mode: bool = False
    implemented_rule_ids: frozenset[RuleId] | None = None
    unknown_raw_count: int = 0
    unresolved_decorator_count: int = 0
    active_exception_count: int = 0
    stale_exception_count: int = 0
    expedited_exception_ratio: float = 0.0
    # WP 2.4: Governance metadata
    control_law: str = "normal"
    analysis_level: int = 1
    manifest_hash: str | None = None
    scan_timestamp: str | None = None
    commit_ref: str | None = None

    def _implemented_rules(self) -> list[str]:
        """Return sorted list of canonical rule ID values (excludes pseudo-IDs).

        If ``implemented_rule_ids`` is set, uses that (from loaded rules).
        Otherwise falls back to all canonical RuleId members.
        """
        if self.implemented_rule_ids is not None:
            return sorted(
                r.value for r in self.implemented_rule_ids
                if r not in _PSEUDO_RULE_IDS
            )
        return sorted(
            r.value for r in RuleId if r not in _PSEUDO_RULE_IDS
        )

    def _collect_rule_descriptors(self) -> list[dict[str, Any]]:
        """Build deduplicated, sorted rule descriptors from findings."""
        # Map rule_id -> worst severity seen for that rule.
        rule_severity: dict[RuleId, Severity] = {}
        for f in self.findings:
            existing = rule_severity.get(f.rule_id)
            if existing is None or _severity_rank(f.severity) > _severity_rank(existing):
                rule_severity[f.rule_id] = f.severity
        # Sort by rule ID string for determinism.
        return [
            _make_rule_descriptor(rid, sev)
            for rid, sev in sorted(rule_severity.items(), key=lambda x: str(x[0]))
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a SARIF v2.1.0 compliant dict."""
        # Sort findings for deterministic output.
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (f.file_path, f.line, f.col, str(f.rule_id)),
        )

        results = [_make_result(f) for f in sorted_findings]
        rules = self._collect_rule_descriptors()

        run: dict[str, Any] = {
            "properties": {
                "wardline.analysisLevel": self.analysis_level,
                **({"wardline.commitRef": self.commit_ref}
                   if not self.verification_mode and self.commit_ref
                   else {}),
                "wardline.conformanceGaps": [],
                "wardline.controlLaw": self.control_law,
                "wardline.implementedRules": self._implemented_rules(),
                **({"wardline.manifestHash": self.manifest_hash}
                   if self.manifest_hash is not None
                   else {}),
                "wardline.propertyBagVersion": "0.2",
                **({"wardline.scanTimestamp": self.scan_timestamp}
                   if not self.verification_mode and self.scan_timestamp
                   else {}),
                "wardline.suppressedFindingCount": sum(
                    1 for f in self.findings if f.exception_id is not None
                ),
                "wardline.unknownRawFunctionCount": self.unknown_raw_count,
                "wardline.unresolvedDecoratorCount": self.unresolved_decorator_count,
                "wardline.activeExceptionCount": self.active_exception_count,
                "wardline.staleExceptionCount": self.stale_exception_count,
                "wardline.expeditedExceptionRatio": round(self.expedited_exception_ratio, 3),
            },
            "results": results,
            "tool": {
                "driver": {
                    "informationUri": "https://wardline.dev",
                    "name": "wardline",
                    "rules": rules,
                    "version": self.tool_version,
                },
            },
        }

        return {
            "$schema": _SARIF_SCHEMA,
            "runs": [run],
            "version": "2.1.0",
        }

    def to_json_string(self) -> str:
        """Return the SARIF report as a JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_json(self, path: str | Path) -> None:
        """Write the SARIF report to a JSON file."""
        Path(path).write_text(self.to_json_string(), encoding="utf-8")
