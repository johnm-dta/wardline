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
    RuleId.PY_WL_001: "Dict key access should use fallback default",
    RuleId.PY_WL_002: "Missing shape validation on external input",
    RuleId.PY_WL_003: "Raw external data used without sanitisation",
    RuleId.PY_WL_004: "Unvalidated decorator argument",
    RuleId.PY_WL_005: "Unsafe type coercion on tainted data",
    RuleId.PY_WL_006: "Missing audit trail annotation",
    RuleId.PY_WL_007: "Pipeline stage ordering violation",
    RuleId.PY_WL_008: "Taint state escalation without validation",
    RuleId.PY_WL_009: "Governance registry mismatch",
    RuleId.PY_WL_001_GOVERNED_DEFAULT: "Governed default value (diagnostic)",
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
}

# Pseudo-rule-IDs that should NOT appear in implementedRules.
_PSEUDO_RULE_IDS: frozenset[RuleId] = frozenset(
    {
        RuleId.PY_WL_001_GOVERNED_DEFAULT,
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
    }
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
            "wardline.taintState": (
                str(finding.taint_state) if finding.taint_state else None
            ),
            "wardline.severity": str(finding.severity),
            "wardline.exceptionability": str(finding.exceptionability),
            "wardline.analysisLevel": finding.analysis_level,
        }
    )
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
            if existing is None or f.severity == Severity.ERROR:
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
                "wardline.conformanceGaps": [],
                "wardline.implementedRules": self._implemented_rules(),
                "wardline.propertyBagVersion": "1",
                "wardline.unknownRawFunctionCount": self.unknown_raw_count,
                "wardline.unresolvedDecoratorCount": self.unresolved_decorator_count,
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
