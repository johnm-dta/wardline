"""SARIF 2.1.0 output emitter — tracer bullet version.

Produces a minimal valid SARIF log from a list of Findings, with wardline
property bags for taint state and exceptionability metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jsonschema

from wardline.core.matrix import lookup
from wardline.core.severity import Severity

if TYPE_CHECKING:
    from spike.rule_base import Finding

_SARIF_SCHEMA_PATH = Path(__file__).parent / "sarif-schema-2.1.0.json"

# Map wardline severity to SARIF level
_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.SUPPRESS: "note",
}


def findings_to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Convert a list of findings to a SARIF 2.1.0 log object."""
    results: list[dict[str, Any]] = []

    for f in findings:
        cell = lookup(f.rule_id, f.taint)
        sarif_level = _SEVERITY_TO_SARIF_LEVEL[cell.severity]

        result: dict[str, Any] = {
            "ruleId": f.rule_id.value,
            "level": sarif_level,
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.col + 1,  # SARIF is 1-based
                        },
                    }
                }
            ],
            "properties": {
                "wardline": {
                    "taintState": f.taint.value,
                    "severity": cell.severity.value,
                    "exceptionability": cell.exceptionability.value,
                }
            },
        }
        results.append(result)

    # Collect unique rule IDs for the tool driver rules array
    seen_rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule_id.value not in seen_rules:
            seen_rules[f.rule_id.value] = {
                "id": f.rule_id.value,
                "shortDescription": {"text": f"Wardline rule {f.rule_id.value}"},
            }

    sarif_log: dict[str, Any] = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wardline",
                        "version": "0.1.0-spike",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif_log


def validate_sarif(sarif_log: dict[str, Any]) -> None:
    """Validate a SARIF log against the vendored 2.1.0 schema.

    Raises jsonschema.ValidationError if invalid.
    """
    schema = json.loads(_SARIF_SCHEMA_PATH.read_text())
    jsonschema.validate(instance=sarif_log, schema=schema)
