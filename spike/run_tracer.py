"""End-to-end tracer bullet runner.

Parses the fixture file, runs PY-WL-004, emits SARIF, validates it,
and exercises registry lookup — all in one pass.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import TYPE_CHECKING

from spike.registry_validation import (
    validate_factory_assertion,
    validate_registry_lookup,
)
from spike.rule_py_wl_004 import RulePyWl004

if TYPE_CHECKING:
    from spike.rule_base import Finding
from spike.sarif_emitter import findings_to_sarif, validate_sarif

FIXTURE_PATH = Path(__file__).parent / "fixture_broad_except.py"


def run_tracer_bullet() -> dict[str, object]:
    """Run the full tracer bullet and return summary results."""
    source = FIXTURE_PATH.read_text()
    tree = ast.parse(source, filename=str(FIXTURE_PATH))

    # --- Validation Point 1: AST parsing + rule detection ---
    rule = RulePyWl004()
    all_findings: list[Finding] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            findings = rule.visit_function(node, str(FIXTURE_PATH))
            all_findings.extend(findings)

    # --- Validation Point 2: SARIF output + schema validation ---
    sarif_log = findings_to_sarif(all_findings)
    validate_sarif(sarif_log)  # Raises on failure

    # --- Validation Point 3: Registry lookup + factory assertion ---
    entry = validate_registry_lookup("external_boundary")
    validate_factory_assertion(
        "external_boundary",
        {"_wardline_tier_source": "some_value"},
    )

    return {
        "findings_count": len(all_findings),
        "sarif_valid": True,
        "registry_lookup_ok": entry.canonical_name == "external_boundary",
        "factory_assertion_ok": True,
        "sarif_json": json.dumps(sarif_log, indent=2),
    }


if __name__ == "__main__":
    results = run_tracer_bullet()
    print(f"Findings: {results['findings_count']}")
    print(f"SARIF valid: {results['sarif_valid']}")
    print(f"Registry lookup: {results['registry_lookup_ok']}")
    print(f"Factory assertion: {results['factory_assertion_ok']}")
    print("---")
    print(results["sarif_json"])
