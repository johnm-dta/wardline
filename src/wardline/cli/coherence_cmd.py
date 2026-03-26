"""wardline manifest coherence — cross-reference annotations against manifest.

Runs all 13 coherence checks, formats output (text or JSON), and
optionally gates on ERROR-level issues.
"""

from __future__ import annotations

import json as json_mod
import sys
from pathlib import Path
from typing import Any

import click

from wardline.cli._helpers import cli_error

from wardline.cli._helpers import COHERENCE_SEVERITY_MAP as SEVERITY_MAP
from wardline.cli.scan import EXIT_CONFIG_ERROR

CATEGORY_MAP = {
    "tier_downgrade": "policy",
    "tier_upgrade_without_evidence": "policy",
    "tier_topology_inconsistency": "policy",
    "orphaned_annotation": "enforcement",
    "undeclared_boundary": "enforcement",
    "unmatched_contract": "enforcement",
    "stale_contract_binding": "enforcement",
    "tier_distribution": "enforcement",
    "agent_originated_exception": "enforcement",
    "expired_exception": "enforcement",
    "first_scan_perimeter": "enforcement",
    "missing_validation_scope": "enforcement",
    "insufficient_restoration_evidence": "enforcement",
}


def _discover_all_annotations(
    scan_path: Path,
) -> dict[tuple[str, str], list[Any]]:
    """Walk .py files under *scan_path*, parse to AST, discover annotations."""
    from wardline.cli._helpers import discover_all_annotations

    return discover_all_annotations(scan_path)


@click.command("coherence")
@click.option(
    "--manifest",
    "manifest_file",
    type=click.Path(),
    required=True,
    help="Path to wardline.yaml manifest.",
)
@click.option(
    "--path",
    "scan_path",
    type=click.Path(exists=True),
    required=True,
    help="Root path to scan for Python files.",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output.")
@click.option(
    "--gate",
    is_flag=True,
    help="Exit 1 if any ERROR-level issues found.",
)
def coherence(
    manifest_file: str,
    scan_path: str,
    output_json: bool,
    gate: bool,
) -> None:
    """Run all coherence checks against manifest and code annotations."""
    import yaml

    from wardline.manifest.coherence import (
        CoherenceIssue,
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
        check_validation_scope_presence,
        check_restoration_evidence,
    )
    from wardline.manifest.exceptions import load_exceptions
    from wardline.manifest.loader import (
        ManifestLoadError,
        ManifestPolicyError,
        WardlineYAMLError,
        load_manifest,
    )
    from wardline.manifest.resolve import resolve_boundaries, resolve_contract_bindings

    # --- Load manifest ---
    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        cli_error(f"manifest not found: {manifest_file}")
        sys.exit(EXIT_CONFIG_ERROR)

    try:
        manifest_model = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError) as exc:
        cli_error(f"malformed manifest: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)

    # --- Discover annotations ---
    path_root = Path(scan_path).resolve()
    annotations = _discover_all_annotations(path_root)

    # --- Load supporting data ---
    manifest_dir = manifest_path.parent
    baseline_path = manifest_dir / "wardline.manifest.baseline.json"
    perimeter_baseline_path = manifest_dir / "wardline.perimeter.baseline.json"

    from wardline.manifest.discovery import GovernanceError

    try:
        boundaries = resolve_boundaries(manifest_dir, manifest_model)
    except ManifestPolicyError:
        raise
    except (GovernanceError, ManifestLoadError, OSError) as exc:
        click.echo(f"warning: boundary resolution failed: {exc}", err=True)
        boundaries = ()

    try:
        contract_bindings = resolve_contract_bindings(manifest_dir, manifest_model)
    except ManifestPolicyError:
        raise
    except (GovernanceError, ManifestLoadError, OSError) as exc:
        click.echo(f"warning: contract binding resolution failed: {exc}", err=True)
        contract_bindings = ()

    try:
        exceptions = load_exceptions(manifest_dir)
    except ManifestLoadError:
        exceptions = ()

    # --- Run all 13 checks ---
    all_issues: list[CoherenceIssue] = []

    all_issues.extend(
        check_orphaned_annotations(annotations, boundaries)
    )
    all_issues.extend(
        check_undeclared_boundaries(annotations, boundaries)
    )
    all_issues.extend(
        check_tier_distribution(
            manifest_model.tiers, manifest_model.module_tiers
        )
    )
    all_issues.extend(
        check_tier_downgrades(
            manifest_model.tiers, manifest_model.module_tiers, baseline_path
        )
    )
    all_issues.extend(
        check_tier_upgrade_without_evidence(
            manifest_model.tiers,
            manifest_model.module_tiers,
            boundaries,
            baseline_path,
        )
    )
    all_issues.extend(
        check_agent_originated_exceptions(exceptions)
    )
    all_issues.extend(
        check_expired_exceptions(exceptions)
    )
    all_issues.extend(
        check_first_scan_perimeter(perimeter_baseline_path)
    )
    all_issues.extend(
        check_unmatched_contracts(annotations, boundaries)
    )
    all_issues.extend(
        check_stale_contract_bindings(annotations, contract_bindings)
    )
    all_issues.extend(
        check_tier_topology_consistency(
            boundaries, manifest_model.tiers, manifest_model.module_tiers
        )
    )
    all_issues.extend(
        check_validation_scope_presence(boundaries)
    )
    all_issues.extend(
        check_restoration_evidence(boundaries)
    )

    # --- Format output ---
    if output_json:
        _format_json(all_issues)
    else:
        _format_text(all_issues)

    # --- Gate logic ---
    if gate:
        has_errors = any(
            SEVERITY_MAP.get(issue.kind) == "ERROR" for issue in all_issues
        )
        if has_errors:
            sys.exit(1)


def _format_text(issues: list[Any]) -> None:
    """Print human-readable text output."""
    if not issues:
        click.echo("0 issues found")
        return

    error_count = sum(
        1 for i in issues if SEVERITY_MAP.get(i.kind) == "ERROR"
    )
    warning_count = sum(
        1 for i in issues if SEVERITY_MAP.get(i.kind) == "WARNING"
    )

    for issue in issues:
        severity = SEVERITY_MAP.get(issue.kind, "WARNING")
        click.echo(f"[{severity}] {issue.kind}")
        if issue.file_path:
            click.echo(f"  file: {issue.file_path}")
        if issue.function:
            click.echo(f"  function: {issue.function}")
        click.echo(f"  {issue.detail}")

    click.echo(
        f"{len(issues)} issues found "
        f"({error_count} error(s), {warning_count} warning(s))"
    )


def _format_json(issues: list[Any]) -> None:
    """Print JSON output."""
    records = []
    for issue in issues:
        records.append({
            "check_name": issue.kind,
            "severity": SEVERITY_MAP.get(issue.kind, "WARNING"),
            "file_path": issue.file_path,
            "function": issue.function,
            "message": issue.detail,
            "category": CATEGORY_MAP.get(issue.kind, "enforcement"),
        })
    click.echo(json_mod.dumps(records, indent=2))
