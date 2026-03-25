"""wardline manifest -- validate and baseline management commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from wardline.cli._helpers import cli_error


@click.group()
def manifest() -> None:
    """Manifest validation and baseline management."""


from wardline.cli.coherence_cmd import coherence  # noqa: E402

manifest.add_command(coherence)


@manifest.command()
@click.argument("file", required=False, type=click.Path())
def validate(file: str | None) -> None:
    """Validate a wardline.yaml manifest against the schema.

    Exit 0: valid, Exit 1: invalid, Exit 2: file not found.
    """
    import yaml

    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )

    manifest_path: Path | None = None

    if file is not None:
        manifest_path = Path(file)
        if not manifest_path.exists():
            cli_error(f"manifest not found: {file}")
            sys.exit(2)
    else:
        manifest_path = discover_manifest(Path.cwd())
        if manifest_path is None:
            click.echo(
                f"error: no wardline.yaml found (searched from {Path.cwd()})",
                err=True,
            )
            sys.exit(2)

    try:
        load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError) as exc:
        cli_error(f"manifest invalid: {exc}")
        sys.exit(1)

    click.echo(f"manifest valid: {manifest_path}")
    sys.exit(0)


@manifest.command("baseline")
@click.argument("action", type=click.Choice(["update"]))
@click.option("--approve", is_flag=True, help="Confirm baseline update.")
@click.option(
    "--manifest",
    "manifest_file",
    type=click.Path(),
    default=None,
    help="Path to wardline.yaml.",
)
def baseline(action: str, approve: bool, manifest_file: str | None) -> None:
    """Manage manifest baselines.

    Usage: wardline manifest baseline update --approve
    """
    if action == "update":
        _baseline_update(approve=approve, manifest_file=manifest_file)


def _baseline_update(*, approve: bool, manifest_file: str | None) -> None:
    """Write baseline files from the current manifest."""
    import yaml

    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )

    if not approve:
        click.echo(
            "error: --approve required to update baselines",
            err=True,
        )
        sys.exit(1)

    # Locate manifest
    manifest_path = Path(manifest_file) if manifest_file is not None else discover_manifest(Path.cwd())

    if manifest_path is None or not manifest_path.exists():
        looked_up = manifest_file if manifest_file is not None else str(Path.cwd())
        cli_error(f"manifest not found: {looked_up}")
        sys.exit(2)

    try:
        manifest_model = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError, ManifestLoadError) as exc:
        cli_error(f"manifest invalid: {exc}")
        sys.exit(1)

    # Build manifest baseline JSON
    manifest_baseline = {
        "tiers": [
            {"id": t.id, "tier": t.tier, "description": t.description}
            for t in manifest_model.tiers
        ],
        "module_tiers": [
            {"path": mt.path, "default_taint": mt.default_taint}
            for mt in manifest_model.module_tiers
        ],
    }

    # Build perimeter baseline JSON
    perimeter_baseline = {
        "module_paths": [mt.path for mt in manifest_model.module_tiers],
    }

    # Write baselines
    manifest_baseline_path = manifest_path.parent / "wardline.manifest.baseline.json"
    perimeter_baseline_path = (
        manifest_path.parent / "wardline.perimeter.baseline.json"
    )

    manifest_baseline_path.write_text(
        json.dumps(manifest_baseline, indent=2) + "\n",
        encoding="utf-8",
    )
    perimeter_baseline_path.write_text(
        json.dumps(perimeter_baseline, indent=2) + "\n",
        encoding="utf-8",
    )

    click.echo(f"wrote {manifest_baseline_path}")
    click.echo(f"wrote {perimeter_baseline_path}")
    sys.exit(0)
