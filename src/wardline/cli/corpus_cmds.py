"""Corpus verification commands."""

from __future__ import annotations

import ast
import hashlib
import logging
from pathlib import Path

import click
import yaml

from wardline.manifest.loader import make_wardline_loader

logger = logging.getLogger(__name__)


@click.group()
def corpus() -> None:
    """Corpus management commands."""


@corpus.command()
@click.option(
    "--corpus-dir",
    type=click.Path(exists=True, file_okay=False),
    default="corpus/",
    help="Directory containing specimen YAML files.",
)
def verify(corpus_dir: str) -> None:
    """Verify corpus specimens against scanner rules."""
    corpus_path = Path(corpus_dir)
    specimens = sorted(
        list(corpus_path.glob("*.yaml")) + list(corpus_path.glob("*.yml"))
    )

    if not specimens:
        click.echo("No specimens found.", err=True)
        raise SystemExit(1)

    WardlineSafeLoader = make_wardline_loader()
    errors = 0
    total = 0

    for specimen_path in specimens:
        total += 1
        with open(specimen_path) as f:
            data = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506

        if not isinstance(data, dict):
            click.echo(
                f"error: {specimen_path.name} is not a YAML mapping",
                err=True,
            )
            errors += 1
            continue

        source = data.get("source", "")
        expected_hash = data.get("sha256", "")

        if not source:
            click.echo(
                f"error: {specimen_path.name} has no 'source' field",
                err=True,
            )
            errors += 1
            continue

        # SHA-256 verification
        actual_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if actual_hash != expected_hash:
            click.echo(
                f"error: hash mismatch in {specimen_path.name}: "
                f"expected {expected_hash[:12]}..., got {actual_hash[:12]}...",
                err=True,
            )
            errors += 1
            continue

        # Parse with ast.parse ONLY — never exec/eval/compile
        try:
            ast.parse(source)
        except SyntaxError as exc:
            click.echo(
                f"error: syntax error in {specimen_path.name}: {exc}",
                err=True,
            )
            errors += 1

    click.echo(f"Lite bootstrap: {total} specimens")

    if errors:
        raise SystemExit(1)
