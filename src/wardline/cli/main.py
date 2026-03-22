"""Wardline CLI — Click-based command-line interface.

Entry point: ``wardline = "wardline.cli.main:cli"`` (pyproject.toml).
"""

from __future__ import annotations

import click


@click.group()
def cli() -> None:
    """Wardline — semantic boundary enforcement for Python."""


# --- Register subcommands ---
from wardline.cli.corpus_cmds import corpus  # noqa: E402
from wardline.cli.scan import scan  # noqa: E402

cli.add_command(corpus)
cli.add_command(scan)
