"""Wardline CLI — Click-based command-line interface.

Entry point: ``wardline = "wardline.cli.main:cli"`` (pyproject.toml).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from wardline.core.severity import RuleId

if TYPE_CHECKING:
    from wardline.scanner.rules.base import RuleBase

# Exit codes
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CONFIG_ERROR = 2
EXIT_TOOL_ERROR = 3

logger = logging.getLogger("wardline")


def _error(msg: str) -> None:
    """Print structured error to stderr."""
    click.echo(f"error: {msg}", err=True)


def _setup_logging(*, verbose: bool, debug: bool) -> None:
    """Configure logging level based on CLI flags."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    # Remove existing handlers to avoid duplicate output across invocations
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)


def _make_rules() -> tuple[RuleBase, ...]:
    """Instantiate all available rule classes."""
    from wardline.scanner.rules.py_wl_001 import RulePyWl001
    from wardline.scanner.rules.py_wl_002 import RulePyWl002
    from wardline.scanner.rules.py_wl_003 import RulePyWl003
    from wardline.scanner.rules.py_wl_004 import RulePyWl004
    from wardline.scanner.rules.py_wl_005 import RulePyWl005

    return (
        RulePyWl001(),
        RulePyWl002(),
        RulePyWl003(),
        RulePyWl004(),
        RulePyWl005(),
    )


@click.group()
def cli() -> None:
    """Wardline — semantic boundary enforcement for Python."""


@cli.command()
@click.option("--manifest", type=click.Path(exists=False), default=None,
              help="Path to wardline.yaml manifest.")
@click.option("--config", type=click.Path(exists=False), default=None,
              help="Path to wardline.toml config.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (stdout if not given).")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging to stderr.")
@click.option("--debug", is_flag=True, help="Debug logging to stderr.")
@click.option("--verification-mode", is_flag=True,
              help="Deterministic output (no timestamps).")
def scan(
    manifest: str | None,
    config: str | None,
    output: str | None,
    verbose: bool,
    debug: bool,
    verification_mode: bool,
) -> None:
    """Scan Python files for boundary violations."""
    _setup_logging(verbose=verbose, debug=debug)

    # --- Load manifest ---
    import yaml

    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )

    manifest_path: Path | None = None

    if manifest is not None:
        manifest_path = Path(manifest)
        if not manifest_path.exists():
            _error(f"manifest not found: {manifest}")
            sys.exit(EXIT_CONFIG_ERROR)
    else:
        manifest_path = discover_manifest(Path.cwd())
        if manifest_path is None:
            _error(
                "no wardline.yaml found (searched upward from "
                f"{Path.cwd()})"
            )
            sys.exit(EXIT_CONFIG_ERROR)

    try:
        load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError) as exc:
        _error(f"YAML parse error in {manifest_path}: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)
    except ManifestLoadError as exc:
        _error(f"manifest validation failed: {exc}")
        sys.exit(EXIT_CONFIG_ERROR)

    logger.info("Loaded manifest: %s", manifest_path)

    # --- Load optional config ---
    from wardline.manifest.models import ScannerConfig
    from wardline.scanner.engine import ScanEngine, ScanResult

    scanner_config: ScannerConfig | None = None
    if config is not None:
        config_path = Path(config)
        if not config_path.exists():
            _error(f"config not found: {config}")
            sys.exit(EXIT_CONFIG_ERROR)
        try:
            scanner_config = ScannerConfig.from_toml(config_path)
        except Exception as exc:
            _error(f"config load error: {exc}")
            sys.exit(EXIT_CONFIG_ERROR)

    # --- Determine target paths ---
    if scanner_config and scanner_config.target_paths:
        target_paths = scanner_config.target_paths
    else:
        # Default: scan from manifest's parent directory
        target_paths = (manifest_path.parent,)

    exclude_paths: tuple[Path, ...] = ()
    if scanner_config and scanner_config.exclude_paths:
        exclude_paths = scanner_config.exclude_paths

    # --- Create rules and engine ---
    rules = _make_rules()

    engine = ScanEngine(
        target_paths=target_paths,
        exclude_paths=exclude_paths,
        rules=rules,
    )

    # --- Run scan ---
    logger.info("Scanning %d target path(s)...", len(target_paths))
    result: ScanResult = engine.scan()
    logger.info(
        "Scan complete: %d files scanned, %d skipped, %d findings",
        result.files_scanned,
        result.files_skipped,
        len(result.findings),
    )

    # --- Format output ---
    output_lines: list[str] = []
    for finding in result.findings:
        output_lines.append(
            f"{finding.file_path}:{finding.line}:{finding.col}: "
            f"{finding.rule_id} {finding.message}"
        )

    if result.files_scanned == 0 and not result.findings:
        output_lines.append("No files scanned.")

    output_text = "\n".join(output_lines)
    if output_lines:
        output_text += "\n"

    summary = (
        f"\n{result.files_scanned} file(s) scanned, "
        f"{len(result.findings)} finding(s)."
    )
    output_text += summary + "\n"

    if output is not None:
        Path(output).write_text(output_text)
    else:
        click.echo(output_text, nl=False)

    # --- Determine exit code ---
    # Priority: exit 3 (tool error) > exit 1 (findings) > exit 0 (clean)
    has_tool_error = any(
        f.rule_id == RuleId.TOOL_ERROR for f in result.findings
    )
    has_findings = len(result.findings) > 0

    if has_tool_error:
        sys.exit(EXIT_TOOL_ERROR)
    elif has_findings:
        sys.exit(EXIT_FINDINGS)
    else:
        sys.exit(EXIT_CLEAN)
