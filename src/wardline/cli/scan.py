"""wardline scan — full pipeline CLI command.

Wires manifest loading, config parsing, registry sync, rule
execution, GOVERNANCE signals, and SARIF output into a single
``wardline scan <path>`` command.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from wardline.core.severity import (
    Exceptionability,
    RuleId,
    Severity,
)
from wardline.scanner.context import Finding
from wardline.scanner.sarif import _PSEUDO_RULE_IDS, SarifReport

if TYPE_CHECKING:
    from wardline.manifest.models import ScannerConfig, WardlineManifest
    from wardline.scanner.rules.base import RuleBase

logger = logging.getLogger("wardline")


class _ConfigError:
    """Sentinel for config loading failure."""


_CONFIG_ERROR = _ConfigError()

# Exit codes (shared with main.py)
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CONFIG_ERROR = 2
EXIT_TOOL_ERROR = 3


def _error(msg: str) -> None:
    """Print structured error to stderr."""
    click.echo(f"error: {msg}", err=True)


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


def _canonical_registry() -> frozenset[RuleId]:
    """Return the set of canonical (non-pseudo) rule IDs from the registry."""
    return frozenset(r for r in RuleId if r not in _PSEUDO_RULE_IDS)


def _check_registry_sync(
    rules: tuple[RuleBase, ...],
) -> list[str]:
    """Bidirectional registry sync check.

    Returns a list of mismatch descriptions (empty = clean).
    - Every canonical RuleId must have a loaded rule class.
    - Every loaded rule class must have a canonical RuleId.
    """
    registry = _canonical_registry()
    loaded_ids = frozenset(r.RULE_ID for r in rules)

    mismatches: list[str] = []

    in_registry_not_loaded = registry - loaded_ids
    if in_registry_not_loaded:
        for rid in sorted(in_registry_not_loaded, key=str):
            mismatches.append(f"registry has {rid} but no rule class is loaded")

    in_loaded_not_registry = loaded_ids - registry
    if in_loaded_not_registry:
        for rid in sorted(in_loaded_not_registry, key=str):
            mismatches.append(
                f"rule class loaded for {rid} but not in registry"
            )

    return mismatches


def _make_governance_finding(
    rule_id: RuleId,
    message: str,
    severity: Severity = Severity.WARNING,
) -> Finding:
    """Create a GOVERNANCE-level diagnostic finding."""
    return Finding(
        rule_id=rule_id,
        file_path="<governance>",
        line=1,
        col=0,
        end_line=None,
        end_col=None,
        message=message,
        severity=severity,
        exceptionability=Exceptionability.UNCONDITIONAL,
        taint_state=None,
        analysis_level=0,
        source_snippet=None,
    )


def _disabled_rule_findings(
    disabled_rules: tuple[RuleId, ...],
    all_rules: tuple[RuleBase, ...],
) -> list[Finding]:
    """Emit GOVERNANCE findings for disabled rules.

    WARNING for standard disablement; ERROR for UNCONDITIONAL rules.
    A rule is UNCONDITIONAL if its DEFAULT_EXCEPTIONABILITY is
    UNCONDITIONAL (meaning all its findings are non-exceptable).
    """
    findings: list[Finding] = []
    # Build set of rules whose default exceptionability is UNCONDITIONAL
    unconditional_ids = frozenset(
        r.RULE_ID for r in all_rules
        if getattr(r, "DEFAULT_EXCEPTIONABILITY", Exceptionability.STANDARD)
        == Exceptionability.UNCONDITIONAL
    )

    for rid in disabled_rules:
        if rid in unconditional_ids:
            severity = Severity.ERROR
            msg = (
                f"UNCONDITIONAL rule {rid} has been disabled "
                "by configuration"
            )
        else:
            severity = Severity.WARNING
            msg = f"Rule {rid} has been disabled by configuration"

        findings.append(
            _make_governance_finding(
                RuleId.GOVERNANCE_RULE_DISABLED,
                msg,
                severity=severity,
            )
        )
    return findings


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
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
@click.option("--max-unknown-raw-percent", type=float, default=None,
              help="Max percentage of UNKNOWN_RAW findings per file scanned "
                   "(exit 1 if exceeded). Denominator is files_scanned.")
@click.option("--allow-registry-mismatch", is_flag=True, default=False,
              help="Emit GOVERNANCE finding instead of exit 2 on registry mismatch.")
@click.option("--allow-permissive-distribution", is_flag=True, default=False,
              help="Emit GOVERNANCE finding for permissive distribution mode.")
def scan(
    path: str,
    manifest: str | None,
    config: str | None,
    output: str | None,
    verbose: bool,
    debug: bool,
    verification_mode: bool,
    max_unknown_raw_percent: float | None,
    allow_registry_mismatch: bool,
    allow_permissive_distribution: bool,
) -> None:
    """Scan Python files for boundary violations."""
    _setup_logging(verbose=verbose, debug=debug)

    # --- Load manifest ---
    _manifest_result = _load_manifest(manifest)
    if _manifest_result is None:
        sys.exit(EXIT_CONFIG_ERROR)
    manifest_model, manifest_path = _manifest_result

    # --- Load optional config ---
    cfg = _load_config(config)
    if cfg is _CONFIG_ERROR:
        sys.exit(EXIT_CONFIG_ERROR)
    assert not isinstance(cfg, _ConfigError)  # narrow type for mypy

    # --- Merge CLI flags with config (CLI wins) ---
    effective_max_pct = max_unknown_raw_percent
    effective_allow_mismatch = allow_registry_mismatch
    effective_allow_permissive = allow_permissive_distribution

    if cfg is not None:
        if effective_max_pct is None:
            effective_max_pct = cfg.max_unknown_raw_percent
        if not effective_allow_mismatch:
            effective_allow_mismatch = cfg.allow_registry_mismatch
        if not effective_allow_permissive:
            effective_allow_permissive = cfg.allow_permissive_distribution

    # --- Create rules ---
    all_rules = _make_rules()

    # --- Filter out disabled rules ---
    disabled_rules: tuple[RuleId, ...] = ()
    if cfg is not None and cfg.disabled_rules:
        disabled_rules = cfg.disabled_rules

    active_rules = tuple(
        r for r in all_rules if r.RULE_ID not in disabled_rules
    )

    # --- Registry sync check ---
    mismatches = _check_registry_sync(all_rules)
    governance_findings: list[Finding] = []

    if mismatches:
        if effective_allow_mismatch:
            for mm in mismatches:
                governance_findings.append(
                    _make_governance_finding(
                        RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED,
                        f"Registry mismatch (allowed): {mm}",
                    )
                )
            logger.warning(
                "Registry mismatch allowed: %d mismatch(es)", len(mismatches)
            )
        else:
            for mm in mismatches:
                _error(f"registry sync failed: {mm}")
            sys.exit(EXIT_CONFIG_ERROR)

    # --- GOVERNANCE: disabled rules ---
    governance_findings.extend(
        _disabled_rule_findings(disabled_rules, all_rules)
    )

    # --- GOVERNANCE: permissive distribution ---
    if effective_allow_permissive:
        governance_findings.append(
            _make_governance_finding(
                RuleId.GOVERNANCE_PERMISSIVE_DISTRIBUTION,
                "Permissive distribution mode is active",
            )
        )

    # --- Determine target paths ---
    scan_path = Path(path).resolve()
    target_paths = cfg.target_paths if cfg is not None and cfg.target_paths else (scan_path,)

    exclude_paths: tuple[Path, ...] = ()
    if cfg is not None and cfg.exclude_paths:
        exclude_paths = cfg.exclude_paths

    # --- Resolve overlay boundaries ---
    from wardline.manifest.models import BoundaryEntry as _BoundaryEntry
    from wardline.manifest.resolve import resolve_boundaries

    boundaries: tuple[_BoundaryEntry, ...] = ()
    # manifest_path is threaded from _load_manifest — no re-discovery needed
    boundaries = resolve_boundaries(manifest_path.parent, manifest_model)

    # --- Create engine and run scan ---
    from wardline.scanner.engine import ScanEngine, ScanResult

    engine = ScanEngine(
        target_paths=target_paths,
        exclude_paths=exclude_paths,
        rules=active_rules,
        manifest=manifest_model,
        boundaries=boundaries,
    )

    logger.info("Scanning %d target path(s)...", len(target_paths))
    result: ScanResult = engine.scan()
    logger.info(
        "Scan complete: %d files scanned, %d skipped, %d findings",
        result.files_scanned,
        result.files_skipped,
        len(result.findings),
    )

    # --- Apply exception register ---
    from wardline.manifest.exceptions import load_exceptions
    from wardline.scanner.exceptions import apply_exceptions

    exceptions = load_exceptions(manifest_path.parent)
    if exceptions:
        processed, governance_ex = apply_exceptions(
            result.findings, exceptions, project_root=manifest_path.parent
        )
        result.findings = processed
        governance_findings.extend(governance_ex)

    # --- Merge governance findings ---
    all_findings = governance_findings + result.findings

    # --- Compute run-level counts ---
    from wardline.core.taints import TaintState

    unknown_raw_count = sum(
        1 for f in result.findings
        if f.taint_state == TaintState.UNKNOWN_RAW
    )
    unresolved_decorator_count = sum(
        1 for f in result.findings
        if f.rule_id == RuleId.WARDLINE_UNRESOLVED_DECORATOR
    )

    # --- Check max_unknown_raw_percent ---
    # NOTE: denominator is files_scanned, not function count. A single file
    # with multiple UNKNOWN_RAW functions can push the ratio above 100%.
    exceeded_pct = False
    if effective_max_pct is not None and result.files_scanned > 0:
        pct = (unknown_raw_count / result.files_scanned) * 100
        if pct > effective_max_pct:
            exceeded_pct = True
            logger.warning(
                "UNKNOWN_RAW percentage %.1f%% exceeds max %.1f%%",
                pct, effective_max_pct,
            )

    # --- Build SARIF output ---
    loaded_rule_ids = frozenset(r.RULE_ID for r in active_rules)
    report = SarifReport(
        findings=all_findings,
        verification_mode=verification_mode,
        implemented_rule_ids=loaded_rule_ids,
        unknown_raw_count=unknown_raw_count,
        unresolved_decorator_count=unresolved_decorator_count,
    )

    sarif_text = report.to_json_string() + "\n"

    if output is not None:
        try:
            Path(output).write_text(sarif_text, encoding="utf-8")
        except OSError as exc:
            click.echo(f"error: cannot write to '{output}': {exc}", err=True)
            sys.exit(EXIT_CONFIG_ERROR)
    else:
        click.echo(sarif_text, nl=False)

    # --- Summary to stderr ---
    scan_finding_count = len(result.findings)
    click.echo(
        f"{result.files_scanned} file(s) scanned, "
        f"{scan_finding_count} finding(s).",
        err=True,
    )

    # --- Determine exit code ---
    # GOVERNANCE findings are diagnostic metadata in SARIF; they do NOT
    # drive the exit code. Only scan findings + max_pct ceiling matter.
    has_tool_error = any(
        f.rule_id == RuleId.TOOL_ERROR for f in result.findings
    )

    if has_tool_error:
        sys.exit(EXIT_TOOL_ERROR)
    elif exceeded_pct or scan_finding_count > 0:
        sys.exit(EXIT_FINDINGS)
    else:
        sys.exit(EXIT_CLEAN)


def _setup_logging(*, verbose: bool, debug: bool) -> None:
    """Configure logging level based on CLI flags."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)


def _load_manifest(
    manifest_arg: str | None,
) -> tuple[WardlineManifest, Path] | None:
    """Load and validate the wardline.yaml manifest.

    Returns ``(manifest, resolved_path)`` on success, or ``None`` on
    error (after printing a structured error message).
    """
    import yaml

    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import (
        ManifestLoadError,
        WardlineYAMLError,
        load_manifest,
    )

    manifest_path: Path | None = None

    if manifest_arg is not None:
        manifest_path = Path(manifest_arg)
        if not manifest_path.exists():
            _error(f"manifest not found: {manifest_arg}")
            return None
    else:
        manifest_path = discover_manifest(Path.cwd())
        if manifest_path is None:
            _error(
                "no wardline.yaml found (searched upward from "
                f"{Path.cwd()})"
            )
            return None

    try:
        result = load_manifest(manifest_path)
    except (WardlineYAMLError, yaml.YAMLError) as exc:
        _error(f"manifest schema invalid: {exc}")
        return None
    except ManifestLoadError as exc:
        _error(f"manifest validation failed: {exc}")
        return None

    logger.info("Loaded manifest: %s", manifest_path)
    return result, manifest_path


def _load_config(config_arg: str | None) -> ScannerConfig | None | _ConfigError:
    """Load wardline.toml scanner configuration.

    Returns:
        ScannerConfig on success, None if no config specified,
        _CONFIG_ERROR sentinel on error.
    """
    from wardline.manifest.models import ScannerConfig, ScannerConfigError

    if config_arg is None:
        return None

    config_path = Path(config_arg)
    if not config_path.exists():
        _error(f"config not found: {config_arg}")
        return _CONFIG_ERROR

    try:
        return ScannerConfig.from_toml(config_path)
    except ScannerConfigError as exc:
        _error(f"config error: {exc}")
        return _CONFIG_ERROR
    except Exception as exc:
        _error(f"config load error: {exc}")
        return _CONFIG_ERROR
