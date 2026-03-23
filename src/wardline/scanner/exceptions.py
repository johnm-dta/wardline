"""Exception matching and finding suppression.

Matches findings against active exceptions using the four-tuple key:
(rule, taint_state, location, ast_fingerprint). Produces governance
findings for stale, unknown-provenance, recurring, and no-expiry exceptions.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core.severity import (
    Exceptionability,
    RuleId,
    Severity,
)
from wardline.scanner.context import Finding, make_governance_finding
from wardline.scanner.fingerprint import compute_ast_fingerprint

if TYPE_CHECKING:
    from wardline.manifest.models import ExceptionEntry

logger = logging.getLogger(__name__)


def _parse_location(location: str) -> tuple[str, str | None]:
    """Parse 'file_path::qualname' into (file_path, qualname)."""
    if "::" in location:
        parts = location.split("::", 1)
        return parts[0], parts[1]
    return location, None


def apply_exceptions(
    findings: list[Finding],
    exceptions: tuple[ExceptionEntry, ...],
    project_root: Path,
    *,
    now: datetime.date | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Match findings against exceptions, return (processed, governance).

    ``now`` accepts a date for clock injection in tests (defaults to today).
    """
    if now is None:
        now = datetime.date.today()

    # Build index: (rule, taint_state, location) -> [exceptions]
    index: dict[tuple[str, str, str], list[ExceptionEntry]] = {}
    for exc in exceptions:
        key = (exc.rule, exc.taint_state, exc.location)
        index.setdefault(key, []).append(exc)

    # Cache for parsed AST fingerprints: (file_path, qualname) -> fingerprint
    _fp_cache: dict[tuple[str, str], str | None] = {}

    processed: list[Finding] = []
    governance: list[Finding] = []

    # Emit governance findings for all exceptions (regardless of matching)
    _emit_register_governance(exceptions, governance, now)

    for finding in findings:
        if finding.qualname is None:
            # Module-level findings can't be exception-matched
            processed.append(finding)
            continue

        # Relativize file_path so location keys match CLI-added exceptions
        try:
            rel_path = str(Path(finding.file_path).relative_to(project_root))
        except ValueError:
            rel_path = finding.file_path

        location = f"{rel_path}::{finding.qualname}"
        key = (str(finding.rule_id), str(finding.taint_state), location)
        candidates = index.get(key)

        if candidates is None:
            processed.append(finding)
            continue

        # Check if finding's exceptionability allows suppression
        if finding.exceptionability == Exceptionability.UNCONDITIONAL:
            processed.append(finding)
            continue

        # Compute fingerprint once per (file, qualname) — use absolute path
        # for file reading, project_root for consistent hash with CLI
        fp_key = (rel_path, finding.qualname)
        if fp_key not in _fp_cache:
            _fp_cache[fp_key] = compute_ast_fingerprint(
                Path(finding.file_path), finding.qualname,
                project_root=project_root,
            )
        current_fp = _fp_cache[fp_key]

        # Guard: if fingerprint computation failed, leave unsuppressed
        if current_fp is None:
            processed.append(finding)
            continue

        matched = False
        for exc in candidates:
            # Check expiry
            if exc.expires is not None:
                try:
                    expiry = datetime.date.fromisoformat(exc.expires)
                except ValueError:
                    continue
                if expiry < now:
                    continue  # Expired

            if exc.ast_fingerprint and current_fp != exc.ast_fingerprint:
                # Stale — fingerprint mismatch
                governance.append(_governance_finding(
                    RuleId.GOVERNANCE_STALE_EXCEPTION,
                    finding.file_path,
                    finding.line,
                    f"Exception '{exc.id}' has stale AST fingerprint "
                    f"(expected {exc.ast_fingerprint}, got {current_fp})",
                    qualname=finding.qualname,
                ))
                continue

            if not exc.ast_fingerprint:
                # Empty fingerprint = always stale
                governance.append(_governance_finding(
                    RuleId.GOVERNANCE_STALE_EXCEPTION,
                    finding.file_path,
                    finding.line,
                    f"Exception '{exc.id}' has no AST fingerprint — "
                    f"run 'wardline exception refresh {exc.id}' to compute one",
                    qualname=finding.qualname,
                ))
                continue

            # Match! Suppress the finding
            suppressed = replace(
                finding,
                severity=Severity.SUPPRESS,
                exceptionability=Exceptionability.TRANSPARENT,
                exception_id=exc.id,
                exception_expires=exc.expires,
            )
            processed.append(suppressed)
            matched = True
            break

        if not matched:
            processed.append(finding)

    return processed, governance


def _emit_register_governance(
    exceptions: tuple[ExceptionEntry, ...],
    governance: list[Finding],
    now: datetime.date,
) -> None:
    """Emit governance findings for exception register health."""
    for exc in exceptions:
        # Check expiry first — skip governance for expired exceptions
        if exc.expires is not None:
            try:
                expiry = datetime.date.fromisoformat(exc.expires)
                if expiry < now:
                    continue
            except ValueError:
                pass

        exc_file, exc_qualname = _parse_location(exc.location)

        if exc.agent_originated is None:
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_UNKNOWN_PROVENANCE,
                exc_file,
                1,
                f"Exception '{exc.id}' has unknown agent provenance "
                f"(agent_originated is null)",
                qualname=exc_qualname,
            ))

        if exc.recurrence_count >= 2:
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_RECURRING_EXCEPTION,
                exc_file,
                1,
                f"Exception '{exc.id}' has been renewed {exc.recurrence_count} times",
                qualname=exc_qualname,
            ))

        if exc.expires is None:
            governance.append(_governance_finding(
                RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION,
                exc_file,
                1,
                f"Exception '{exc.id}' has no expiry date",
                qualname=exc_qualname,
            ))


def _governance_finding(
    rule_id: RuleId,
    file_path: str,
    line: int,
    message: str,
    *,
    qualname: str | None = None,
) -> Finding:
    """Create a governance pseudo-rule finding (delegates to shared factory)."""
    return make_governance_finding(
        rule_id,
        message,
        file_path=file_path,
        line=line,
        qualname=qualname,
    )
