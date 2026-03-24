"""Preview Phase 2 migration impact report."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

from wardline.core.severity import RuleId

if TYPE_CHECKING:
    from wardline.scanner.context import Finding

_GOVERNANCE_REASON_MAP: dict[RuleId, str] = {
    RuleId.GOVERNANCE_STALE_EXCEPTION: "stale_fingerprint",
    RuleId.GOVERNANCE_UNKNOWN_PROVENANCE: "unknown_provenance",
    RuleId.GOVERNANCE_RECURRING_EXCEPTION: "recurring",
    RuleId.GOVERNANCE_NO_EXPIRY_EXCEPTION: "no_expiry",
}


def build_preview_report(
    findings: list[Finding],
    governance_findings: list[Finding],
    *,
    scanned_path: str,
    wardline_version: str,
) -> dict[str, Any]:
    """Build the --preview-phase2 impact report.

    Pure function: filters findings and governance findings into
    a JSON-serializable dict.
    """
    # Ungoverned schema_default() calls
    unverified = [
        f for f in findings
        if f.rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
    ]

    # Group governance findings by exception ID, aggregate reasons
    exc_map: dict[str, dict[str, Any]] = {}
    for gf in governance_findings:
        reason = _GOVERNANCE_REASON_MAP.get(gf.rule_id)
        if reason is None or gf.exception_id is None:
            continue
        if gf.exception_id not in exc_map:
            exc_map[gf.exception_id] = {
                "exception_id": gf.exception_id,
                "rule": gf.original_rule or "",
                "location": (
                    f"{gf.file_path}::{gf.qualname}"
                    if gf.qualname
                    else gf.file_path
                ),
                "reasons": [],
            }
        exc_map[gf.exception_id]["reasons"].append(reason)

    return {
        "version": "1.0",
        "scan_metadata": {
            "wardline_version": wardline_version,
            "scanned_path": scanned_path,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        },
        "unverified_default_count": len(unverified),
        "exception_rereview_count": len(exc_map),
        "total_phase2_impact": len(unverified) + len(exc_map),
        "details": {
            "unverified_defaults": [
                {
                    "file": f.file_path,
                    "line": f.line,
                    "qualname": f.qualname,
                    "message": f.message,
                }
                for f in unverified
            ],
            "exceptions_needing_rereview": list(exc_map.values()),
        },
    }
