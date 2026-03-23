"""Exception register loading and validation.

Loads ``wardline.exceptions.json``, validates against JSON schema, and
performs load-time UNCONDITIONAL re-validation against the severity matrix.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId
from wardline.core.taints import TaintState
from wardline.manifest.loader import ManifestLoadError
from wardline.manifest.models import ExceptionEntry

from wardline.core.severity import GovernancePath

_SCHEMA_DIR = Path(__file__).parent / "schemas"
_EXCEPTIONS_FILENAME = "wardline.exceptions.json"


def load_exceptions(manifest_dir: Path) -> tuple[ExceptionEntry, ...]:
    """Load and validate wardline.exceptions.json from *manifest_dir*.

    Returns empty tuple if the file does not exist.
    Raises ManifestLoadError on schema or governance validation failure.
    """
    path = manifest_dir / _EXCEPTIONS_FILENAME
    if not path.exists():
        return ()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ManifestLoadError(f"Cannot read {path}: {exc}") from exc

    # Schema validation
    schema_path = _SCHEMA_DIR / "exceptions.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ManifestLoadError(
            f"Cannot read exception schema {schema_path}: {exc}"
        ) from exc
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise ManifestLoadError(
            f"Exception register schema validation failed: {exc.message}"
        ) from exc

    entries: list[ExceptionEntry] = []
    for raw in data.get("exceptions", []):
        entry = ExceptionEntry(
            id=raw["id"],
            rule=raw["rule"],
            taint_state=raw["taint_state"],
            location=raw["location"],
            exceptionability=raw["exceptionability"],
            severity_at_grant=raw["severity_at_grant"],
            rationale=raw["rationale"],
            reviewer=raw["reviewer"],
            expires=raw.get("expires"),
            provenance=raw.get("provenance"),
            agent_originated=raw.get("agent_originated"),
            ast_fingerprint=raw.get("ast_fingerprint", ""),
            recurrence_count=raw.get("recurrence_count", 0),
            governance_path=GovernancePath(raw.get("governance_path", "standard")),
            last_refreshed_by=raw.get("last_refreshed_by"),
            last_refresh_rationale=raw.get("last_refresh_rationale"),
            last_refreshed_at=raw.get("last_refreshed_at"),
        )
        _validate_not_unconditional(entry, path)
        entries.append(entry)

    return tuple(entries)


def _validate_not_unconditional(entry: ExceptionEntry, path: Path) -> None:
    """Reject exceptions targeting UNCONDITIONAL severity matrix cells."""
    try:
        rule_id = RuleId(entry.rule)
        taint = TaintState(entry.taint_state)
    except ValueError:
        return  # Unknown rule/taint — can't validate

    cell = matrix.lookup(rule_id, taint)
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        raise ManifestLoadError(
            f"Exception '{entry.id}' targets UNCONDITIONAL cell "
            f"({entry.rule}, {entry.taint_state}) in {path}. "
            f"UNCONDITIONAL findings cannot be excepted."
        )
