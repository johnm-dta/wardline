"""wardline exception — exception register lifecycle commands."""

from __future__ import annotations

import datetime
import json
import sys
import uuid
from pathlib import Path
from typing import Any

import click

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId
from wardline.core.taints import TaintState
from wardline.scanner.fingerprint import compute_ast_fingerprint


# Rule governance context — explains why each rule matters
_RULE_GOVERNANCE_CONTEXT: dict[str, str] = {
    "PY-WL-001": (
        "This rule detects code that silently fabricates values for missing dictionary "
        "keys, bypassing validation. Fabricated defaults can mask data corruption or "
        "inject unvalidated values into trusted pipelines."
    ),
    "PY-WL-002": (
        "This rule detects missing shape validation on external input. Without shape "
        "checks, malformed data can propagate through the pipeline uncaught."
    ),
    "PY-WL-003": (
        "This rule detects raw external data used without sanitisation. Unsanitised "
        "data from untrusted sources can lead to injection or data corruption."
    ),
    "PY-WL-004": (
        "This rule detects unvalidated decorator arguments. Invalid arguments to "
        "wardline decorators can misconfigure security boundaries."
    ),
    "PY-WL-005": (
        "This rule detects unsafe type coercion on tainted data. Implicit type "
        "conversion can silently alter data semantics."
    ),
}

_EXCEPTIONS_FILENAME = "wardline.exceptions.json"


@click.group()
def exception() -> None:
    """Manage the wardline exception register."""


@exception.command()
@click.option("--rule", required=True, help="Rule ID (e.g., PY-WL-001)")
@click.option("--location", required=True, help="file_path::qualname")
@click.option("--taint-state", required=True, help="Taint state (e.g., EXTERNAL_RAW)")
@click.option("--rationale", required=True, help="Why this exception is granted")
@click.option("--reviewer", required=True, help="Who approved this exception")
@click.option("--governance-path", default="standard", type=click.Choice(["standard", "expedited"]))
@click.option("--expires", default=None, help="Expiry date (ISO 8601, e.g., 2027-03-23)")
@click.option("--agent-originated", is_flag=True, default=False, help="Mark as agent-originated")
def add(
    rule: str,
    location: str,
    taint_state: str,
    rationale: str,
    reviewer: str,
    governance_path: str,
    expires: str | None,
    agent_originated: bool,
) -> None:
    """Add a new exception to the register."""
    # Validate rule ID
    try:
        rule_id = RuleId(rule)
    except ValueError:
        click.echo(f"Error: invalid rule ID: {rule}", err=True)
        sys.exit(1)

    # Validate taint state
    try:
        taint = TaintState(taint_state)
    except ValueError:
        click.echo(f"Error: invalid taint state: {taint_state}", err=True)
        sys.exit(1)

    # Check not UNCONDITIONAL
    cell = matrix.lookup(rule_id, taint)
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        click.echo(
            f"Error: ({rule}, {taint_state}) is UNCONDITIONAL — cannot be excepted",
            err=True,
        )
        sys.exit(1)

    # Validate location format
    if "::" not in location:
        click.echo("Error: --location must be file_path::qualname", err=True)
        sys.exit(1)

    file_path, qualname = location.split("::", 1)

    # Agent-originated without expires
    if agent_originated and expires is None:
        click.echo("Error: agent-originated exceptions require --expires", err=True)
        sys.exit(1)

    # Validate expires format
    if expires is not None:
        try:
            datetime.date.fromisoformat(expires)
        except ValueError:
            click.echo(f"Error: invalid date format: {expires}", err=True)
            sys.exit(1)

    # Compute fingerprint
    fp = compute_ast_fingerprint(Path(file_path), qualname)
    if fp is None:
        click.echo(f"Error: cannot compute fingerprint for {location}", err=True)
        sys.exit(1)

    # Build entry
    exc_id = f"EXC-{uuid.uuid4().hex[:8].upper()}"
    entry: dict[str, Any] = {
        "id": exc_id,
        "rule": rule,
        "taint_state": taint_state,
        "location": location,
        "exceptionability": str(cell.exceptionability),
        "severity_at_grant": str(cell.severity),
        "rationale": rationale,
        "reviewer": reviewer,
        "expires": expires,
        "provenance": "cli",
        "agent_originated": agent_originated or None,
        "ast_fingerprint": fp,
        "recurrence_count": 0,
        "governance_path": governance_path,
    }

    # Load or create exceptions file
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    data["exceptions"].append(entry)
    _write_exceptions(exc_path, data)

    click.echo(f"Added exception {exc_id} for {rule} at {location}")


@exception.command()
@click.argument("ids", nargs=-1)
@click.option("--all", "refresh_all", is_flag=True, help="Refresh all non-expired exceptions")
@click.option("--actor", required=True, help="Who is performing this refresh")
@click.option("--rationale", required=True, help="Why the code change is safe")
@click.option("--confirm", is_flag=True, help="Required with --all")
@click.option("--dry-run", is_flag=True, help="Show rule context without modifying")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def refresh(
    ids: tuple[str, ...],
    refresh_all: bool,
    actor: str,
    rationale: str,
    confirm: bool,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Refresh exception fingerprints after code changes."""
    if not ids and not refresh_all:
        click.echo("Error: provide exception IDs or use --all", err=True)
        sys.exit(1)

    if refresh_all and not confirm:
        click.echo("Error: --all requires --confirm", err=True)
        sys.exit(1)

    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    today = datetime.date.today().isoformat()
    today_date = datetime.date.today()

    updated = 0
    stale = 0
    results: list[dict[str, Any]] = []

    for entry in data["exceptions"]:
        if not refresh_all and entry["id"] not in ids:
            continue

        # Skip expired
        if entry.get("expires"):
            try:
                if datetime.date.fromisoformat(entry["expires"]) < today_date:
                    continue
            except ValueError:
                pass

        location = entry["location"]
        rule = entry["rule"]

        if dry_run:
            # Show rule context
            desc = _RULE_GOVERNANCE_CONTEXT.get(rule, f"Rule {rule}")
            click.echo(f"\nException {entry['id']} for {rule}")
            click.echo(f"\n  {desc}")
            click.echo(f"\n  Granted because: \"{entry['rationale']}\"")
            click.echo(f"  Code at: {location}")
            click.echo(f"  Current fingerprint: {entry.get('ast_fingerprint', '<none>')}")
            continue

        if "::" not in location:
            results.append({"id": entry["id"], "status": "skipped", "reason": "invalid location"})
            continue

        file_path, qualname = location.split("::", 1)
        new_fp = compute_ast_fingerprint(Path(file_path), qualname)

        if new_fp is None:
            stale += 1
            results.append({"id": entry["id"], "status": "stale", "reason": "qualname not found"})
            continue

        old_fp = entry.get("ast_fingerprint", "")
        if old_fp and old_fp == new_fp:
            results.append({"id": entry["id"], "status": "unchanged"})
            continue

        # Update
        entry["ast_fingerprint"] = new_fp
        entry["last_refreshed_by"] = actor
        entry["last_refresh_rationale"] = rationale
        entry["last_refreshed_at"] = today
        updated += 1
        results.append({"id": entry["id"], "status": "refreshed", "old_fp": old_fp, "new_fp": new_fp})

    if not dry_run:
        _write_exceptions(exc_path, data)

    if json_output:
        click.echo(json.dumps({"updated": updated, "stale": stale, "results": results}, indent=2))
    else:
        click.echo(f"Refreshed {updated} exception(s), {stale} stale")


@exception.command()
@click.argument("exc_id")
@click.option("--reason", default="", help="Reason for expiry")
def expire(exc_id: str, reason: str) -> None:
    """Mark an exception as expired."""
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    today = datetime.date.today().isoformat()

    for entry in data["exceptions"]:
        if entry["id"] == exc_id:
            entry["expires"] = today
            _write_exceptions(exc_path, data)
            click.echo(f"Expired {exc_id} (expires: {today})")
            return

    click.echo(f"Error: exception {exc_id} not found", err=True)
    sys.exit(1)


@exception.command()
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def review(json_output: bool) -> None:
    """Review exceptions needing attention."""
    exc_path = _find_exceptions_file()
    data = _load_or_create(exc_path)
    today = datetime.date.today()

    stale: list[str] = []
    expired: list[str] = []
    approaching: list[str] = []
    unknown_prov: list[str] = []
    recurring: list[str] = []
    total = 0
    expedited = 0

    for entry in data["exceptions"]:
        total += 1
        if entry.get("governance_path") == "expedited":
            expedited += 1

        # Check fingerprint
        location = entry["location"]
        if "::" in location:
            fp, qn = location.split("::", 1)
            current = compute_ast_fingerprint(Path(fp), qn)
            stored = entry.get("ast_fingerprint", "")
            if not stored or current != stored:
                stale.append(entry["id"])

        # Expiry checks
        if entry.get("expires"):
            try:
                exp_date = datetime.date.fromisoformat(entry["expires"])
                if exp_date < today:
                    expired.append(entry["id"])
                elif exp_date <= today + datetime.timedelta(days=30):
                    approaching.append(entry["id"])
            except ValueError:
                pass

        if entry.get("agent_originated") is None:
            unknown_prov.append(entry["id"])

        if entry.get("recurrence_count", 0) >= 2:
            recurring.append(entry["id"])

    ratio = expedited / total if total > 0 else 0.0

    if json_output:
        click.echo(json.dumps({
            "stale": stale,
            "expired": expired,
            "approaching_expiry": approaching,
            "unknown_provenance": unknown_prov,
            "recurring": recurring,
            "expedited_ratio": round(ratio, 3),
            "total": total,
        }, indent=2))
    else:
        click.echo(f"Exception Register Review ({total} total)")
        click.echo(f"  Stale (fingerprint mismatch): {len(stale)}")
        click.echo(f"  Expired: {len(expired)}")
        click.echo(f"  Approaching expiry (30d): {len(approaching)}")
        click.echo(f"  Unknown provenance: {len(unknown_prov)}")
        click.echo(f"  Recurring (count >= 2): {len(recurring)}")
        click.echo(f"  Expedited ratio: {ratio:.1%}")


# --- Helpers ---

def _find_exceptions_file() -> Path:
    """Find wardline.exceptions.json relative to CWD."""
    # Walk up to find wardline.yaml, then use its directory
    from wardline.manifest.discovery import discover_manifest
    manifest_path = discover_manifest(Path.cwd())
    if manifest_path is not None:
        return manifest_path.parent / _EXCEPTIONS_FILENAME
    return Path.cwd() / _EXCEPTIONS_FILENAME


def _load_or_create(path: Path) -> dict[str, Any]:
    """Load exceptions file or create empty structure."""
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "$id": "https://wardline.dev/schemas/0.1/exceptions.schema.json",
        "exceptions": [],
    }


def _write_exceptions(path: Path, data: dict[str, Any]) -> None:
    """Write exceptions file with sorted, indented JSON."""
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
