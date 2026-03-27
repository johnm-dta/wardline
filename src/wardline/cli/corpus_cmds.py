"""Corpus verification commands.

Verifies specimen fragments against scanner rules, computes per-cell
(rule x taint_state) precision/recall where sample >= 5, and tracks
known_false_negative specimens separately from true negatives.
"""

from __future__ import annotations

import ast
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import click
import yaml

from wardline.manifest.loader import make_wardline_loader
from wardline.scanner.rules import make_rules

if TYPE_CHECKING:
    from wardline.manifest.models import BoundaryEntry, OptionalFieldEntry
    from wardline.scanner.context import ScanContext
    from wardline.scanner.rules.base import RuleBase

logger = logging.getLogger(__name__)


@dataclass
class _CellStats:
    """Per-cell (rule x taint_state) verdict counters."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    kfn: int = 0

    @property
    def sample_size(self) -> int:
        return self.tp + self.fp + self.tn + self.fn + self.kfn


def _collect_qualnames(
    nodes: list[ast.stmt],
    prefix: str,
    result: dict[str, None],
) -> None:
    """Recursively collect dotted qualnames for all functions, mirroring RuleBase scope tracking."""
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{prefix}.{node.name}" if prefix else node.name
            result[qualname] = None
            _collect_qualnames(node.body, qualname, result)
        elif isinstance(node, ast.ClassDef):
            new_prefix = f"{prefix}.{node.name}" if prefix else node.name
            _collect_qualnames(node.body, new_prefix, result)
        else:
            # Recurse into control-flow blocks (if/for/while/with/try)
            for attr in ("body", "orelse", "finalbody"):
                sub = getattr(node, attr, None)
                if sub:
                    _collect_qualnames(sub, prefix, result)
            for handler in getattr(node, "handlers", ()) or ():
                if hasattr(handler, "body"):
                    _collect_qualnames(handler.body, prefix, result)


def _build_specimen_context(
    tree: ast.Module,
    taint_state: str,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> ScanContext:
    """Build a ScanContext that assigns *taint_state* to every function in *tree*.

    Uses dotted qualnames (e.g. ``MyClass.method``) matching the scope-stack
    construction in ``RuleBase._dispatch``, so ``_get_function_taint`` lookups
    resolve correctly for class methods and nested functions.
    """
    from wardline.core.taints import TaintState
    from wardline.scanner.context import ScanContext

    taint = TaintState(taint_state)
    qualnames: dict[str, None] = {}
    _collect_qualnames(tree.body, "", qualnames)
    taint_map: dict[str, TaintState] = {qn: taint for qn in qualnames}
    return ScanContext(
        file_path="<specimen>",
        function_level_taint_map=taint_map,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
        boundaries=boundaries,
        optional_fields=optional_fields,
    )


def _parse_specimen_boundaries(data: dict[str, object]) -> tuple[BoundaryEntry, ...]:
    """Build boundary declarations from an optional corpus specimen field."""
    from wardline.manifest.models import BoundaryEntry

    raw = data.get("boundaries", ())
    if raw in (None, ()):
        return ()
    if not isinstance(raw, list):
        raise ValueError("boundaries must be a list")

    entries: list[BoundaryEntry] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"boundary #{idx} must be a mapping")
        function = item.get("function")
        transition = item.get("transition")
        overlay_scope = item.get("overlay_scope", "<specimen>")
        if not isinstance(function, str) or not function:
            raise ValueError(f"boundary #{idx} missing string function")
        if not isinstance(transition, str) or not transition:
            raise ValueError(f"boundary #{idx} missing string transition")
        if not isinstance(overlay_scope, str):
            raise ValueError(f"boundary #{idx} has invalid overlay_scope")
        entries.append(
            BoundaryEntry(
                function=function,
                transition=transition,
                overlay_scope=overlay_scope,
            )
        )
    return tuple(entries)


def _parse_specimen_optional_fields(
    data: dict[str, object],
) -> tuple[OptionalFieldEntry, ...]:
    """Build optional-field declarations from an optional corpus specimen field."""
    from wardline.manifest.models import OptionalFieldEntry

    raw = data.get("optional_fields", ())
    if raw in (None, ()):
        return ()
    if not isinstance(raw, list):
        raise ValueError("optional_fields must be a list")

    entries: list[OptionalFieldEntry] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"optional_field #{idx} must be a mapping")
        field = item.get("field")
        rationale = item.get("rationale", "corpus specimen declaration")
        overlay_scope = item.get("overlay_scope", "<specimen>")
        approved_default = item.get("approved_default")
        if not isinstance(field, str) or not field:
            raise ValueError(f"optional_field #{idx} missing string field")
        if not isinstance(rationale, str):
            raise ValueError(f"optional_field #{idx} has invalid rationale")
        if not isinstance(overlay_scope, str):
            raise ValueError(f"optional_field #{idx} has invalid overlay_scope")
        entries.append(
            OptionalFieldEntry(
                field=field,
                approved_default=approved_default,
                rationale=rationale,
                overlay_scope=overlay_scope,
            )
        )
    return tuple(entries)


def _run_rules_on_fragment(
    source: str,
    rules: tuple[RuleBase, ...],
    taint_state: str | None = None,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> set[str]:
    """Run all rules on a source fragment, return set of fired rule IDs.

    Findings with ``Severity.SUPPRESS`` are excluded — they represent
    matrix cells where the rule is intentionally silent at that taint state.
    """
    from wardline.core.severity import Severity

    tree = ast.parse(source)

    ctx: ScanContext | None = None
    if taint_state is not None:
        ctx = _build_specimen_context(
            tree,
            taint_state,
            boundaries=boundaries,
            optional_fields=optional_fields,
        )

    fired: set[str] = set()
    for rule in rules:
        rule.findings.clear()
        rule.set_context(ctx)
        try:
            rule.visit(tree)
        except Exception as exc:
            logger.warning(
                "Rule %s crashed on specimen: %s", rule.RULE_ID, exc,
            )
            continue
        if any(f.severity != Severity.SUPPRESS for f in rule.findings):
            fired.add(str(rule.RULE_ID))
    return fired


def _evaluate_specimen(
    data: dict[str, object],
    source: str,
    rules: tuple[RuleBase, ...],
    stats: dict[tuple[str, str], _CellStats],
) -> None:
    """Evaluate a specimen's verdict against scanner results."""
    rule_id = str(data.get("rule", "") or data.get("rule_id", ""))
    verdict = str(data.get("verdict", ""))

    if not rule_id or not verdict:
        return

    raw_taint = data.get("taint_state")
    taint_state = str(raw_taint) if raw_taint is not None else "UNKNOWN"

    key = (rule_id, taint_state)
    if key not in stats:
        stats[key] = _CellStats()

    boundaries = _parse_specimen_boundaries(data)
    optional_fields = _parse_specimen_optional_fields(data)
    fired = _run_rules_on_fragment(
        source,
        rules,
        taint_state=taint_state if taint_state != "UNKNOWN" else None,
        boundaries=boundaries,
        optional_fields=optional_fields,
    )
    rule_fired = rule_id in fired

    if verdict == "true_positive":
        if rule_fired:
            stats[key].tp += 1
        else:
            stats[key].fn += 1
    elif verdict == "true_negative":
        if rule_fired:
            stats[key].fp += 1
        else:
            stats[key].tn += 1
    elif verdict == "known_false_negative":
        if rule_fired:
            click.echo(
                f"notice: {rule_id} fired on KFN specimen — consider promoting to true_positive",
                err=True,
            )
        stats[key].kfn += 1


def _get_floors(
    rule_id: str, taint_state: str,
) -> tuple[float | None, float | None]:
    """Return (precision_floor, recall_floor) from the severity matrix.

    Floors:
    - Precision: 80% (65% for MIXED_RAW)
    - Recall: 90% for UNCONDITIONAL, 70% for STANDARD/RELAXED
    - SUPPRESS cells: precision floor only, no recall floor
    """
    from wardline.core.matrix import SEVERITY_MATRIX
    from wardline.core.severity import Exceptionability, RuleId, Severity
    from wardline.core.taints import TaintState

    try:
        rid = RuleId(rule_id)
        ts = TaintState(taint_state)
    except ValueError:
        return (None, None)

    cell = SEVERITY_MATRIX.get((rid, ts))
    if cell is None:
        return (None, None)

    # Precision floor
    precision_floor = 0.65 if ts == TaintState.MIXED_RAW else 0.80

    # SUPPRESS cells: precision floor only, no recall floor
    if cell.severity == Severity.SUPPRESS:
        return (precision_floor, None)

    # Recall floor based on exceptionability
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        recall_floor = 0.90
    elif cell.exceptionability in (
        Exceptionability.STANDARD,
        Exceptionability.RELAXED,
    ):
        recall_floor = 0.70
    else:
        # TRANSPARENT — no recall floor
        recall_floor = None

    return (precision_floor, recall_floor)


def _print_cell_stats(stats: dict[tuple[str, str], _CellStats]) -> None:
    """Print per-cell verdict stats grouped by rule, with floor comparison."""
    if not stats:
        return

    # Group by rule_id
    rules: dict[str, list[str]] = {}
    for rule_id, taint_state in sorted(stats):
        rules.setdefault(rule_id, []).append(taint_state)

    for rule_id in sorted(rules):
        click.echo(f"  {rule_id}:")
        for taint_state in sorted(rules[rule_id]):
            key = (rule_id, taint_state)
            s = stats[key]
            parts: list[str] = []
            if s.tp:
                parts.append(f"{s.tp} TP")
            if s.tn:
                parts.append(f"{s.tn} TN")
            if s.fn:
                parts.append(f"{s.fn} FN")
            if s.fp:
                parts.append(f"{s.fp} FP")
            if s.kfn:
                parts.append(f"{s.kfn} KFN")

            line = f"    {taint_state}: {', '.join(parts)}"

            if s.sample_size >= 5:
                prec_denom = s.tp + s.fp
                precision = s.tp / prec_denom if prec_denom > 0 else 0.0
                recall_denom = s.tp + s.fn  # KFN excluded
                recall = s.tp / recall_denom if recall_denom > 0 else 0.0
                line += f" | precision={precision:.1%} recall={recall:.1%}"

                prec_floor, recall_floor = _get_floors(rule_id, taint_state)
                floor_parts: list[str] = []
                if prec_floor is not None:
                    status = "ok" if precision >= prec_floor else "BELOW"
                    floor_parts.append(
                        f"prec>={prec_floor:.0%} {status}"
                    )
                if recall_floor is not None:
                    status = "ok" if recall >= recall_floor else "BELOW"
                    floor_parts.append(
                        f"recall>={recall_floor:.0%} {status}"
                    )
                if floor_parts:
                    line += f" [{', '.join(floor_parts)}]"

            click.echo(line)


def _build_json_report(
    stats: dict[tuple[str, str], _CellStats],
) -> dict[str, object]:
    """Build per-cell assessment JSON with verdicts."""
    from wardline.core.matrix import SEVERITY_MATRIX
    from wardline.core.severity import RuleId, Severity
    from wardline.core.taints import TaintState

    cells: list[dict[str, object]] = []
    passing = 0
    failing = 0
    no_data = 0
    suppress_count = 0
    below_precision = 0
    below_recall = 0

    for rule_id, taint_state in sorted(stats):
        s = stats[(rule_id, taint_state)]
        prec_floor, recall_floor = _get_floors(rule_id, taint_state)

        # Determine matrix cell properties
        try:
            matrix_cell = SEVERITY_MATRIX[(RuleId(rule_id), TaintState(taint_state))]
            is_suppress = matrix_cell.severity == Severity.SUPPRESS
            exceptionability = str(matrix_cell.exceptionability.value)
        except (ValueError, KeyError):
            is_suppress = False
            exceptionability = "UNKNOWN"

        if is_suppress:
            suppress_count += 1

        # Compute metrics
        prec_denom = s.tp + s.fp
        precision = round(s.tp / prec_denom, 4) if prec_denom > 0 else None
        recall_denom = s.tp + s.fn
        recall = round(s.tp / recall_denom, 4) if recall_denom > 0 else None

        # Determine cell verdict
        if s.sample_size == 0:
            verdict = "NO_DATA"
            no_data += 1
        elif is_suppress:
            verdict = "PASS" if s.fp == 0 else "FAIL"
            if verdict == "PASS":
                passing += 1
            else:
                failing += 1
        else:
            below_p = (
                precision is not None
                and prec_floor is not None
                and precision < prec_floor
            )
            below_r = (
                recall is not None
                and recall_floor is not None
                and recall < recall_floor
            )
            if below_p:
                below_precision += 1
            if below_r:
                below_recall += 1
            verdict = "FAIL" if below_p or below_r else "PASS"
            if verdict == "PASS":
                passing += 1
            else:
                failing += 1

        cells.append({
            "rule": rule_id,
            "taint_state": taint_state,
            "exceptionability": exceptionability,
            "suppress": is_suppress,
            "tp": s.tp,
            "tn": s.tn,
            "fp": s.fp,
            "fn": s.fn,
            "kfn": s.kfn,
            "precision": precision,
            "recall": recall,
            "precision_floor": prec_floor,
            "recall_floor": recall_floor,
            "cell_verdict": verdict,
        })

    overall = "PASS" if failing == 0 and no_data == 0 else "FAIL"

    return {
        "format_version": "1.0",
        "overall_verdict": overall,
        "cells": cells,
        "summary": {
            "total_cells": len(cells),
            "measured_cells": passing + failing,
            "suppress_cells": suppress_count,
            "passing_cells": passing,
            "failing_cells": failing,
            "no_data_cells": no_data,
            "cells_below_precision_floor": below_precision,
            "cells_below_recall_floor": below_recall,
        },
    }


def _compute_corpus_hash(corpus_path: Path) -> str:
    """Hash-of-hashes over the full corpus artefact set.

    Covers specimen YAML files, corpus_manifest.json, and schema files.
    Uses the same §10.1 construction as inputHash.
    """
    all_files = sorted(
        list(corpus_path.glob("**/*.yaml"))
        + list(corpus_path.glob("**/*.yml"))
        + list(corpus_path.glob("**/*.json"))
    )

    records: list[str] = []
    for fp in all_files:
        resolved = fp.resolve()
        try:
            rel = resolved.relative_to(corpus_path.resolve())
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        records.append(f"{normalized}\x00{digest}")

    records.sort()
    combined = "".join(r + "\n" for r in records)
    return "sha256:" + hashlib.sha256(combined.encode("utf-8")).hexdigest()


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
@click.option(
    "--analysis-level",
    type=click.IntRange(1, 3),
    default=1,
    help="Analysis level (1-3). Specimens requiring a higher level are skipped.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output per-cell assessment JSON instead of text.",
)
def verify(corpus_dir: str, analysis_level: int, output_json: bool) -> None:
    """Verify corpus specimens against scanner rules."""
    corpus_path = Path(corpus_dir)
    # Keep the two glob results concatenated before sorting so `.yaml` and
    # `.yml` files share one deterministic ordering regardless of extension.
    specimens = sorted(
        list(corpus_path.glob("**/*.yaml"))
        + list(corpus_path.glob("**/*.yml"))
    )

    if not specimens:
        click.echo("No specimens found.", err=True)
        raise SystemExit(1)

    WardlineSafeLoader = make_wardline_loader()
    rules = make_rules()
    stats: dict[tuple[str, str], _CellStats] = {}
    errors = 0
    total = 0
    skipped = 0

    for specimen_path in specimens:
        total += 1
        try:
            with open(specimen_path, encoding="utf-8") as f:
                data = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506
        except OSError as exc:
            click.echo(
                f"error: cannot read {specimen_path.name}: {exc}",
                err=True,
            )
            errors += 1
            continue
        except yaml.YAMLError as exc:
            click.echo(
                f"error: {specimen_path.name} has invalid YAML: {exc}",
                err=True,
            )
            errors += 1
            continue

        if not isinstance(data, dict):
            click.echo(
                f"error: {specimen_path.name} is not a YAML mapping",
                err=True,
            )
            errors += 1
            continue

        # Skip specimens that require a higher analysis level
        try:
            required_level = int(data.get("analysis_level_required", 1))
        except (ValueError, TypeError):
            click.echo(
                f"error: {specimen_path.name} has invalid analysis_level_required",
                err=True,
            )
            errors += 1
            continue
        if required_level > analysis_level:
            skipped += 1
            total -= 1  # Don't count skipped specimens
            continue

        source = data.get("fragment", "") or data.get("source", "")

        if not source:
            click.echo(
                f"error: {specimen_path.name} has no 'fragment' field",
                err=True,
            )
            errors += 1
            continue

        # SHA-256 verification
        actual_hash = hashlib.sha256(
            str(source).encode("utf-8")
        ).hexdigest()
        expected_hash = data.get("sha256", "")
        if actual_hash != expected_hash:
            click.echo(
                f"error: hash mismatch in {specimen_path.name}: "
                f"expected {str(expected_hash)[:12]}..., "
                f"got {actual_hash[:12]}...",
                err=True,
            )
            errors += 1
            continue

        # Parse with ast.parse ONLY — never exec/eval/compile
        try:
            ast.parse(str(source))
        except SyntaxError as exc:
            click.echo(
                f"error: syntax error in {specimen_path.name}: {exc}",
                err=True,
            )
            errors += 1
            continue

        # Evaluate verdict against scanner rules
        try:
            _evaluate_specimen(data, str(source), rules, stats)
        except ValueError as exc:
            click.echo(
                f"error: {specimen_path.name}: {exc}",
                err=True,
            )
            errors += 1
            continue

    if output_json:
        import json as json_mod

        report = _build_json_report(stats)
        # No timestamp — deterministic output per §10 property 5.
        # corpus publish adds generated_at when producing the conformance file.
        click.echo(json_mod.dumps(report, indent=2, sort_keys=True))
    else:
        skip_msg = f" ({skipped} skipped, level > {analysis_level})" if skipped else ""
        click.echo(f"Lite bootstrap: {total} specimens{skip_msg}")
        _print_cell_stats(stats)

    if errors:
        raise SystemExit(1)


@corpus.command()
@click.option(
    "--corpus-dir",
    type=click.Path(exists=True, file_okay=False),
    default="corpus/",
    help="Corpus specimen directory.",
)
@click.option(
    "--sarif",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Self-hosting SARIF output file from a previous scan.",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False),
    default="wardline.conformance.json",
    help="Output path for conformance status file.",
)
@click.option(
    "--analysis-level",
    type=click.IntRange(1, 3),
    default=1,
    help="Analysis level (1-3).",
)
def publish(
    corpus_dir: str,
    sarif: str,
    output: str,
    analysis_level: int,
) -> None:
    """Generate wardline.conformance.json from corpus verify + self-hosting SARIF."""
    import json as json_mod
    from datetime import UTC, datetime

    # --- Run corpus verify internally ---
    corpus_path = Path(corpus_dir)
    specimens = sorted(
        list(corpus_path.glob("**/*.yaml"))
        + list(corpus_path.glob("**/*.yml"))
    )

    WardlineSafeLoader = make_wardline_loader()
    rules = make_rules()
    stats: dict[tuple[str, str], _CellStats] = {}
    errors = 0

    for specimen_path in specimens:
        try:
            with open(specimen_path, encoding="utf-8") as f:
                data = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506
        except (OSError, yaml.YAMLError):
            errors += 1
            continue
        if not isinstance(data, dict):
            errors += 1
            continue

        required_level = int(data.get("analysis_level_required", 1))
        if required_level > analysis_level:
            continue

        source = data.get("fragment", "") or data.get("source", "")
        if not source:
            errors += 1
            continue

        actual_hash = hashlib.sha256(str(source).encode("utf-8")).hexdigest()
        if actual_hash != data.get("sha256", ""):
            errors += 1
            continue

        try:
            ast.parse(str(source))
        except SyntaxError:
            errors += 1
            continue

        try:
            _evaluate_specimen(data, str(source), rules, stats)
        except ValueError:
            errors += 1
            continue

    if errors > 0:
        click.echo(
            f"error: {errors} corpus specimen(s) failed verification — "
            f"cannot generate conformance status from partial evidence.",
            err=True,
        )
        raise SystemExit(1)

    corpus_report = _build_json_report(stats)

    # --- Read self-hosting SARIF ---
    sarif_data = json_mod.loads(Path(sarif).read_text(encoding="utf-8"))
    run = sarif_data["runs"][0]
    run_props = run.get("properties", {})
    implemented_rules = set(run_props.get("wardline.implementedRules", []))

    # Count unexcepted findings for implemented rules
    unexcepted = 0
    for result in run.get("results", []):
        rule_id = result.get("ruleId", "")
        if rule_id not in implemented_rules:
            continue
        props = result.get("properties", {})
        if "wardline.exceptionId" in props:
            continue
        unexcepted += 1

    self_hosting_verdict = "PASS" if unexcepted == 0 else "FAIL"

    # --- Compute corpus hash ---
    corpus_hash = _compute_corpus_hash(corpus_path)

    # --- Build gaps list ---
    gaps: list[str] = []
    if corpus_report["overall_verdict"] == "FAIL":
        failing = corpus_report["summary"]["failing_cells"]
        gaps.append(f"{failing} corpus cell(s) below floor")
    if self_hosting_verdict == "FAIL":
        gaps.append(f"{unexcepted} unexcepted self-hosting finding(s)")
    gaps.append("adversarial corpus below full floor (deferred)")

    # --- Assemble conformance status ---
    tool_version = run.get("tool", {}).get("driver", {}).get("version", "unknown")

    conformance = {
        "format_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "inputs": {
            "tool_version": tool_version,
            "commit_ref": run_props.get("wardline.commitRef", "unknown"),
            "manifest_hash": run_props.get("wardline.manifestHash", "unknown"),
            "corpus_hash": corpus_hash,
            "self_hosting_input_hash": run_props.get("wardline.inputHash", "unknown"),
        },
        "corpus_verdict": corpus_report["overall_verdict"],
        "self_hosting_verdict": self_hosting_verdict,
        "gaps": gaps,
        "corpus_cells_failing": [
            c for c in corpus_report["cells"]
            if c["cell_verdict"] == "FAIL"
        ],
        "self_hosting_unexcepted_findings": unexcepted,
    }

    Path(output).write_text(
        json_mod.dumps(conformance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    click.echo(
        f"Conformance status written to {output} "
        f"(corpus={corpus_report['overall_verdict']}, "
        f"self-hosting={self_hosting_verdict}, "
        f"{len(gaps)} gap(s))"
    )
