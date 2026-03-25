"""Corpus verification commands.

Verifies specimen fragments against scanner rules, computes per-rule
precision/recall where sample >= 5, and tracks known_false_negative
specimens separately from true negatives.
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
class _RuleStats:
    """Per-rule verdict counters."""

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
    stats: dict[str, _RuleStats],
) -> None:
    """Evaluate a specimen's verdict against scanner results."""
    rule_id = str(data.get("rule", "") or data.get("rule_id", ""))
    verdict = str(data.get("verdict", ""))

    if not rule_id or not verdict:
        return

    if rule_id not in stats:
        stats[rule_id] = _RuleStats()

    raw_taint = data.get("taint_state")
    taint_state = str(raw_taint) if raw_taint is not None else None
    boundaries = _parse_specimen_boundaries(data)
    optional_fields = _parse_specimen_optional_fields(data)
    fired = _run_rules_on_fragment(
        source,
        rules,
        taint_state=taint_state,
        boundaries=boundaries,
        optional_fields=optional_fields,
    )
    rule_fired = rule_id in fired

    if verdict == "true_positive":
        if rule_fired:
            stats[rule_id].tp += 1
        else:
            stats[rule_id].fn += 1
    elif verdict == "true_negative":
        if rule_fired:
            stats[rule_id].fp += 1
        else:
            stats[rule_id].tn += 1
    elif verdict == "known_false_negative":
        if rule_fired:
            click.echo(
                f"notice: {rule_id} fired on KFN specimen — consider promoting to true_positive",
                err=True,
            )
        stats[rule_id].kfn += 1


def _print_stats(stats: dict[str, _RuleStats]) -> None:
    """Print per-rule verdict stats with precision/recall where sample >= 5."""
    if not stats:
        return

    for rule_id in sorted(stats):
        s = stats[rule_id]
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

        line = f"  {rule_id}: {', '.join(parts)}"

        if s.sample_size >= 5:
            prec_denom = s.tp + s.fp
            precision = s.tp / prec_denom if prec_denom > 0 else 0.0
            recall_denom = s.tp + s.fn  # KFN excluded
            recall = s.tp / recall_denom if recall_denom > 0 else 0.0
            line += (
                f" | precision={precision:.1%}"
                f" recall={recall:.1%}"
            )

        click.echo(line)


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
def verify(corpus_dir: str, analysis_level: int) -> None:
    """Verify corpus specimens against scanner rules."""
    corpus_path = Path(corpus_dir)
    specimens = sorted(
        list(corpus_path.glob("**/*.yaml"))
        + list(corpus_path.glob("**/*.yml"))
    )

    if not specimens:
        click.echo("No specimens found.", err=True)
        raise SystemExit(1)

    WardlineSafeLoader = make_wardline_loader()
    rules = make_rules()
    stats: dict[str, _RuleStats] = {}
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

    skip_msg = f" ({skipped} skipped, level > {analysis_level})" if skipped else ""
    click.echo(f"Lite bootstrap: {total} specimens{skip_msg}")
    _print_stats(stats)

    if errors:
        raise SystemExit(1)
