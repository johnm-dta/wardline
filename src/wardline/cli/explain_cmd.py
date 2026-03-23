"""wardline explain — show taint resolution for a function."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import click


@click.command()
@click.argument("qualname")
@click.option(
    "--manifest",
    type=click.Path(),
    default=None,
    help="Path to wardline.yaml manifest.",
)
@click.option(
    "--path",
    "scan_path",
    type=click.Path(exists=True),
    default=".",
    help="Root path to search for the function.",
)
def explain(qualname: str, manifest: str | None, scan_path: str) -> None:
    """Show taint resolution path for a function.

    QUALNAME is the qualified name of the function (e.g., 'MyClass.process').
    """
    from wardline.core.matrix import lookup
    from wardline.core.severity import RuleId
    from wardline.manifest.discovery import discover_manifest
    from wardline.manifest.loader import load_manifest
    from wardline.scanner.discovery import discover_annotations
    from wardline.scanner.sarif import _PSEUDO_RULE_IDS
    from wardline.scanner.taint.function_level import (
        DECORATOR_TAINT_MAP,
        assign_function_taints,
        resolve_module_default,
        taint_from_annotations,
    )

    # Load manifest
    manifest_model = None
    manifest_path = Path(manifest) if manifest is not None else discover_manifest(Path(scan_path))

    if manifest_path is not None and manifest_path.exists():
        try:
            manifest_model = load_manifest(manifest_path)
        except Exception as exc:
            click.echo(f"warning: could not load manifest: {exc}", err=True)

    # Search for the function in Python files
    root = Path(scan_path).resolve()
    found = False

    for py_file in sorted(root.rglob("*.py")):
        # Skip hidden dirs, __pycache__, .venv, etc.
        parts = py_file.parts
        if any(
            p.startswith(".") or p == "__pycache__" or p == ".venv"
            for p in parts
        ):
            continue

        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        file_path_str = str(py_file)

        # Discover annotations and assign taints
        annotations = discover_annotations(tree, file_path_str)
        taint_map = assign_function_taints(
            tree, file_path_str, annotations, manifest_model
        )

        if qualname not in taint_map:
            continue

        # Found the function
        found = True
        taint = taint_map[qualname]

        click.echo(f"Function: {qualname}")
        click.echo(f"File: {py_file}")
        click.echo(f"Taint state: {taint}")
        click.echo()

        # Determine how taint was resolved
        decorator_taint = taint_from_annotations(
            file_path_str, qualname, annotations
        )
        module_default = resolve_module_default(file_path_str, manifest_model)

        if decorator_taint is not None:
            # Find which decorator(s) matched
            key = (file_path_str, qualname)
            annots = annotations.get(key, [])
            matching = [
                a.canonical_name
                for a in annots
                if a.canonical_name in DECORATOR_TAINT_MAP
            ]
            click.echo(f"Resolution: decorator ({', '.join(matching)})")
            click.echo(f"  Decorator taint: {decorator_taint}")
            if module_default is not None:
                click.echo(f"  Module default (overridden): {module_default}")
        elif module_default is not None:
            # Find which module_tiers entry matched
            click.echo("Resolution: module_tiers entry")
            if manifest_model is not None:
                from pathlib import PurePosixPath

                file_p = PurePosixPath(file_path_str)
                for mt in manifest_model.module_tiers:
                    entry_p = PurePosixPath(mt.path)
                    try:
                        file_p.relative_to(entry_p)
                        click.echo(f"  Matched path: {mt.path}")
                        click.echo(f"  Default taint: {mt.default_taint}")
                        break
                    except ValueError:
                        continue
        else:
            click.echo("Resolution: UNKNOWN_RAW (fallback)")
            if manifest_model is None:
                click.echo("  Reason: no manifest loaded")
            else:
                click.echo(
                    "  Reason: module not declared in module_tiers"
                )

        # Report unresolved decorators
        key = (file_path_str, qualname)
        annots = annotations.get(key, [])
        unresolved = [
            a
            for a in annots
            if a.canonical_name not in DECORATOR_TAINT_MAP
            and a.canonical_name != ""
        ]
        if unresolved:
            click.echo()
            click.echo("Unresolved decorators:")
            for a in unresolved:
                click.echo(f"  - {a.canonical_name}")

        # Show which rules would evaluate and at what severity
        click.echo()
        click.echo("Rules evaluated at this taint state:")
        canonical_rules = [
            r
            for r in RuleId
            if r not in _PSEUDO_RULE_IDS
        ]
        for rule_id in sorted(canonical_rules, key=lambda r: r.value):
            try:
                cell = lookup(rule_id, taint)
                click.echo(
                    f"  {rule_id}: severity={cell.severity}, "
                    f"exceptionability={cell.exceptionability}"
                )
            except KeyError:
                pass

        break  # Only show first match

    if not found:
        click.echo(f"error: function '{qualname}' not found")
        sys.exit(1)
