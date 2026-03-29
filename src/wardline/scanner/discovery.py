"""Decorator discovery from AST — build import table and annotation map.

Scans a Python AST to discover wardline decorator usage on functions.
Three-phase process:

1. **TYPE_CHECKING detection** — pre-pass to identify line ranges inside
   ``if TYPE_CHECKING:`` blocks (both direct and qualified forms).
2. **Import table** — collect ``import`` and ``from … import`` statements
   (excluding TYPE_CHECKING blocks), resolve local names to canonical
   wardline decorator names via the registry.
3. **Annotation map** — walk decorated function definitions, match
   decorators against the import table, produce ``WardlineAnnotation``
   entries keyed by ``(file_path, qualname)``.

.. note:: **Known limitation (Level 1):** Import table construction
   only scans top-level statements. Imports inside ``try/except``,
   conditional blocks (except ``if TYPE_CHECKING``), or nested scopes
   are not discovered. See ``_build_import_table`` for details.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.core.registry import REGISTRY
from wardline.scanner.context import WardlineAnnotation

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Module prefixes that indicate a wardline import
_WARDLINE_PREFIXES = ("wardline",)


@dataclass(frozen=True)
class DynamicImportDiagnostic:
    """Structured warning for dynamic wardline imports."""

    line: int
    col: int
    message: str


# ── Phase 1: TYPE_CHECKING block detection ───────────────────────


def _collect_type_checking_lines(tree: ast.Module) -> frozenset[int]:
    """Collect all line numbers inside ``if TYPE_CHECKING:`` blocks.

    Handles both forms:
    - ``from typing import TYPE_CHECKING; if TYPE_CHECKING:``
      → ``ast.Name(id='TYPE_CHECKING')``
    - ``import typing; if typing.TYPE_CHECKING:``
      → ``ast.Attribute(value=ast.Name(id='typing'), attr='TYPE_CHECKING')``

    Returns a frozenset of line numbers that fall inside these blocks.
    """
    lines: set[int] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if not _is_type_checking_test(node.test):
            continue

        # Collect line numbers in the if-true body only (NOT orelse).
        # The else-branch contains runtime imports that must NOT be filtered.
        for body_node in node.body:
            for child in ast.walk(body_node):
                if hasattr(child, "lineno"):
                    lines.add(child.lineno)

    return frozenset(lines)


def _is_type_checking_test(node: ast.expr) -> bool:
    """Check if an expression is ``TYPE_CHECKING`` or ``typing.TYPE_CHECKING``."""
    # Direct: TYPE_CHECKING
    if isinstance(node, ast.Name) and node.id == "TYPE_CHECKING":
        return True
    # Qualified: typing.TYPE_CHECKING only
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "TYPE_CHECKING"
        and isinstance(node.value, ast.Name)
        and node.value.id == "typing"
    )


# ── Phase 2: Import table construction ───────────────────────────


def _build_import_table(
    tree: ast.Module,
    tc_lines: frozenset[int],
) -> dict[str, str]:
    """Build a mapping of local name → canonical decorator name.

    Scans top-level ``import`` and ``from … import`` statements and
    cross-references imported names against the registry.

    .. note:: **Level-1 limitation** — only top-level import statements
       are scanned (via ``ast.iter_child_nodes(tree)``). Imports nested
       inside ``try/except`` blocks, conditional branches including
       ``if TYPE_CHECKING``, function bodies, or class bodies are not
       discovered. This is intentional for Level 1: deeper import
       tracking requires control-flow analysis (Level 2+).

    Returns:
        Dict mapping local names to canonical decorator names.
        For qualified imports (``import wardline``), the key is
        the module alias (e.g., ``"wardline"``), indicating that
        attribute access like ``wardline.external_boundary`` should
        be resolved at decorator matching time.
    """
    # local_name → canonical_name for direct/submodule imports
    name_table: dict[str, str] = {}
    # module aliases that could be used for qualified access
    # e.g., import wardline → "wardline" is a qualified source
    qualified_modules: dict[str, str] = {}

    has_star_import = False

    for node in ast.iter_child_nodes(tree):
        # Only process top-level imports. Nested imports, including those
        # inside TYPE_CHECKING blocks, are intentionally ignored at L1.
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue

        if isinstance(node, ast.ImportFrom):
            # Detect star imports from wardline modules
            if _is_wardline_module(node.module or ""):
                for alias in node.names:
                    if alias.name == "*":
                        has_star_import = True
                        logger.warning(
                            "Star import from wardline module '%s' makes "
                            "decorator tracking unreliable (line %d)",
                            node.module,
                            node.lineno,
                        )
            _process_from_import(node, name_table)
        elif isinstance(node, ast.Import):
            _process_import(node, qualified_modules)

    # Merge qualified modules into the table with a sentinel prefix
    # so decorator matching can distinguish them
    for qual_alias, module_path in qualified_modules.items():
        name_table[f"__qualified__:{qual_alias}"] = module_path

    if has_star_import:
        name_table["__star_import__"] = "True"

    return name_table


def _process_from_import(
    node: ast.ImportFrom,
    name_table: dict[str, str],
) -> None:
    """Process ``from X import Y`` — add to name_table if wardline-related.

    Handles:
    - ``from wardline import external_boundary``
    - ``from wardline.decorators.authority import external_boundary``
    - ``from wardline import external_boundary as eb``
    """
    module = node.module or ""
    if not _is_wardline_module(module):
        return

    for alias in node.names:
        imported_name = alias.name
        local_name = alias.asname or imported_name

        # Check if the imported name is a known decorator
        if imported_name in REGISTRY:
            name_table[local_name] = imported_name


def _process_import(
    node: ast.Import,
    qualified_modules: dict[str, str],
) -> None:
    """Process ``import X`` — track wardline module aliases.

    Handles:
    - ``import wardline`` → qualified_modules["wardline"] = "wardline"
    - ``import wardline as wl`` → qualified_modules["wl"] = "wardline"
    """
    for alias in node.names:
        module_name = alias.name
        local_alias = alias.asname or module_name

        if _is_wardline_module(module_name):
            qualified_modules[local_alias] = module_name


def _is_wardline_module(module: str) -> bool:
    """Check if a module path starts with a wardline prefix."""
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in _WARDLINE_PREFIXES)


def _detect_dynamic_imports(tree: ast.Module) -> list[DynamicImportDiagnostic]:
    """Scan AST for dynamic wardline imports and return diagnostics.

    Detects two patterns:
    - ``importlib.import_module("wardline...")``
    - ``__import__("wardline...")``

    Only literal string arguments are checked. Non-literal arguments
    (variables, f-strings) are silently skipped — they cannot be
    statically resolved.
    """
    diagnostics: list[DynamicImportDiagnostic] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Pattern: __import__("wardline...")
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and _is_wardline_module(node.args[0].value)
        ):
            diagnostics.append(
                DynamicImportDiagnostic(
                    line=node.lineno,
                    col=node.col_offset,
                    message=(
                        "Dynamic import of wardline module via "
                        f"__import__('{node.args[0].value}') makes decorator "
                        "tracking unreliable"
                    ),
                )
            )

        # Pattern: importlib.import_module("wardline...")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and _is_wardline_module(node.args[0].value)
        ):
            diagnostics.append(
                DynamicImportDiagnostic(
                    line=node.lineno,
                    col=node.col_offset,
                    message=(
                        "Dynamic import of wardline module via "
                        f"importlib.import_module('{node.args[0].value}') "
                        "makes decorator tracking unreliable"
                    ),
                )
            )
    return diagnostics


# ── Phase 3: Decorator → annotation mapping ──────────────────────


def discover_annotations(
    tree: ast.Module,
    file_path: Path | str,
) -> dict[tuple[str, str], list[WardlineAnnotation]]:
    """Discover wardline decorator annotations in a parsed AST.

    Args:
        tree: Parsed AST module.
        file_path: Path to the source file (used as map key).

    Returns:
        Dict mapping ``(file_path, qualname)`` to lists of
        ``WardlineAnnotation`` for each decorated function.

    Note:
        The spec calls for ``set[WardlineAnnotation]`` values, but ``list``
        is used deliberately: decorator ordering is meaningful for taint
        assignment (Group 1 before Group 2, and within a group the order
        of decorator application determines the final taint state).

    .. note:: Import discovery is limited to top-level statements.
       See ``_build_import_table`` for the full Level-1 limitation
       description.
    """
    path_str = str(file_path)
    tc_lines = _collect_type_checking_lines(tree)
    import_table = _build_import_table(tree, tc_lines)
    annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}

    _walk_functions(tree, import_table, path_str, annotations, scope="")

    return annotations


def _walk_functions(
    node: ast.AST,
    import_table: dict[str, str],
    file_path: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    scope: str,
) -> None:
    """Recursively walk AST nodes to find decorated functions.

    Builds qualified names by tracking class/function nesting.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{scope}.{child.name}" if scope else child.name
            found = _match_decorators(child, import_table)
            if found:
                annotations[(file_path, qualname)] = found
            # Recurse into nested functions/methods
            _walk_functions(
                child, import_table, file_path, annotations, scope=qualname
            )
        elif isinstance(child, ast.ClassDef):
            class_scope = (
                f"{scope}.{child.name}" if scope else child.name
            )
            _walk_functions(
                child, import_table, file_path, annotations, scope=class_scope
            )
        else:
            # Continue walking for other node types (e.g., if blocks)
            _walk_functions(
                child, import_table, file_path, annotations, scope=scope
            )


def _match_decorators(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    import_table: dict[str, str],
) -> list[WardlineAnnotation]:
    """Match a function's decorators against the import table.

    Handles two decorator AST forms:
    - ``@name`` → ``ast.Name`` → look up in import table
    - ``@module.name`` → ``ast.Attribute`` → check if module is a
      qualified wardline import, then look up ``name`` in registry
    """
    found: list[WardlineAnnotation] = []
    has_star = "__star_import__" in import_table

    for dec in func_node.decorator_list:
        canonical = _resolve_decorator(dec, import_table)
        if canonical is not None:
            entry = REGISTRY[canonical]
            found.append(
                WardlineAnnotation(
                    canonical_name=canonical,
                    group=entry.group,
                    attrs=MappingProxyType(
                        _extract_decorator_attrs(dec, canonical)
                    ),
                )
            )
            continue

        # If there's a star import and the decorator is an unresolved Name
        # that exists in the registry, it could be wardline-related
        if has_star and isinstance(dec, ast.Name) and dec.id in REGISTRY:
            logger.warning(
                "Decorator @%s on %s (line %d) may be wardline-related "
                "but cannot be reliably resolved due to star import",
                dec.id,
                func_node.name,
                dec.lineno,
            )

    return found


def _extract_decorator_attrs(
    dec: ast.expr,
    canonical: str,
) -> dict[str, object]:
    """Extract scanner-usable decorator arguments for known call decorators."""
    if not isinstance(dec, ast.Call):
        return {}

    attrs: dict[str, object] = {}
    for keyword in dec.keywords:
        if keyword.arg is None:
            continue
        value = _literalish_value(keyword.value)
        if value is not None:
            attrs[keyword.arg] = value

    if canonical == "ordered_after" and dec.args and "name" not in attrs:
        value = _literalish_value(dec.args[0])
        if value is not None:
            attrs["name"] = value

    return attrs


def _literalish_value(node: ast.expr) -> object | None:
    """Convert a simple AST node to a scanner-friendly literalish value."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        receiver = _literalish_value(node.value)
        if isinstance(receiver, str):
            return f"{receiver}.{node.attr}"
        return node.attr
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[object] = []
        for elt in node.elts:
            value = _literalish_value(elt)
            if value is None:
                return None
            values.append(value)
        return tuple(values)
    return None


def _resolve_decorator(
    dec: ast.expr,
    import_table: dict[str, str],
    *,
    max_depth: int = 50,
    _depth: int = 0,
) -> str | None:
    """Resolve a decorator AST node to a canonical registry name.

    Returns the canonical name if resolved, None otherwise.
    Returns None if the ``__wrapped__`` / call chain exceeds *max_depth*
    to prevent unbounded recursion on pathological decorator chains.
    """
    if _depth >= max_depth:
        return None

    # @name — direct import or aliased import
    if isinstance(dec, ast.Name):
        return import_table.get(dec.id)

    # @module.name — qualified access (e.g., @wardline.external_boundary)
    if isinstance(dec, ast.Attribute) and isinstance(dec.value, ast.Name):
        module_alias = dec.value.id
        attr_name = dec.attr
        # Check if this module alias is a qualified wardline import
        qualified_key = f"__qualified__:{module_alias}"
        if qualified_key in import_table and attr_name in REGISTRY:
            return attr_name

    # @call() — decorator with arguments (e.g., @external_boundary())
    if isinstance(dec, ast.Call):
        return _resolve_decorator(
            dec.func, import_table, max_depth=max_depth, _depth=_depth + 1
        )

    return None
