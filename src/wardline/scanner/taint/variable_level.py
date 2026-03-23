"""Level 2 taint — per-variable taint tracking within function bodies.

Given a function AST node and its Level 1 (function-level) taint state,
walks the function body tracking taint per variable through assignments.

Design principles:
- **Pure function**: no side effects, returns a new dict.
- **Conservative**: unknown expressions get the function's own L1 taint.
- **Join-based merging**: control-flow branches merge via ``taint_join``.

Assignment forms handled:
1. ``x = expr`` — simple assignment
2. ``x += expr`` — augmented assignment (join with existing)
3. ``a, b = expr1, expr2`` — tuple unpacking
4. ``for x in iterable:`` — for-loop target
5. ``with open(f) as handle:`` — with-as
6. ``except Error as e:`` — exception-as
7. ``if (x := expr):`` — walrus operator (NamedExpr)
"""

from __future__ import annotations

import ast
import logging
from wardline.core.taints import TaintState, taint_join

logger = logging.getLogger(__name__)


def compute_variable_taints(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
) -> dict[str, TaintState]:
    """Compute per-variable taint for a function body.

    Args:
        func_node: The function AST node to analyze.
        function_taint: The Level 1 taint assigned to this function.
        taint_map: Maps function qualnames to their L1 taint states,
            used for resolving callee taint in function calls.

    Returns:
        Dict mapping variable name to ``TaintState`` for every assigned
        variable in the function body, including parameters.
    """
    var_taints: dict[str, TaintState] = {}

    # Parameters inherit the function's own taint (callers' data flows in).
    _seed_parameters(func_node, function_taint, var_taints)

    # Walk the body.
    _walk_body(func_node.body, function_taint, taint_map, var_taints)

    return var_taints


# ── Parameter seeding ────────────────────────────────────────────


def _seed_parameters(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    """Assign function taint to all parameters."""
    args = func_node.args
    for arg in (
        *args.posonlyargs,
        *args.args,
        *args.kwonlyargs,
    ):
        var_taints[arg.arg] = function_taint
    if args.vararg:
        var_taints[args.vararg.arg] = function_taint
    if args.kwarg:
        var_taints[args.kwarg.arg] = function_taint


# ── Expression taint resolution ──────────────────────────────────


def _resolve_expr(
    node: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    """Resolve the taint of an expression node.

    Rules:
    - Literals (Constant, JoinedStr with all-constant parts) → AUDIT_TRAIL
    - Name references → look up in var_taints
    - Function calls → look up callee in taint_map
    - Binary ops → join(left, right)
    - List/Tuple/Set/Dict literals → join of all elements
    - NamedExpr (walrus) → resolve inner, also assign to target
    - Fallback → function_taint
    """
    if isinstance(node, ast.Constant):
        return TaintState.AUDIT_TRAIL

    if isinstance(node, ast.Name):
        return var_taints.get(node.id, function_taint)

    if isinstance(node, ast.Call):
        return _resolve_call(node, function_taint, taint_map, var_taints)

    if isinstance(node, ast.BinOp):
        left = _resolve_expr(node.left, function_taint, taint_map, var_taints)
        right = _resolve_expr(node.right, function_taint, taint_map, var_taints)
        return taint_join(left, right)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if not node.elts:
            return TaintState.AUDIT_TRAIL
        result = _resolve_expr(node.elts[0], function_taint, taint_map, var_taints)
        for elt in node.elts[1:]:
            result = taint_join(
                result,
                _resolve_expr(elt, function_taint, taint_map, var_taints),
            )
        return result

    if isinstance(node, ast.Dict):
        if not node.values:
            return TaintState.AUDIT_TRAIL
        parts: list[TaintState] = []
        for v in node.values:
            if v is not None:
                parts.append(
                    _resolve_expr(v, function_taint, taint_map, var_taints)
                )
        if not parts:
            return TaintState.AUDIT_TRAIL
        result = parts[0]
        for p in parts[1:]:
            result = taint_join(result, p)
        return result

    if isinstance(node, ast.NamedExpr):
        taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
        if isinstance(node.target, ast.Name):
            var_taints[node.target.id] = taint
        return taint

    if isinstance(node, ast.IfExp):
        true_t = _resolve_expr(node.body, function_taint, taint_map, var_taints)
        false_t = _resolve_expr(node.orelse, function_taint, taint_map, var_taints)
        return taint_join(true_t, false_t)

    if isinstance(node, ast.UnaryOp):
        return _resolve_expr(node.operand, function_taint, taint_map, var_taints)

    # Fallback: attribute access, subscript, etc. — use function taint.
    return function_taint


def _resolve_call(
    node: ast.Call,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    """Resolve taint for a function call expression.

    Simple name calls (``foo()``) look up in taint_map.
    Everything else (method calls, complex expressions) → function_taint.
    """
    if isinstance(node.func, ast.Name):
        callee_name = node.func.id
        if callee_name in taint_map:
            return taint_map[callee_name]
    return function_taint


# ── Statement walkers ────────────────────────────────────────────


def _walk_body(
    stmts: list[ast.stmt],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Walk a list of statements, updating var_taints in place."""
    for stmt in stmts:
        _process_stmt(stmt, function_taint, taint_map, var_taints)


def _process_stmt(
    stmt: ast.stmt,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Process a single statement, dispatching by type."""

    if isinstance(stmt, ast.Assign):
        _handle_assign(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.AugAssign):
        _handle_augassign(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        # x: int = expr
        taint = _resolve_expr(stmt.value, function_taint, taint_map, var_taints)
        if isinstance(stmt.target, ast.Name):
            var_taints[stmt.target.id] = taint

    elif isinstance(stmt, ast.For):
        _handle_for(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.While):
        _handle_while(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.If):
        _handle_if(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.With) or isinstance(stmt, ast.AsyncWith):
        _handle_with(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.Try):
        _handle_try(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.Expr):
        # Expression statement — walk for side-effects (walrus operators).
        _resolve_expr(stmt.value, function_taint, taint_map, var_taints)

    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # Nested function — don't descend (separate scope).
        pass

    elif isinstance(stmt, ast.ClassDef):
        # Nested class — don't descend (separate scope).
        pass

    else:
        # Return, Raise, Import, Pass, Break, Continue, etc.
        # Walk child expressions for walrus operators.
        _walk_exprs_for_walrus(stmt, function_taint, taint_map, var_taints)


def _walk_exprs_for_walrus(
    node: ast.AST,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Walk all child expressions to catch walrus operators."""
    for child in ast.walk(node):
        if isinstance(child, ast.NamedExpr):
            taint = _resolve_expr(
                child.value, function_taint, taint_map, var_taints
            )
            if isinstance(child.target, ast.Name):
                var_taints[child.target.id] = taint


# ── Assignment handlers ──────────────────────────────────────────


def _handle_assign(
    stmt: ast.Assign,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``x = expr`` and ``a, b = expr1, expr2``."""
    for target in stmt.targets:
        if isinstance(target, ast.Name):
            # Simple: x = expr
            taint = _resolve_expr(
                stmt.value, function_taint, taint_map, var_taints
            )
            var_taints[target.id] = taint

        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple unpacking: a, b = ...
            _handle_unpack(
                target, stmt.value, function_taint, taint_map, var_taints
            )
        # Ignore attribute/subscript targets (obj.x = ..., d[k] = ...)


def _handle_unpack(
    target: ast.Tuple | ast.List,
    value: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle tuple/list unpacking assignment."""
    # If value is a Tuple/List with matching length, do element-wise.
    if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(
        target.elts
    ):
        for tgt, val in zip(target.elts, value.elts):
            if isinstance(tgt, ast.Name):
                taint = _resolve_expr(
                    val, function_taint, taint_map, var_taints
                )
                var_taints[tgt.id] = taint
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                _handle_unpack(tgt, val, function_taint, taint_map, var_taints)
    else:
        # RHS is not a matching literal tuple — all targets get RHS taint.
        rhs_taint = _resolve_expr(
            value, function_taint, taint_map, var_taints
        )
        for tgt in target.elts:
            if isinstance(tgt, ast.Name):
                var_taints[tgt.id] = rhs_taint
            elif isinstance(tgt, ast.Starred) and isinstance(
                tgt.value, ast.Name
            ):
                var_taints[tgt.value.id] = rhs_taint


def _handle_augassign(
    stmt: ast.AugAssign,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``x += expr`` — join existing taint with new value."""
    rhs_taint = _resolve_expr(
        stmt.value, function_taint, taint_map, var_taints
    )
    if isinstance(stmt.target, ast.Name):
        existing = var_taints.get(stmt.target.id, function_taint)
        var_taints[stmt.target.id] = taint_join(existing, rhs_taint)


# ── Control flow handlers ────────────────────────────────────────


def _handle_if(
    stmt: ast.If,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle if/elif/else — merge variable taints from branches."""
    # Resolve test expression (may contain walrus).
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints)

    # Snapshot before branches.
    pre_if = dict(var_taints)

    # Walk the if-body.
    if_taints = dict(var_taints)
    _walk_body(stmt.body, function_taint, taint_map, if_taints)

    if stmt.orelse:
        # Walk the else-body.
        else_taints = dict(var_taints)
        _walk_body(stmt.orelse, function_taint, taint_map, else_taints)
    else:
        # No else — the "else" branch is the pre-if state.
        else_taints = pre_if

    # Merge: for each variable, join the two branch values.
    all_vars = set(if_taints) | set(else_taints)
    for var in all_vars:
        if var in if_taints and var in else_taints:
            var_taints[var] = taint_join(if_taints[var], else_taints[var])
        elif var in if_taints:
            var_taints[var] = if_taints[var]
        else:
            var_taints[var] = else_taints[var]


def _handle_for(
    stmt: ast.For,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle for loops — target gets iterable taint, body merges."""
    iter_taint = _resolve_expr(
        stmt.iter, function_taint, taint_map, var_taints
    )

    # Assign the loop variable.
    _assign_target(stmt.target, iter_taint, var_taints)

    # Snapshot pre-loop.
    pre_loop = dict(var_taints)

    # Walk body.
    _walk_body(stmt.body, function_taint, taint_map, var_taints)

    # Merge body state with pre-loop (loop may not execute, or
    # body assignments may differ across iterations).
    for var in set(var_taints) | set(pre_loop):
        if var in var_taints and var in pre_loop:
            var_taints[var] = taint_join(var_taints[var], pre_loop[var])
        # Variables only in var_taints stay as-is.

    # Walk orelse (runs after normal loop completion).
    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints)


def _handle_while(
    stmt: ast.While,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle while loops — body merges with pre-loop state."""
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints)

    pre_loop = dict(var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints)

    # Merge body state with pre-loop.
    for var in set(var_taints) | set(pre_loop):
        if var in var_taints and var in pre_loop:
            var_taints[var] = taint_join(var_taints[var], pre_loop[var])

    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints)


def _handle_with(
    stmt: ast.With | ast.AsyncWith,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle with/async-with statements."""
    for item in stmt.items:
        expr_taint = _resolve_expr(
            item.context_expr, function_taint, taint_map, var_taints
        )
        if item.optional_vars is not None:
            _assign_target(item.optional_vars, expr_taint, var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints)


def _handle_try(
    stmt: ast.Try,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle try/except/else/finally — snapshot-branch-join pattern."""
    pre_try = dict(var_taints)

    # Walk try body on a copy.
    try_taints = dict(pre_try)
    _walk_body(stmt.body, function_taint, taint_map, try_taints)

    # Walk each handler on separate copies (mutually exclusive with try body).
    handler_branches: list[dict[str, TaintState]] = [try_taints]  # try-success is one branch
    for handler in stmt.handlers:
        handler_taints = dict(pre_try)
        if handler.name:
            handler_taints[handler.name] = TaintState.AUDIT_TRAIL
        _walk_body(handler.body, function_taint, taint_map, handler_taints)
        handler_branches.append(handler_taints)

    # Walk orelse on try-success branch (runs only if no exception).
    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, try_taints)

    # Merge all branches.
    all_vars: set[str] = set()
    for branch in handler_branches:
        all_vars.update(branch.keys())

    for var in all_vars:
        taints_to_join = [b[var] for b in handler_branches if var in b]
        if taints_to_join:
            var_taints[var] = taints_to_join[0]
            for t in taints_to_join[1:]:
                var_taints[var] = taint_join(var_taints[var], t)
        elif var in pre_try:
            var_taints[var] = pre_try[var]

    # finalbody runs unconditionally after merge.
    if stmt.finalbody:
        _walk_body(stmt.finalbody, function_taint, taint_map, var_taints)


# ── Helpers ──────────────────────────────────────────────────────


def _assign_target(
    target: ast.expr,
    taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    """Assign taint to a target node (Name, Tuple, or List)."""
    if isinstance(target, ast.Name):
        var_taints[target.id] = taint
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _assign_target(elt, taint, var_taints)
    elif isinstance(target, ast.Starred) and isinstance(target.value, ast.Name):
        var_taints[target.value.id] = taint
