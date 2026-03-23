# Spike: Call Graph Approach for L3 Taint Propagation

**Date:** 2026-03-23
**Status:** Decision made
**Scope:** WP 2.1 — Intra-module call graph for taint propagation

## Decision

**Use stdlib `ast` only.** Sufficient for intra-module call graph
construction. `astroid` not needed.

## Resolution Rates

### By call pattern (intra-module only)

| Pattern | `ast` resolves? | Frequency |
|---------|----------------|-----------|
| `foo()` — direct call to module-level def | YES | High |
| `self.method()` — method on enclosing class | YES (scope stack) | High |
| `ClassName()` — constructor | YES | Medium |
| `handler(x)` — parameter-passed callable | NO | Low |
| `renamed()` where `renamed = original` | NO (needs data flow) | Rare |
| `step(x)` in loop over collection | NO | Rare |

### Real-world (engine.py)

- Intra-module calls (self.method): **5/5 = 100%**
- All calls including cross-module: ~9/22 = ~41%
- **For L3 purposes (intra-module only): ~100%**

Real wardline code uses direct calls and self-method calls almost
exclusively for intra-module edges. Unresolvable patterns (higher-order,
aliases, dynamic dispatch) are overwhelmingly cross-module.

## What `astroid` Would Add

- Alias resolution (~5% more edges in practice)
- ~15s additional parse overhead per scan
- Heavy transitive dependency (pylint ecosystem)
- Known hangs on recursive/complex inference chains
- **Net value for intra-module L3: minimal**

## Implementation Approach

### Algorithm

1. **Collect definitions:** Walk module AST, build `{name: qualname}` for
   all module-level functions and `{class.method: qualname}` for methods.
   Reuse `_scope.py`.

2. **Extract call edges:** For each function body:
   - `ast.Name(id=X)` where X in module defs → edge to X
   - `ast.Attribute(value=ast.Name(id='self'), attr=M)` where M in
     enclosing class → edge to `EnclosingClass.M`
   - Everything else → `UNRESOLVED` (no edge, no error)

3. **Build adjacency list:**
   `{caller_qualname: [(callee_qualname, certainty)]}`

4. **Propagate taint:** Fixed-point iteration. Function effective taint =
   join(own_taint, join(callee_taints)). Converges in O(depth) iterations.

### Integration

- `function_level.py` produces initial `{qualname: TaintState}`
- Call graph pass consumes this and produces refined taints
- Engine runs this as a new pass between Pass 1 and Pass 2
- `_scope.py` reused for def collection

### Unresolved Edges Policy

Unresolved calls → edge to implicit `UNKNOWN` node with `UNKNOWN_RAW`
taint. Conservative: if we can't resolve a call, the caller's taint
cannot be better than `UNKNOWN_RAW` (unless it has an explicit decorator
taint, which takes precedence per L1 invariant).

## Effort Estimate

| Task | Effort |
|------|--------|
| Call graph extractor | 2h |
| Fixed-point taint propagation | 1h |
| Engine integration (new pass) | 1h |
| Tests | 2h |
| **Total** | **~6h** |

## Deferred

- Cross-module call graphs (L4+, needs import resolution)
- Alias tracking (diminishing returns for intra-module)
- `astroid` integration (revisit only if L4 cross-module needs it)
