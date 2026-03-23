# L3 Call-Graph Taint Propagation Design — WP 2.1

**Date:** 2026-03-24
**Status:** Draft
**Scope:** Intra-module call-graph taint inference with fixed-point propagation
**Target release:** v0.3.0
**Dependencies:** None (L1 and L2 taint infrastructure exist)
**Spike:** `docs/superpowers/specs/2026-03-23-callgraph-approach-spike.md`
**Spec references:** Wardline Framework Specification v0.2.0 — §5 (taint model), §10 property 6 (taint flow verification)

## Context

L1 taint assigns a `TaintState` per function from decorators or module defaults. L2 tracks per-variable taint within function bodies. Neither considers what a function *calls* — a function with no decorator that only calls `@external_boundary` functions is currently `UNKNOWN_RAW`, even though its actual data context is external.

L3 refines function-level taints by propagating taint along intra-module call edges. The spike decided: stdlib `ast` only (no `astroid`), intra-module scope only, direct calls + `self.method()` resolution.

This design was informed by a 7-reviewer panel. The panel identified three critical flaws in the spike's original propagation formula that this spec corrects:

- **Static Analysis C-1:** The `taint_join` lattice collapses cross-family pairs to `MIXED_RAW`, which would saturate the call graph. L3 needs a total trust order.
- **Static Analysis C-2:** Decorated functions must be anchored (read-only seeds), not participants in the join.
- **Static Analysis I-2 / Systems Thinker C2:** Unresolved calls must be transparent (no contribution), not `UNKNOWN_RAW` sources.

Additional panel findings incorporated: Security F1 (L3 cannot upgrade trust), Solution Architect C1 (L3 consumes and returns same type as L1), Quality F3 (property-based convergence testing), Python I3 (super() out of scope), Solution Architect I1 (separate extractor and propagator modules).

## 1. Trust Order for L3 Propagation

### Problem

The existing `taint_join()` in `core/taints.py` is designed for L2 variable-level merges within a function body. It uses a partial order where cross-family joins (e.g., `PIPELINE + EXTERNAL_RAW`) collapse to `MIXED_RAW`. This is correct for data-flow merges — if a variable holds data from both a pipeline and an external source, it genuinely has mixed provenance.

For call-graph propagation, the question is different: "what is the least-trusted data this function transitively touches?" A `PIPELINE` function that calls an `EXTERNAL_RAW` function doesn't have mixed data — it has a dependency on untrusted data. The effective trust should be `EXTERNAL_RAW`, not `MIXED_RAW`.

### Solution: Total Trust Order

Define a total ordering over `TaintState` for L3 purposes (most trusted → least trusted):

```
AUDIT_TRAIL > PIPELINE > SHAPE_VALIDATED > UNKNOWN_SEM_VALIDATED >
UNKNOWN_SHAPE_VALIDATED > EXTERNAL_RAW > UNKNOWN_RAW > MIXED_RAW
```

Represented as an integer rank (lower = more trusted):

| TaintState | Rank |
|---|---|
| `AUDIT_TRAIL` | 0 |
| `PIPELINE` | 1 |
| `SHAPE_VALIDATED` | 2 |
| `UNKNOWN_SEM_VALIDATED` | 3 |
| `UNKNOWN_SHAPE_VALIDATED` | 4 |
| `EXTERNAL_RAW` | 5 |
| `UNKNOWN_RAW` | 6 |
| `MIXED_RAW` | 7 |

L3 propagation uses `max(rank)` — the effective taint is the least-trusted state in the transitive call closure. This replaces `taint_join` for L3 purposes only. L2 variable-level taint continues to use `taint_join` unchanged.

**Location:** New function `callgraph_taint_min(a, b) -> TaintState` in `scanner/taint/callgraph.py`. Not added to `core/taints.py` — this is an L3-specific operation, not a lattice primitive.

## 2. Anchored vs. Floating Functions

### Problem

The spike's formula `function_taint = join(own_taint, join(callee_taints))` allows decorated functions to have their taint altered by call-graph propagation. This violates the L1 security invariant (function_level.py line 13-14): "a function explicitly decorated `@external_boundary` must still get `EXTERNAL_RAW`."

Worse: if propagation is bidirectional (callee taint flows to caller AND caller context influences callee), a decorated function could be *upgraded* — a trust boundary violation.

### Solution: Anchored/Floating Split

Split functions into two sets:

- **Anchored:** Functions with a decorator taint or manifest module_tiers taint. Their L1-assigned taint is immutable — they are read-only data sources in the call graph. They seed the propagation but their own taint never changes.
- **Floating:** Functions that defaulted to `UNKNOWN_RAW` in L1 (no decorator, no module_tiers match). Only floating functions participate in propagation — their taint is refined based on what they call.

**Propagation formula for floating functions:**

```
L3_taint(F) = max_rank(callee_taints)
            where callee_taints = {L3_taint(G) for G in resolved_callees(F)}
```

If a floating function has no resolved callees, its taint remains `UNKNOWN_RAW` (the L1 default).

**Invariant (enforced post-fixed-point):**

```
For all functions F:
    L3_taint(F) == L1_taint(F)       if F is anchored
    trust_rank(L3_taint(F)) >= trust_rank(L1_taint(F))   if F is floating
```

The second condition ensures L3 can only make floating functions *less* trusted (higher rank) than their L1 default, or leave them unchanged. L3 cannot upgrade trust. This is verified by a post-fixed-point assertion — violation is a scanner bug.

## 3. Unresolved Call Policy

### Problem

The spike says unresolved calls map to `UNKNOWN_RAW`. Combined with the trust-order propagation, any function that calls an imported function (which is nearly every function) would be pulled to `UNKNOWN_RAW` or worse, destroying L3's value.

### Solution: Transparent Unresolved Calls

Unresolved calls contribute nothing to the callee taint set. Only resolved intra-module edges participate in propagation.

**Rationale:** L3 explicitly scopes to intra-module analysis. Injecting `UNKNOWN_RAW` for cross-module calls would make L3 strictly worse than L1 for any function that imports anything. The pragmatic approach: L3 refines taint based on edges it *can* resolve. Edges it cannot resolve are treated as if they don't exist.

**Semantic:** "L3 computes the taint contribution of intra-module call relationships. Cross-module effects are not modeled and assumed neutral."

**What is unresolved:**
- `import foo; foo.bar()` — cross-module call
- `func_ref()` where `func_ref` is a parameter — higher-order call
- `getattr(obj, name)()` — dynamic dispatch
- `super().method()` — requires MRO resolution (explicitly out of scope for v0.3.0)
- `renamed()` where `renamed = original` — alias tracking (deferred)

**What is resolved:**
- `foo()` where `foo` is a module-level `def foo` — direct call
- `self.method()` where `method` is defined in the enclosing class — method call
- `ClassName()` — constructor call to a class defined in the same module

## 4. Call Graph Extraction

### Module: `scanner/taint/callgraph.py`

**Function:** `extract_call_edges(tree: ast.Module, qualname_map: dict[int, str]) -> dict[str, set[str]]`

**Algorithm:**

1. **Collect definitions:** Reuse `ScanEngine._build_qualname_map()` (extract to shared utility `scanner/_qualnames.py` if not already shared). Produces `{id(node): qualname}` for all functions.

2. **Build reverse map:** `{name: qualname}` for module-level functions, `{class_name: {method_name: qualname}}` for class methods.

3. **Extract edges per function:** Walk each function body:
   - `ast.Call(func=ast.Name(id=X))` where X is in module-level defs → edge to X's qualname
   - `ast.Call(func=ast.Attribute(value=ast.Name(id='self'), attr=M))` where M is in enclosing class → edge to `EnclosingClass.M`'s qualname
   - `ast.Call(func=ast.Name(id=ClassName))` where ClassName is a module-level class → edge to `ClassName.__init__` if it exists
   - Everything else → no edge (transparent)

4. **Return adjacency list:** `{caller_qualname: {callee_qualname, ...}}`

**Enclosing class resolution:** The qualname already encodes the class (`ClassName.method`). To resolve `self.method()`, extract the class prefix from the caller's qualname (`qualname.rsplit(".", 1)[0]`) and look up the method in the class's method set.

### Module: `scanner/taint/callgraph_propagation.py`

Separate from extraction (panel finding Solution Architect I1 — two distinct failure modes deserve independent test surfaces).

## 5. Fixed-Point Propagation

### Module: `scanner/taint/callgraph_propagation.py`

**Function:** `propagate_callgraph_taints(edges: dict[str, set[str]], taint_map: dict[str, TaintState]) -> dict[str, TaintState]`

**Input:**
- `edges`: adjacency list from `extract_call_edges`
- `taint_map`: L1 function-level taint map from `assign_function_taints`

**Output:** Refined `dict[str, TaintState]` — same type as input, drop-in replacement for L1 map.

**Algorithm:**

1. **Classify functions:** Partition into anchored (taint != `UNKNOWN_RAW` — they got a decorator or module_tiers assignment) and floating (taint == `UNKNOWN_RAW`).

2. **Initialize:** Copy `taint_map`. Floating functions start at `UNKNOWN_RAW`.

3. **SCC decomposition:** Compute strongly connected components via Tarjan's algorithm (O(V+E)). Process SCCs in reverse topological order — DAG portions converge in a single pass, iteration only within SCCs.

4. **Worklist iteration per SCC:**
   For each SCC (in reverse-topo order):
   - If the SCC contains only anchored functions, skip (their taints are fixed).
   - Initialize worklist with all floating functions in the SCC.
   - While worklist is non-empty:
     - Pop function F from worklist.
     - Compute `new_taint = max_rank({current_taint(G) for G in resolved_callees(F)})`.
     - If F has no resolved callees, `new_taint` remains `UNKNOWN_RAW`.
     - If `new_taint` differs from F's current taint: update F's taint, add all floating callers of F (within this SCC) to the worklist.
   - Safety bound: if iterations exceed `LATTICE_HEIGHT * SCC_SIZE` (= `8 * len(scc)`), log warning, break, use current state. This should never trigger if the implementation is monotonic.

5. **Post-fixed-point assertion:** For every function F:
   - If anchored: assert `result[F] == taint_map[F]`
   - If floating: assert `trust_rank(result[F]) >= trust_rank(taint_map[F])`
   - Violation → log error, emit `TOOL-ERROR` finding, return original `taint_map` unchanged.

**Convergence guarantee:** The trust-rank lattice has height 8. The transfer function (`max_rank` over callees) is monotone — taint can only stay the same or decrease in trust. With SCC-based ordering, DAG portions converge in one pass. Within SCCs, worst-case iterations = `LATTICE_HEIGHT * SCC_SIZE`. Total worst-case: `O(V + E + 8 * max_SCC_size * SCC_count)`, which is effectively `O(V + E)` for practical call graphs.

## 6. Engine Integration

### Pass Ordering

Current: L1 → L2 → rules
New:     L1 → L3 → L2 → rules

L3 runs *before* L2 because L2's `_resolve_call()` in `variable_level.py` looks up callee taint in `taint_map`. If L3 has refined a callee's taint, L2 should see the refined value.

### Engine Changes (`scanner/engine.py`)

In `_scan_file()`, between the existing L1 assignment and L2 variable taint:

```python
# Pass 1.5: Level 3 call-graph taint (when analysis_level >= 3)
if self._analysis_level >= 3 and taint_map:
    taint_map = self._run_callgraph_taint(tree, taint_map, file_path, result)
```

This replaces `taint_map` in-place — L2 and rules both consume the L3-refined map transparently. No `ScanContext` changes needed — L3 is invisible to rules (they already read `function_level_taint_map`, which now contains L3-refined taints).

### New Engine Method

```python
def _run_callgraph_taint(
    self,
    tree: ast.Module,
    taint_map: dict[str, TaintState],
    file_path: Path,
    result: ScanResult,
) -> dict[str, TaintState]:
    """Run L3 call-graph taint propagation. Returns refined taint_map."""
    from scanner.taint.callgraph import extract_call_edges
    from scanner.taint.callgraph_propagation import propagate_callgraph_taints

    qualname_map = self._build_qualname_map(tree)
    try:
        edges = extract_call_edges(tree, qualname_map)
        return propagate_callgraph_taints(edges, taint_map)
    except Exception as exc:
        logger.warning("L3 call-graph taint failed for %s: %s", file_path, exc)
        result.errors.append(f"L3 taint failed for {file_path}: {exc}")
        return taint_map  # Fall back to L1 map
```

### Qualname Map Extraction

`ScanEngine._build_qualname_map()` (engine.py:228-248) should be extracted to `scanner/_qualnames.py` as a shared utility, since L3's `extract_call_edges` needs the same mapping. This avoids a third implementation of scope tracking.

## 7. Taint Provenance Tracking

For WP 2.3b's extended `explain` command, L3 should record *why* a function's taint changed. Store a lightweight provenance record alongside the refined taint map:

```python
@dataclass(frozen=True)
class TaintProvenance:
    source: Literal["decorator", "module_default", "callgraph", "fallback"]
    via_callee: str | None = None  # qualname of the dominating callee (L3 only)
```

The propagation function returns `tuple[dict[str, TaintState], dict[str, TaintProvenance]]`. The engine stores provenance in `ScanContext` as an optional field for `explain` to consume later.

**This is additive — does not block L3 core functionality.** If it complicates the initial implementation, defer provenance to WP 2.3b and have L3 return only the refined taint map.

## 8. Exception Register Impact

### Problem (Systems Thinker C1, Security F4)

Exception matching uses `(rule, taint_state, location)` as key. When L3 changes a function's effective taint, existing exceptions silently stop matching.

### Solution

This is an exception register design change, not an L3 algorithm change. Two interventions:

1. **GOVERNANCE-EXCEPTION-TAINT-DRIFT finding:** During `apply_exceptions`, when an exception's `taint_state` doesn't match the function's current effective taint at the active analysis level, emit a governance finding instead of silently failing to match. Implementation: extend `scanner/exceptions.py`.

2. **`analysis_level` field on exception entries:** Store the analysis level active when the exception was granted. When analysis level changes (L1→L2→L3), exceptions granted at a lower level are flagged for re-review. Implementation: extend `ExceptionEntry` model and `exception_cmds.py`.

Both are scoped as requirements within WP 2.1, not separate work packages.

## 9. Corpus Upgrades

### Prerequisites (ship in v0.2.1)

- **Corpus verifier taint wiring:** `corpus_cmds.py` must wire `ScanContext` from specimen YAML metadata so taint-dependent rules execute correctly. Without this, L3 specimens are meaningless.
- **`analysis_level_required` field:** Add to `corpus-specimen.schema.json`. Verifier skips specimens above configured level. Default 1 for all existing specimens.
- **Rules 006-009 in verifier:** `_make_rules()` in `corpus_cmds.py` currently only instantiates rules 001-005. Add all 9.

### L3 Specimens (ship with WP 2.1)

Minimum specimen set for L3 validation:

| Specimen | Pattern | Expected L3 Behavior |
|---|---|---|
| Multi-hop call chain | A→B→C where C is `@external_boundary` | A and B refined to `EXTERNAL_RAW` |
| Direct recursion | A calls A (self-recursive) | Taint stable (no infinite loop) |
| Mutual recursion | A↔B cycle | Both converge to least-trusted callee taint |
| Mixed resolved/unresolved | A calls B (resolved) and `json.loads` (unresolved) | A refined by B only; `json.loads` transparent |
| Anchored not demoted | `@external_boundary` A calls `@tier1_read` B | A stays `EXTERNAL_RAW` (anchored) |
| Floating refinement | Undecorated A calls only `@tier1_read` functions | A refined from `UNKNOWN_RAW` to `AUDIT_TRAIL` |
| Diamond pattern | A calls B and C; B and C both call D | A gets `max_rank(B_taint, C_taint)` |
| No resolved callees | A calls only imported functions | A stays `UNKNOWN_RAW` |
| Trust upgrade blocked | Adversarial: craft call chain that attempts to upgrade trust | Post-fixed-point assertion catches it |

Set `analysis_level_required: 3` on all L3 specimens. Existing KFN specimens (PY-WL-001-KFN-01, PY-WL-004-KFN-01) should flip to TP at L3 — update their metadata.

## 10. Self-Hosting Baseline

L3 will change finding counts for taint-gated rules (especially PY-WL-003, which fires only at `EXTERNAL_RAW`/`UNKNOWN_RAW`/`MIXED_RAW`). The self-hosting test (`test_scan_finding_count_stable`) needs per-analysis-level baselines.

**Approach:** Parameterize the self-hosting test by analysis level. Maintain separate expected ranges for L1 (existing), L2 (existing), and L3 (measured after L3 stabilizes). CI runs at the configured analysis level.

## 11. Performance

Per the static analysis specialist (S-1): call-graph construction is O(V+E), fixed-point iteration is O(V * LATTICE_HEIGHT) = O(8V). The ast.parse() call dominates. No performance concern for intra-module analysis.

**Validation:** Add a `pytest-benchmark` test that runs the self-hosting scan at L3 and records wall time. Set a 30-second budget (same as the existing performance requirement from panel I10).

## 12. Known Limitations

| Limitation | Rationale |
|---|---|
| Intra-module only | Cross-module requires import resolution — deferred to L4+ |
| No alias tracking | `renamed = original; renamed()` unresolvable without data flow |
| No `super()` resolution | Requires MRO computation, which requires class hierarchy — effectively cross-module |
| No dynamic dispatch | `getattr()`, `dispatch_table[key]()` — runtime information unavailable |
| No higher-order calls | `func_ref()` where `func_ref` is a parameter — requires inter-procedural analysis |
| Unresolved calls are transparent | Conservative choice would be UNKNOWN_RAW, but this causes cascade; transparency trades false negatives for noise reduction |

## 13. Testing Strategy

### Unit Tests

- **Call graph extraction:** Test each resolution pattern (direct call, self.method, ClassName(), unresolved) independently.
- **Propagation:** Test anchored/floating classification, single-step propagation, multi-hop chains, diamond patterns.
- **SCC handling:** Direct recursion, mutual recursion, large SCC.

### Property-Based Tests (Hypothesis)

- **Convergence:** Random call graphs (DAGs and cyclic) with random initial taints → propagation terminates within bound.
- **Monotonicity:** Between consecutive iterations, no function's trust rank decreases (becomes more trusted).
- **Idempotence:** Running propagation twice on the same input produces identical output.
- **Anchored immutability:** Anchored functions' taints never change regardless of call graph structure.

### Integration Tests

- Self-hosting scan at L3 completes without errors.
- L3 corpus specimens produce expected results.
- KFN specimens flip to TP at L3.

## 14. Implementation Summary

| Component | File | Lines (est.) | Effort |
|---|---|---|---|
| Trust order + `callgraph_taint_min` | `scanner/taint/callgraph.py` | ~30 | XS |
| Call graph extraction | `scanner/taint/callgraph.py` | ~80 | S |
| SCC decomposition (Tarjan's) | `scanner/taint/callgraph_propagation.py` | ~60 | S |
| Fixed-point propagation | `scanner/taint/callgraph_propagation.py` | ~80 | S |
| Engine integration | `scanner/engine.py` | ~20 | XS |
| Qualname extraction to shared utility | `scanner/_qualnames.py` | ~30 | XS |
| Taint provenance (optional) | `scanner/taint/callgraph_propagation.py` | ~30 | XS |
| Exception taint-drift finding | `scanner/exceptions.py` | ~30 | XS |
| L3 corpus specimens (9+) | `corpus/specimens/` | ~200 | S |
| Property-based tests | `tests/unit/scanner/` | ~100 | S |
| Unit + integration tests | `tests/` | ~150 | S |
| Self-hosting baseline (L3) | `tests/integration/` | ~30 | XS |
| **Total** | | ~840 | **L** |
