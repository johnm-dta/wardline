"""SCC decomposition and fixed-point call-graph taint propagation (L3).

Provides iterative Tarjan's SCC algorithm and the main propagation loop
that refines L1 function-level taints by analysing what each function calls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from wardline.scanner.taint.callgraph import TRUST_RANK

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wardline.core.taints import TaintState
    from wardline.scanner.taint.function_level import TaintSource

logger = logging.getLogger(__name__)

# Multiplier for the per-SCC convergence safety bound.  The worklist is
# allowed at most ``_CONVERGENCE_BOUND_FACTOR * len(scc)`` iterations.
_CONVERGENCE_BOUND_FACTOR: int = 8


# ── Provenance dataclass ──────────────────────────────────────────


@dataclass(frozen=True)
class TaintProvenance:
    """Records how a function's L3 taint was determined.

    Every function in the propagation output has a provenance record.
    """

    source: Literal["decorator", "module_default", "callgraph", "fallback"]
    via_callee: str | None = None
    resolved_call_count: int = 0
    unresolved_call_count: int = 0


# ── Fixed-point propagation ───────────────────────────────────────


def propagate_callgraph_taints(
    edges: dict[str, set[str]],
    taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSource],
    resolved_counts: dict[str, int],
    unresolved_counts: dict[str, int],
    *,
    return_taint_map: dict[str, TaintState] | None = None,
) -> tuple[dict[str, TaintState], dict[str, TaintProvenance], list[tuple[str, str]]]:
    """Run SCC-based fixed-point propagation to refine L1 taints.

    Args:
        edges: Forward adjacency ``{caller: {callee, ...}}``.
        taint_map: L1 taint assignments (copied, not mutated).
        taint_sources: L1 provenance classification per function.
        resolved_counts: Resolved call-site counts per caller.
        unresolved_counts: Unresolved call-site counts per caller.

    Returns:
        Tuple of ``(refined_taint_map, provenance_map, diagnostics)``.
        Diagnostics is a list of ``(code, message)`` tuples for
        L3_CONVERGENCE_BOUND and L3_LOW_RESOLUTION conditions.
    """
    from wardline.core.taints import TaintState

    if not taint_map:
        return {}, {}, []

    # Default return_taint_map to taint_map (body taint) if not provided.
    # This preserves backward compatibility for callers that don't split.
    if return_taint_map is None:
        return_taint_map = taint_map

    diagnostics: list[tuple[str, str]] = []

    # --- 1. Classify functions ------------------------------------------------
    anchored: set[str] = set()
    floating_down: set[str] = set()   # module_default
    floating_free: set[str] = set()   # fallback

    for func, src in taint_sources.items():
        if src == "decorator":
            anchored.add(func)
        elif src == "module_default":
            floating_down.add(func)
        else:
            floating_free.add(func)

    # --- 2. Initialize to L1 taints (copy unchanged) -------------------------
    current: dict[str, TaintState] = dict(taint_map)

    # Track which callee caused the refinement (for provenance)
    via_callee_map: dict[str, str | None] = {f: None for f in taint_map}

    # Track which functions were actually refined by L3
    refined: set[str] = set()

    # --- 3. Build reverse edge map --------------------------------------------
    reverse_edges: dict[str, set[str]] = {f: set() for f in taint_map}
    for caller, callees in edges.items():
        for callee in callees:
            if callee in reverse_edges:
                reverse_edges[callee].add(caller)

    # --- 4. SCC decomposition -------------------------------------------------
    # Only include nodes that are in taint_map
    taint_keys = set(taint_map)
    scc_graph: dict[str, set[str]] = {}
    for func in taint_map:
        scc_graph[func] = edges.get(func, set()) & taint_keys

    sccs = compute_sccs(scc_graph)

    # --- 5. Worklist iteration per SCC ----------------------------------------
    # Pre-compute rank-to-state reverse map (static, built once)
    rank_to_state = {r: s for s, r in TRUST_RANK.items()}

    for scc in sccs:
        # Skip all-anchored SCCs — they cannot change
        if scc <= anchored:
            continue

        safety_bound = _CONVERGENCE_BOUND_FACTOR * len(scc) * len(scc)
        iterations = 0

        # Phase 1: Compute external influence for each SCC member.
        # Only consider callees OUTSIDE the SCC (already at their final taint
        # since SCCs are processed in reverse-topo order).
        # Then initialize non-anchored SCC members to external-only estimate.
        has_external_influence: set[str] = set()
        for f in scc:
            if f in anchored:
                continue
            ext_callees = (edges.get(f, set()) & taint_keys) - scc
            if ext_callees:
                has_external_influence.add(f)
                ext_ranks = [
                    TRUST_RANK[return_taint_map[c] if c in anchored else current[c]]
                    for c in ext_callees
                ]
                ext_max = max(ext_ranks)
                if f in floating_down:
                    l1_rank = TRUST_RANK[taint_map[f]]
                    ext_max = max(ext_max, l1_rank)
                elif f in floating_free:
                    # Fix 1: floor clamp for floating_free in Phase 1
                    l1_rank = TRUST_RANK[taint_map[f]]
                    ext_max = max(ext_max, l1_rank)
                # Fix 2: unresolved calls pessimistic floor in Phase 1
                if unresolved_counts.get(f, 0) > 0:
                    ext_max = max(ext_max, TRUST_RANK[taint_map[f]])
                ext_taint = rank_to_state[ext_max]
                if ext_taint != current[f]:
                    current[f] = ext_taint
                    refined.add(f)
                    # Record via_callee from external callees
                    best_callee: str | None = None
                    best_rank = -1
                    for c in sorted(ext_callees):
                        c_rank = TRUST_RANK[current[c]]
                        if c_rank > best_rank:
                            best_rank = c_rank
                            best_callee = c
                    via_callee_map[f] = best_callee

        # Phase 2: Worklist iteration within the SCC to propagate internal edges.
        # Start with all non-anchored members that have callers with new values.
        worklist = {f for f in scc if f not in anchored}

        while worklist:
            if iterations >= safety_bound:
                logger.warning(
                    "L3 convergence bound hit for SCC of size %d after %d iterations",
                    len(scc),
                    iterations,
                )
                diagnostics.append((
                    "L3_CONVERGENCE_BOUND",
                    f"SCC of size {len(scc)} hit iteration bound after {iterations} iterations",
                ))
                break

            func = min(worklist)  # deterministic pick
            worklist.discard(func)
            iterations += 1

            # Gather ALL callee taints (both inside and outside SCC)
            callee_set = edges.get(func, set()) & taint_keys
            if not callee_set:
                # No resolved callees — stay at current taint
                continue

            # Compute max_rank (least trusted) among callees
            callee_ranks = [
                TRUST_RANK[return_taint_map[c] if c in anchored else current[c]]
                for c in callee_set
            ]
            max_callee_rank = max(callee_ranks, default=TRUST_RANK[TaintState.AUDIT_TRAIL])

            # Floor clamp for module_default: result >= L1 rank
            if func in floating_down:
                l1_rank = TRUST_RANK[taint_map[func]]
                result_rank = max(max_callee_rank, l1_rank)
            elif func in floating_free:
                # Fix 1: floor clamp — L3 must never make a function MORE
                # trusted than its L1 baseline.
                l1_rank = TRUST_RANK[taint_map[func]]
                result_rank = max(max_callee_rank, l1_rank)
            else:
                # anchored — skip (shouldn't reach here due to worklist filter)
                continue

            # Fix 2: unresolved calls pessimistic floor — if this function
            # has unresolved calls, it cannot be more trusted than its L1
            # baseline (unresolved calls could go anywhere).
            if unresolved_counts.get(func, 0) > 0:
                result_rank = max(result_rank, TRUST_RANK[taint_map[func]])

            new_taint = rank_to_state[result_rank]

            if new_taint != current[func]:
                current[func] = new_taint
                refined.add(func)

                # Determine via_callee: the callee with highest rank (least trusted).
                # Tie-break: alphabetically first qualname.
                best_callee_wl: str | None = None
                best_rank_wl = -1
                for c in sorted(callee_set):  # sorted for tie-breaking
                    c_rank = TRUST_RANK[current[c]]
                    if c_rank > best_rank_wl:
                        best_rank_wl = c_rank
                        best_callee_wl = c

                via_callee_map[func] = best_callee_wl

                # Add callers within this SCC to worklist
                for caller in reverse_edges.get(func, set()):
                    if caller in scc and caller not in anchored:
                        worklist.add(caller)

    # --- 6. Post-fixed-point assertions ---------------------------------------
    for func in anchored:
        if current[func] != taint_map[func]:
            logger.error(
                "L3 post-assertion FAILED: anchored function %s changed from %s to %s",
                func,
                taint_map[func],
                current[func],
            )
            return dict(taint_map), _seed_provenance_only(
                taint_map, taint_sources, resolved_counts, unresolved_counts,
            ), diagnostics

    for func in floating_down:
        if TRUST_RANK[current[func]] < TRUST_RANK[taint_map[func]]:
            logger.error(
                "L3 post-assertion FAILED: module_default function %s upgraded from %s to %s",
                func,
                taint_map[func],
                current[func],
            )
            return dict(taint_map), _seed_provenance_only(
                taint_map, taint_sources, resolved_counts, unresolved_counts,
            ), diagnostics

    # --- 6b. L3_LOW_RESOLUTION detection --------------------------------------
    for func in taint_map:
        res = resolved_counts.get(func, 0)
        unres = unresolved_counts.get(func, 0)
        total_calls = res + unres
        if total_calls > 0:
            unresolved_ratio = unres / total_calls
            if unresolved_ratio > 0.7:
                pct = int(unresolved_ratio * 100)
                diagnostics.append((
                    "L3_LOW_RESOLUTION",
                    f"Function {func} has {pct}% unresolved calls "
                    f"({unres}/{total_calls})",
                ))

    # --- 7. Build provenance records ------------------------------------------
    provenance: dict[str, TaintProvenance] = {}
    for func in taint_map:
        if func in anchored:
            provenance[func] = TaintProvenance(
                source="decorator",
                via_callee=None,
                resolved_call_count=resolved_counts.get(func, 0),
                unresolved_call_count=unresolved_counts.get(func, 0),
            )
        elif func in refined:
            provenance[func] = TaintProvenance(
                source="callgraph",
                via_callee=via_callee_map.get(func),
                resolved_call_count=resolved_counts.get(func, 0),
                unresolved_call_count=unresolved_counts.get(func, 0),
            )
        elif func in floating_down:
            provenance[func] = TaintProvenance(
                source="module_default",
                via_callee=None,
                resolved_call_count=resolved_counts.get(func, 0),
                unresolved_call_count=unresolved_counts.get(func, 0),
            )
        else:
            # fallback, unrefined
            provenance[func] = TaintProvenance(
                source="fallback",
                via_callee=None,
                resolved_call_count=resolved_counts.get(func, 0),
                unresolved_call_count=unresolved_counts.get(func, 0),
            )

    return current, provenance, diagnostics


def _seed_provenance_only(
    taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSource],
    resolved_counts: dict[str, int],
    unresolved_counts: dict[str, int],
) -> dict[str, TaintProvenance]:
    """Build provenance records without any L3 refinement (fallback path)."""
    provenance: dict[str, TaintProvenance] = {}
    for func in taint_map:
        src = taint_sources.get(func, "fallback")
        if src == "decorator":
            prov_source: Literal["decorator", "module_default", "callgraph", "fallback"] = "decorator"
        elif src == "module_default":
            prov_source = "module_default"
        else:
            prov_source = "fallback"
        provenance[func] = TaintProvenance(
            source=prov_source,
            via_callee=None,
            resolved_call_count=resolved_counts.get(func, 0),
            unresolved_call_count=unresolved_counts.get(func, 0),
        )
    return provenance


def compute_sccs(graph: dict[str, set[str]]) -> list[set[str]]:
    """Compute strongly connected components using iterative Tarjan's algorithm.

    Returns SCCs in reverse topological order of the condensation DAG
    (callees/leaves first), which is the natural output order of Tarjan's.

    Uses an explicit stack to avoid Python's recursion limit on large graphs.
    """
    index_counter = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    stack: list[str] = []
    result: list[set[str]] = []

    # Work stack frames: (node, neighbor_iterator, is_first_visit)
    work_stack: list[tuple[str, Iterator[str], bool]] = []

    for start_node in sorted(graph):
        if start_node in indices:
            continue

        # Push initial frame
        work_stack.append((start_node, iter(sorted(graph.get(start_node, set()))), True))

        while work_stack:
            node, neighbors, is_first_visit = work_stack.pop()

            if is_first_visit:
                # First visit: assign index and lowlink
                indices[node] = index_counter
                lowlinks[node] = index_counter
                index_counter += 1
                stack.append(node)
                on_stack[node] = True

            # Try to advance through neighbors
            pushed_child = False
            for neighbor in neighbors:
                if neighbor not in graph:
                    # Neighbor not in graph, skip
                    continue
                if neighbor not in indices:
                    # Unvisited neighbor: save current frame and push child
                    work_stack.append((node, neighbors, False))
                    work_stack.append((neighbor, iter(sorted(graph.get(neighbor, set()))), True))
                    pushed_child = True
                    break
                elif on_stack.get(neighbor, False):
                    lowlinks[node] = min(lowlinks[node], indices[neighbor])

            if pushed_child:
                continue

            # All neighbors processed: check if this is an SCC root
            if lowlinks[node] == indices[node]:
                scc: set[str] = set()
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.add(w)
                    if w == node:
                        break
                result.append(scc)

            # Update parent's lowlink
            if work_stack:
                parent_node = work_stack[-1][0]
                lowlinks[parent_node] = min(lowlinks[parent_node], lowlinks[node])

    return result
