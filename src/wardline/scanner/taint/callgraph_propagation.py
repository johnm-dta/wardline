"""SCC decomposition via iterative Tarjan's algorithm."""

from __future__ import annotations


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
    work_stack: list[tuple[str, object, bool]] = []

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
