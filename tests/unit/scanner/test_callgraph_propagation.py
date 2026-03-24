"""Tests for iterative Tarjan's SCC algorithm."""

from __future__ import annotations

from wardline.scanner.taint.callgraph_propagation import compute_sccs


def _scc_index(sccs: list[set[str]], node: str) -> int:
    """Return the index of the SCC containing `node`."""
    for i, scc in enumerate(sccs):
        if node in scc:
            return i
    raise ValueError(f"{node} not found in any SCC")


class TestComputeSccs:
    def test_dag_single_scc_per_node(self) -> None:
        """Acyclic graph: each node is its own SCC."""
        graph: dict[str, set[str]] = {
            "A": {"B"},
            "B": {"C"},
            "C": set(),
        }
        sccs = compute_sccs(graph)
        assert len(sccs) == 3
        for scc in sccs:
            assert len(scc) == 1
        # Reverse topological: C before B before A
        assert _scc_index(sccs, "C") < _scc_index(sccs, "B")
        assert _scc_index(sccs, "B") < _scc_index(sccs, "A")

    def test_simple_cycle(self) -> None:
        """A->B->A forms one SCC {A, B}."""
        graph: dict[str, set[str]] = {
            "A": {"B"},
            "B": {"A"},
        }
        sccs = compute_sccs(graph)
        assert len(sccs) == 1
        assert sccs[0] == {"A", "B"}

    def test_mutual_recursion(self) -> None:
        """A<->B (bidirectional edges) forms one SCC."""
        graph: dict[str, set[str]] = {
            "A": {"B"},
            "B": {"A"},
        }
        sccs = compute_sccs(graph)
        assert len(sccs) == 1
        assert sccs[0] == {"A", "B"}

    def test_diamond(self) -> None:
        """A->B, A->C, B->D, C->D: 4 SCCs, D processed first."""
        graph: dict[str, set[str]] = {
            "A": {"B", "C"},
            "B": {"D"},
            "C": {"D"},
            "D": set(),
        }
        sccs = compute_sccs(graph)
        assert len(sccs) == 4
        for scc in sccs:
            assert len(scc) == 1

        # D must appear before B, C, and A in the SCC list
        d_idx = _scc_index(sccs, "D")
        b_idx = _scc_index(sccs, "B")
        c_idx = _scc_index(sccs, "C")
        a_idx = _scc_index(sccs, "A")

        assert d_idx < b_idx
        assert d_idx < c_idx
        assert d_idx < a_idx
        # A must appear after B and C
        assert b_idx < a_idx
        assert c_idx < a_idx

    def test_complex_graph(self) -> None:
        """Multiple SCCs with DAG connections, correct reverse-topo order.

        Graph:
          E -> F -> G -> E  (SCC: {E, F, G})
          A -> B -> C -> A  (SCC: {A, B, C})
          A -> E             (DAG edge from {A,B,C} to {E,F,G})
          D (isolated)       (SCC: {D})
        """
        graph: dict[str, set[str]] = {
            "A": {"B", "E"},
            "B": {"C"},
            "C": {"A"},
            "D": set(),
            "E": {"F"},
            "F": {"G"},
            "G": {"E"},
        }
        sccs = compute_sccs(graph)
        assert len(sccs) == 3

        # Find which SCC contains which nodes
        efg_idx = _scc_index(sccs, "E")
        abc_idx = _scc_index(sccs, "A")

        assert sccs[efg_idx] == {"E", "F", "G"}
        assert sccs[abc_idx] == {"A", "B", "C"}

        # {E,F,G} is a callee of {A,B,C}, so it must appear first
        assert efg_idx < abc_idx

    def test_empty_graph(self) -> None:
        """Empty graph returns empty result."""
        graph: dict[str, set[str]] = {}
        sccs = compute_sccs(graph)
        assert sccs == []

    def test_single_node_self_loop(self) -> None:
        """A->A forms one SCC {A}."""
        graph: dict[str, set[str]] = {
            "A": {"A"},
        }
        sccs = compute_sccs(graph)
        assert len(sccs) == 1
        assert sccs[0] == {"A"}
