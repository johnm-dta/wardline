"""Tests for call-graph taint trust order, least_trusted(), and call-graph extraction."""

from __future__ import annotations

import ast
import textwrap

from wardline.core.taints import TaintState
from wardline.scanner._qualnames import build_qualname_map
from wardline.scanner.taint.callgraph import TRUST_RANK, extract_call_edges, least_trusted


class TestTrustRank:
    def test_trust_rank_covers_all_states(self) -> None:
        """Every TaintState member has a rank in TRUST_RANK."""
        for state in TaintState:
            assert state in TRUST_RANK, f"{state} missing from TRUST_RANK"
        assert len(TRUST_RANK) == len(TaintState)


class TestLeastTrusted:
    def test_least_trusted_returns_less_trusted(self) -> None:
        """INTEGRAL vs EXTERNAL_RAW should return EXTERNAL_RAW."""
        result = least_trusted(TaintState.INTEGRAL, TaintState.EXTERNAL_RAW)
        assert result == TaintState.EXTERNAL_RAW

    def test_least_trusted_symmetric(self) -> None:
        """least_trusted(a, b) == least_trusted(b, a) for all 8x8 pairs."""
        for a in TaintState:
            for b in TaintState:
                assert least_trusted(a, b) == least_trusted(b, a), f"Not symmetric for ({a}, {b})"

    def test_least_trusted_identity(self) -> None:
        """least_trusted(a, a) == a for all states."""
        for state in TaintState:
            assert least_trusted(state, state) == state

    def test_mixed_raw_is_bottom(self) -> None:
        """MIXED_RAW vs any X should return MIXED_RAW (it is the least trusted)."""
        for state in TaintState:
            assert least_trusted(TaintState.MIXED_RAW, state) == TaintState.MIXED_RAW
            assert least_trusted(state, TaintState.MIXED_RAW) == TaintState.MIXED_RAW


# ── Helpers for extract_call_edges tests ─────────────────────────


def _parse_and_extract(source: str) -> tuple[dict[str, set[str]], dict[str, int], dict[str, int]]:
    """Parse source, build qualname map, and extract call edges."""
    tree = ast.parse(textwrap.dedent(source))
    qualname_map = build_qualname_map(tree)
    return extract_call_edges(tree, qualname_map)


# ── extract_call_edges tests ─────────────────────────────────────


class TestExtractCallEdges:
    def test_direct_call_resolved(self) -> None:
        """foo() where def foo exists at module level -> resolved edge."""
        adj, resolved, unresolved = _parse_and_extract("""\
            def foo():
                pass

            def bar():
                foo()
        """)
        assert "foo" in adj["bar"]
        assert resolved["bar"] == 1
        assert unresolved["bar"] == 0

    def test_self_method_resolved(self) -> None:
        """self.process() in a class method -> edge to ClassName.process."""
        adj, resolved, unresolved = _parse_and_extract("""\
            class MyClass:
                def process(self):
                    pass

                def run(self):
                    self.process()
        """)
        assert "MyClass.process" in adj["MyClass.run"]
        assert resolved["MyClass.run"] == 1
        assert unresolved["MyClass.run"] == 0

    def test_constructor_resolved(self) -> None:
        """MyClass() -> edge to MyClass.__init__ when __init__ exists."""
        adj, resolved, unresolved = _parse_and_extract("""\
            class MyClass:
                def __init__(self):
                    pass

            def create():
                MyClass()
        """)
        assert "MyClass.__init__" in adj["create"]
        assert resolved["create"] == 1

    def test_import_call_unresolved(self) -> None:
        """json.loads() -> no edge, unresolved count incremented."""
        adj, resolved, unresolved = _parse_and_extract("""\
            def parse_data():
                json.loads('{}')
        """)
        assert adj["parse_data"] == set()
        assert resolved["parse_data"] == 0
        assert unresolved["parse_data"] == 1

    def test_parameter_call_unresolved(self) -> None:
        """callback() where callback is a parameter -> no edge, unresolved."""
        adj, resolved, unresolved = _parse_and_extract("""\
            def run(callback):
                callback()
        """)
        assert adj["run"] == set()
        assert resolved["run"] == 0
        assert unresolved["run"] == 1

    def test_nested_function_call(self) -> None:
        """Inner function calling module-level function -> resolved."""
        adj, resolved, unresolved = _parse_and_extract("""\
            def helper():
                pass

            def outer():
                def inner():
                    helper()
                inner()
        """)
        # inner calls helper (module-level) -> resolved
        assert "helper" in adj["outer.inner"]
        assert resolved["outer.inner"] == 1
        # outer calls inner — inner is NOT module-level, so unresolved
        # (inner is nested, not in module_defs)
        assert unresolved["outer"] == 1

    def test_no_duplicate_edges(self) -> None:
        """Same call twice -> single edge (set semantics)."""
        adj, resolved, unresolved = _parse_and_extract("""\
            def target():
                pass

            def caller():
                target()
                target()
        """)
        assert adj["caller"] == {"target"}
        # Two resolved call sites
        assert resolved["caller"] == 2

    def test_resolved_unresolved_counts(self) -> None:
        """Correct counts for a mix of resolved and unresolved calls."""
        adj, resolved, unresolved = _parse_and_extract("""\
            def known():
                pass

            def mixed():
                known()
                unknown_func()
                known()
                another_unknown()
        """)
        assert adj["mixed"] == {"known"}
        assert resolved["mixed"] == 2
        assert unresolved["mixed"] == 2


class TestBuildQualnameMap:
    """Verify the shared iterative build_qualname_map produces correct results."""

    def test_module_level_function(self) -> None:
        tree = ast.parse("def foo(): pass")
        qmap = build_qualname_map(tree)
        qualnames = set(qmap.values())
        assert "foo" in qualnames

    def test_class_method(self) -> None:
        tree = ast.parse(textwrap.dedent("""\
            class Cls:
                def method(self):
                    pass
        """))
        qmap = build_qualname_map(tree)
        qualnames = set(qmap.values())
        assert "Cls.method" in qualnames

    def test_nested_function(self) -> None:
        tree = ast.parse(textwrap.dedent("""\
            def outer():
                def inner():
                    pass
        """))
        qmap = build_qualname_map(tree)
        qualnames = set(qmap.values())
        assert "outer" in qualnames
        assert "outer.inner" in qualnames
