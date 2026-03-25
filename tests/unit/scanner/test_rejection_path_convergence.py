"""Tests for rejection path index expansion.

Exercises expand_rejection_index with various chain depths,
topologies, and safety bounds.
"""
from __future__ import annotations

import ast

from wardline.scanner._qualnames import build_qualname_map
from wardline.scanner.engine import expand_rejection_index
from wardline.scanner.import_resolver import build_import_alias_map


def _file_data(source: str, module_name: str) -> tuple:
    """Build a file_data tuple from source for testing."""
    tree = ast.parse(source)
    alias_map = build_import_alias_map(tree)
    qualname_map = build_qualname_map(tree)
    return (tree, alias_map, qualname_map, module_name)


class TestSingleRoundExpansion:
    """Default max_rounds=1 preserves two-hop behavior."""

    def test_two_hop_chain(self) -> None:
        """a() calls b() which has raise -> both in index at max_rounds=1."""
        source = "def a():\n    b()\n\ndef b():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.b"}), max_rounds=1)
        assert "mod.a" in result
        assert "mod.b" in result
        # converged=False because max_rounds=1 doesn't get a verification round
        assert not converged

    def test_two_hop_chain_converges_with_headroom(self) -> None:
        """With max_rounds=2, round 2 finds nothing → converged=True."""
        source = "def a():\n    b()\n\ndef b():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.b"}), max_rounds=2)
        assert "mod.a" in result
        assert "mod.b" in result
        assert converged

    def test_three_hop_limited_to_two(self) -> None:
        """a->b->c (c raises), max_rounds=1 -> b enters, a does NOT."""
        source = "def a():\n    b()\n\ndef b():\n    c()\n\ndef c():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.c"}), max_rounds=1)
        assert "mod.b" in result
        assert "mod.a" not in result
        assert not converged

    def test_empty_seed(self) -> None:
        """No seed -> no expansion, converged immediately."""
        source = "def a():\n    b()\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset(), max_rounds=1)
        assert result == frozenset()
        assert converged


class TestMultiRoundConvergence:
    """Deeper expansion when max_rounds > 1."""

    def test_three_hop_with_three_rounds(self) -> None:
        """a->b->c (c raises), max_rounds=3 -> all three, converged."""
        source = "def a():\n    b()\n\ndef b():\n    c()\n\ndef c():\n    raise ValueError('bad')\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.c"}), max_rounds=3)
        assert result == frozenset({"mod.a", "mod.b", "mod.c"})
        assert converged

    def test_four_hop_chain(self) -> None:
        """a->b->c->d (d raises), max_rounds=10 -> all four."""
        source = (
            "def a():\n    b()\n\ndef b():\n    c()\n\n"
            "def c():\n    d()\n\ndef d():\n    raise ValueError('bad')\n"
        )
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.d"}), max_rounds=10)
        assert result == frozenset({"mod.a", "mod.b", "mod.c", "mod.d"})
        assert converged

    def test_converges_at_fixed_point(self) -> None:
        """Unreachable function c stays out of index."""
        source = "def a():\n    b()\n\ndef b():\n    raise ValueError('bad')\n\ndef c():\n    pass\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.b"}), max_rounds=100)
        assert "mod.c" not in result
        assert result == frozenset({"mod.a", "mod.b"})
        assert converged

    def test_circular_calls_no_raise(self) -> None:
        """a<->b mutual recursion, neither raises -> neither in index."""
        source = "def a():\n    b()\n\ndef b():\n    a()\n"
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset(), max_rounds=10)
        assert result == frozenset()
        assert converged

    def test_diamond_call_graph(self) -> None:
        """a->b, a->c, b->d (raises), c->d -> all four in index."""
        source = (
            "def a():\n    b()\n    c()\n\ndef b():\n    d()\n\n"
            "def c():\n    d()\n\ndef d():\n    raise ValueError('bad')\n"
        )
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.d"}), max_rounds=10)
        assert result == frozenset({"mod.a", "mod.b", "mod.c", "mod.d"})
        assert converged

    def test_cross_file_with_imports(self) -> None:
        """Functions across files with import statements resolve transitively."""
        source_a = "from app.validators import validate\n\ndef handler():\n    validate()\n"
        source_b = "from app.checks import check\n\ndef validate():\n    check()\n"
        source_c = "def check():\n    raise ValueError('bad')\n"
        fd_a = _file_data(source_a, "app.views")
        fd_b = _file_data(source_b, "app.validators")
        fd_c = _file_data(source_c, "app.checks")
        result, converged = expand_rejection_index(
            [fd_a, fd_b, fd_c], frozenset({"app.checks.check"}), max_rounds=10
        )
        assert "app.validators.validate" in result
        assert "app.views.handler" in result
        assert converged

    def test_known_validator_as_seed_root(self) -> None:
        """External FQN in seed -> project callers expand from it."""
        source = "import jsonschema\n\ndef validate(data):\n    jsonschema.validate(data, {})\n"
        fd = _file_data(source, "myproject.validators")
        result, converged = expand_rejection_index(
            [fd], frozenset({"jsonschema.validate"}), max_rounds=10
        )
        assert "myproject.validators.validate" in result
        assert converged

    def test_dead_branch_call_does_not_expand(self) -> None:
        """Calls inside if False do not count as delegated rejection."""
        source = (
            "import jsonschema\n\n"
            "def validate(data):\n"
            "    if False:\n"
            "        jsonschema.validate(data, {})\n"
            "    return data\n"
        )
        fd = _file_data(source, "myproject.validators")
        result, converged = expand_rejection_index(
            [fd], frozenset({"jsonschema.validate"}), max_rounds=10
        )
        assert "myproject.validators.validate" not in result
        assert converged

    def test_bound_exceeded_returns_not_converged(self) -> None:
        """Chain of 12 hops, max_rounds=3 -> converged=False."""
        lines = []
        for i in range(12):
            if i < 11:
                lines.append(f"def f{i}():\n    f{i+1}()\n")
            else:
                lines.append(f"def f{i}():\n    raise ValueError('bad')\n")
        source = "\n".join(lines)
        fd = _file_data(source, "mod")
        result, converged = expand_rejection_index([fd], frozenset({"mod.f11"}), max_rounds=3)
        assert not converged
        assert "mod.f11" in result
        assert "mod.f10" in result
        assert "mod.f0" not in result

    def test_empty_file_data(self) -> None:
        """No files -> seed returned unchanged."""
        result, converged = expand_rejection_index([], frozenset({"ext.validate"}), max_rounds=10)
        assert result == frozenset({"ext.validate"})
        assert converged
