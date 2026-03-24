"""Tests for wardline.scanner.fingerprint — AST fingerprint computation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from wardline.scanner.fingerprint import compute_ast_fingerprint

if TYPE_CHECKING:
    from pathlib import Path


class TestComputeAstFingerprint:
    def test_returns_16_char_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "foo")
        assert result is not None
        assert len(result) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", result)

    def test_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "foo") == compute_ast_fingerprint(f, "foo")

    def test_whitespace_same_fingerprint(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        fp1 = compute_ast_fingerprint(f, "foo")
        f.write_text("def foo():\n\n    return 1\n\n", encoding="utf-8")
        fp2 = compute_ast_fingerprint(f, "foo")
        assert fp1 == fp2

    def test_structural_change_different(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        fp1 = compute_ast_fingerprint(f, "foo")
        f.write_text("def foo():\n    x = 1\n    return x\n", encoding="utf-8")
        fp2 = compute_ast_fingerprint(f, "foo")
        assert fp1 != fp2

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        assert compute_ast_fingerprint(tmp_path / "nope.py", "foo") is None

    def test_nonexistent_qualname(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    pass\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "bar") is None

    def test_class_method(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("class C:\n    def m(self):\n        pass\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "C.m")
        assert result is not None and len(result) == 16

    def test_nested_function(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def outer():\n    def inner():\n        pass\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "outer.inner") is not None

    def test_syntax_error(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "broken") is None
