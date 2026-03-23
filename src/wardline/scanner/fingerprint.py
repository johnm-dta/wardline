"""AST fingerprint computation for exception staleness detection.

Produces a 16-char hex SHA-256 fingerprint of a function's AST structure.
Rule-independent — any structural change invalidates ALL exceptions.
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

from wardline.scanner._scope import find_function_node


def compute_ast_fingerprint(file_path: Path, qualname: str) -> str | None:
    """Compute 16-char hex fingerprint for a function's AST structure.

    Includes Python version because ``ast.dump()`` can change between
    minor versions. Python upgrades require ``wardline exception refresh --all``.

    Returns None if the file can't be parsed or *qualname* is not found.
    """
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError):
        return None

    func_node = find_function_node(tree, qualname)
    if func_node is None:
        return None

    dump = ast.dump(func_node, include_attributes=False, annotate_fields=True)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    payload = f"{version}|{file_path}|{qualname}|{dump}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
