"""Tests for wardline.manifest.exceptions — exception register loading."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from wardline.manifest.exceptions import load_exceptions
from wardline.manifest.loader import ManifestLoadError

if TYPE_CHECKING:
    from pathlib import Path


def _write_exceptions(path: Path, entries: list[dict]) -> None:
    data = {
        "$id": "https://wardline.dev/schemas/0.1/exceptions.schema.json",
        "exceptions": entries,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _valid_entry(**overrides) -> dict:
    base = {
        "id": "EXC-001",
        "rule": "PY-WL-001",
        "taint_state": "EXTERNAL_RAW",
        "location": "src/adapters/client.py::Client.handle",
        "exceptionability": "STANDARD",
        "severity_at_grant": "ERROR",
        "rationale": "Schema fallback approved",
        "reviewer": "jsmith",
    }
    base.update(overrides)
    return base


class TestLoadExceptions:
    def test_file_not_found_returns_empty(self, tmp_path: Path) -> None:
        assert load_exceptions(tmp_path) == ()

    def test_valid_file_returns_entries(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert len(result) == 1
        assert result[0].id == "EXC-001"
        assert result[0].rule == "PY-WL-001"

    def test_missing_ast_fingerprint_defaults_empty(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert result[0].ast_fingerprint == ""

    def test_ast_fingerprint_preserved(self, tmp_path: Path) -> None:
        entry = _valid_entry(ast_fingerprint="abcdef0123456789")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        result = load_exceptions(tmp_path)
        assert result[0].ast_fingerprint == "abcdef0123456789"

    def test_invalid_schema_raises(self, tmp_path: Path) -> None:
        bad = {"$id": "https://wardline.dev/schemas/0.1/exceptions.schema.json", "exceptions": [{"bad": True}]}
        (tmp_path / "wardline.exceptions.json").write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ManifestLoadError):
            load_exceptions(tmp_path)

    def test_unconditional_cell_raises(self, tmp_path: Path) -> None:
        # PY-WL-001 with AUDIT_TRAIL is UNCONDITIONAL in the severity matrix
        entry = _valid_entry(rule="PY-WL-001", taint_state="AUDIT_TRAIL")
        _write_exceptions(tmp_path / "wardline.exceptions.json", [entry])
        with pytest.raises(ManifestLoadError, match="UNCONDITIONAL"):
            load_exceptions(tmp_path)

    def test_optional_fields_default(self, tmp_path: Path) -> None:
        _write_exceptions(tmp_path / "wardline.exceptions.json", [_valid_entry()])
        result = load_exceptions(tmp_path)
        assert result[0].recurrence_count == 0
        assert result[0].governance_path == "standard"
        assert result[0].expires is None
