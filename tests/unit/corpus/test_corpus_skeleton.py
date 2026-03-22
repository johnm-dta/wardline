"""Tests for corpus skeleton structure (T-6.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

CORPUS_ROOT = Path(__file__).parent.parent.parent.parent / "corpus"
SCHEMA_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "src"
    / "wardline"
    / "manifest"
    / "schemas"
    / "corpus-specimen.schema.json"
)


class TestCorpusSkeleton:
    """Verify corpus directory structure and template validity."""

    def test_corpus_root_exists(self) -> None:
        assert CORPUS_ROOT.is_dir()

    def test_corpus_manifest_exists(self) -> None:
        assert (CORPUS_ROOT / "corpus_manifest.json").is_file()

    def test_specimens_directory_exists(self) -> None:
        assert (CORPUS_ROOT / "specimens").is_dir()

    @pytest.mark.parametrize("rule", [
        "PY-WL-001", "PY-WL-002", "PY-WL-003",
        "PY-WL-004", "PY-WL-005",
    ])
    def test_rule_directory_exists(self, rule: str) -> None:
        rule_dir = CORPUS_ROOT / "specimens" / rule
        assert rule_dir.is_dir()
        # Check taint state subdirectories
        assert (rule_dir / "EXTERNAL_RAW" / "positive").is_dir()
        assert (rule_dir / "EXTERNAL_RAW" / "negative").is_dir()
        assert (rule_dir / "UNKNOWN_RAW" / "positive").is_dir()
        assert (rule_dir / "UNKNOWN_RAW" / "negative").is_dir()

    def test_specimen_validates_against_schema(self) -> None:
        jsonschema = pytest.importorskip("jsonschema")

        # Use an actual specimen instead of the template
        specimen_path = (
            CORPUS_ROOT / "specimens" / "PY-WL-001"
            / "EXTERNAL_RAW" / "positive" / "PY-WL-001-TP-01.yaml"
        )
        assert specimen_path.is_file()

        with open(specimen_path) as f:
            specimen = yaml.safe_load(f)

        with open(SCHEMA_PATH) as f:
            schema = json.load(f)

        # Should not raise
        jsonschema.validate(specimen, schema)

    def test_corpus_manifest_is_valid_json(self) -> None:
        manifest_path = CORPUS_ROOT / "corpus_manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert "schema_version" in data
        assert "specimens" in data
        assert len(data["specimens"]) > 0
