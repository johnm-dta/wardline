"""Tests for annotation fingerprint computation.

Covers: compute_annotation_fingerprint, compute_single_annotation_fingerprint,
batch_compute_fingerprints, artefact_class classification.
"""

from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING

from wardline.manifest.models import (
    CoverageReport,
    FingerprintEntry,
    ModuleTierEntry,
    TierEntry,
    WardlineManifest,
)

if TYPE_CHECKING:
    from pathlib import Path
from wardline.scanner.fingerprint import (
    batch_compute_fingerprints,
    compute_annotation_fingerprint,
    compute_single_annotation_fingerprint,
)


def _make_manifest(
    *,
    module_tiers: tuple[ModuleTierEntry, ...] = (),
    tiers: tuple[TierEntry, ...] = (),
) -> WardlineManifest:
    """Build a minimal manifest for testing."""
    return WardlineManifest(
        tiers=tiers,
        module_tiers=module_tiers,
    )


# Shared tier setup: tier 1 = "trusted", tier 4 = "untrusted"
_TIERS = (
    TierEntry(id="trusted", tier=1, description="Tier 1"),
    TierEntry(id="untrusted", tier=4, description="Tier 4"),
)


_DECORATED_SOURCE = """\
from wardline import external_boundary, integrity_critical

@external_boundary
def handle_request():
    pass

@integrity_critical
def log_event():
    pass

def plain_function():
    pass
"""


class TestComputeAnnotationFingerprint:
    def test_annotation_fingerprint_deterministic(self) -> None:
        """Same inputs produce the same hash."""
        fp1 = compute_annotation_fingerprint(
            "MyClass.handle", ["external_boundary", "integrity_critical"]
        )
        fp2 = compute_annotation_fingerprint(
            "MyClass.handle", ["external_boundary", "integrity_critical"]
        )
        assert fp1 == fp2
        assert len(fp1) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", fp1)

    def test_annotation_fingerprint_changes_on_decorator_change(self) -> None:
        """Different decorators produce different hashes."""
        fp1 = compute_annotation_fingerprint(
            "handle", ["external_boundary"]
        )
        fp2 = compute_annotation_fingerprint(
            "handle", ["external_boundary", "integrity_critical"]
        )
        assert fp1 != fp2

    def test_annotation_fingerprint_invariant_to_file_move(self) -> None:
        """Same qualname + decorators in different modules produce same hash.

        File path is deliberately excluded from the annotation fingerprint.
        """
        fp1 = compute_annotation_fingerprint(
            "MyClass.handle", ["external_boundary"]
        )
        fp2 = compute_annotation_fingerprint(
            "MyClass.handle", ["external_boundary"]
        )
        # Both calls use the same inputs (no file path involved) — same hash.
        assert fp1 == fp2

    def test_annotation_fingerprint_sorted_decorators(self) -> None:
        """Decorator order does not affect the hash."""
        fp1 = compute_annotation_fingerprint(
            "handle", ["integrity_critical", "external_boundary"]
        )
        fp2 = compute_annotation_fingerprint(
            "handle", ["external_boundary", "integrity_critical"]
        )
        assert fp1 == fp2

    def test_annotation_fingerprint_includes_python_version(self) -> None:
        """Python version is part of the hash payload.

        We verify by manually computing the expected hash with the version
        included and confirming it matches.
        """
        import hashlib

        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        qualname = "fn"
        decorators = "external_boundary"
        payload = f"{version}|{qualname}|{decorators}|"
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

        fp = compute_annotation_fingerprint(qualname, ["external_boundary"])
        assert fp == expected


class TestBatchComputeFingerprints:
    def test_batch_compute_produces_entries(self, tmp_path: Path) -> None:
        """batch_compute returns a list of FingerprintEntry for annotated functions."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "example.py").write_text(_DECORATED_SOURCE, encoding="utf-8")

        manifest = _make_manifest(
            tiers=_TIERS,
            module_tiers=(ModuleTierEntry(path=str(src), default_taint="untrusted"),),
        )

        entries, coverage = batch_compute_fingerprints(src, manifest)
        assert len(entries) == 2  # handle_request + log_event (plain_function excluded)
        qualnames = {e.qualified_name for e in entries}
        assert "handle_request" in qualnames
        assert "log_event" in qualnames

        for entry in entries:
            assert isinstance(entry, FingerprintEntry)
            assert len(entry.annotation_hash) == 16

    def test_batch_compute_includes_coverage(self, tmp_path: Path) -> None:
        """CoverageReport has correct counts."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "example.py").write_text(_DECORATED_SOURCE, encoding="utf-8")

        manifest = _make_manifest(
            tiers=_TIERS,
            module_tiers=(ModuleTierEntry(path=str(src), default_taint="untrusted"),),
        )

        entries, coverage = batch_compute_fingerprints(src, manifest)
        assert isinstance(coverage, CoverageReport)
        assert coverage.annotated == 2
        assert coverage.total == 3  # handle_request + log_event + plain_function
        assert 0.0 < coverage.ratio < 1.0
        assert abs(coverage.ratio - 2.0 / 3.0) < 1e-9


class TestArtefactClass:
    def test_artefact_class_policy_for_tier_decorators(self, tmp_path: Path) -> None:
        """Boundary/tier decorators (groups 1-4) classify as 'policy'."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "mod.py").write_text(
            "from wardline import external_boundary\n\n"
            "@external_boundary\n"
            "def ingress():\n"
            "    pass\n",
            encoding="utf-8",
        )

        manifest = _make_manifest(
            tiers=_TIERS,
            module_tiers=(ModuleTierEntry(path=str(src), default_taint="trusted"),),
        )

        entries, _ = batch_compute_fingerprints(src, manifest)
        assert len(entries) == 1
        assert entries[0].artefact_class == "policy"

    def test_artefact_class_enforcement_for_supplementary(self, tmp_path: Path) -> None:
        """Supplementary decorators (groups 5+) classify as 'enforcement'."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "mod.py").write_text(
            "from wardline import thread_safe\n\n"
            "@thread_safe\n"
            "def worker():\n"
            "    pass\n",
            encoding="utf-8",
        )

        manifest = _make_manifest(
            tiers=_TIERS,
            module_tiers=(ModuleTierEntry(path=str(src), default_taint="untrusted"),),
        )

        entries, _ = batch_compute_fingerprints(src, manifest)
        assert len(entries) == 1
        assert entries[0].artefact_class == "enforcement"


class TestSingleFunctionFingerprint:
    def test_single_function_fingerprint(self, tmp_path: Path) -> None:
        """compute_single_annotation_fingerprint returns entry for specific qualname."""
        f = tmp_path / "mod.py"
        f.write_text(_DECORATED_SOURCE, encoding="utf-8")

        manifest = _make_manifest(
            tiers=_TIERS,
            module_tiers=(ModuleTierEntry(path=str(tmp_path), default_taint="untrusted"),),
        )

        entry = compute_single_annotation_fingerprint(f, "handle_request", manifest)
        assert entry is not None
        assert entry.qualified_name == "handle_request"
        assert "external_boundary" in entry.decorators
        assert len(entry.annotation_hash) == 16
        assert entry.artefact_class == "policy"

        # Non-annotated function returns None
        none_entry = compute_single_annotation_fingerprint(f, "plain_function", manifest)
        assert none_entry is None

        # Non-existent function returns None
        missing = compute_single_annotation_fingerprint(f, "no_such_fn", manifest)
        assert missing is None
