"""Tests for manifest coherence checks."""

from __future__ import annotations

from types import MappingProxyType

from wardline.manifest.coherence import (
    check_orphaned_annotations,
    check_undeclared_boundaries,
)
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import WardlineAnnotation


def _annot(name: str, group: int = 1) -> WardlineAnnotation:
    """Helper to create a WardlineAnnotation with minimal boilerplate."""
    return WardlineAnnotation(
        canonical_name=name,
        group=group,
        attrs=MappingProxyType({}),
    )


# ── Orphaned annotation tests ──────────────────────────────────────


class TestOrphanedAnnotations:
    """Tests for check_orphaned_annotations."""

    def test_no_orphans_when_all_declared(self) -> None:
        """All annotated functions have matching boundary declarations."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
            ("src/validate.py", "validate_input"): [_annot("validates_shape")],
        }
        boundaries = (
            BoundaryEntry(function="handle_request", transition="INGRESS"),
            BoundaryEntry(function="validate_input", transition="SHAPE_VALIDATE"),
        )
        issues = check_orphaned_annotations(annotations, boundaries)
        assert issues == []

    def test_orphan_detected(self) -> None:
        """Annotated function with no boundary declaration is flagged."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
        }
        boundaries: tuple[BoundaryEntry, ...] = ()
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].kind == "orphaned_annotation"
        assert issues[0].function == "handle_request"
        assert issues[0].file_path == "src/api.py"
        assert "external_boundary" in issues[0].detail

    def test_multiple_orphans(self) -> None:
        """Multiple orphaned annotations are all reported."""
        annotations = {
            ("src/a.py", "func_a"): [_annot("external_boundary")],
            ("src/b.py", "func_b"): [_annot("validates_shape")],
            ("src/c.py", "func_c"): [_annot("tier1_read")],
        }
        boundaries = (
            BoundaryEntry(function="func_b", transition="SHAPE_VALIDATE"),
        )
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 2
        orphan_names = {i.function for i in issues}
        assert orphan_names == {"func_a", "func_c"}

    def test_multiple_decorators_on_orphan(self) -> None:
        """All decorator names appear in the detail message."""
        annotations = {
            ("src/api.py", "handler"): [
                _annot("external_boundary"),
                _annot("validates_shape"),
            ],
        }
        boundaries: tuple[BoundaryEntry, ...] = ()
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 1
        assert "external_boundary" in issues[0].detail
        assert "validates_shape" in issues[0].detail

    def test_empty_inputs(self) -> None:
        """No annotations and no boundaries produces no issues."""
        issues = check_orphaned_annotations({}, ())
        assert issues == []

    def test_partial_match(self) -> None:
        """Only the unmatched annotation is flagged."""
        annotations = {
            ("src/a.py", "declared_fn"): [_annot("external_boundary")],
            ("src/b.py", "orphan_fn"): [_annot("validates_shape")],
        }
        boundaries = (
            BoundaryEntry(function="declared_fn", transition="INGRESS"),
        )
        issues = check_orphaned_annotations(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].function == "orphan_fn"


# ── Undeclared boundary tests ──────────────────────────────────────


class TestUndeclaredBoundaries:
    """Tests for check_undeclared_boundaries."""

    def test_no_undeclared_when_all_have_code(self) -> None:
        """All boundary functions have matching annotations in code."""
        annotations = {
            ("src/api.py", "handle_request"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(function="handle_request", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert issues == []

    def test_undeclared_detected(self) -> None:
        """Boundary with no matching annotation is flagged."""
        annotations: dict[tuple[str, str], list[WardlineAnnotation]] = {}
        boundaries = (
            BoundaryEntry(function="ghost_function", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert len(issues) == 1
        assert issues[0].kind == "undeclared_boundary"
        assert issues[0].function == "ghost_function"
        assert "ghost_function" in issues[0].detail
        assert "INGRESS" in issues[0].detail

    def test_multiple_undeclared(self) -> None:
        """Multiple undeclared boundaries are all reported."""
        annotations = {
            ("src/api.py", "real_fn"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(function="real_fn", transition="INGRESS"),
            BoundaryEntry(function="phantom_a", transition="SHAPE_VALIDATE"),
            BoundaryEntry(function="phantom_b", transition="EGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert len(issues) == 2
        undeclared_names = {i.function for i in issues}
        assert undeclared_names == {"phantom_a", "phantom_b"}

    def test_empty_inputs(self) -> None:
        """No annotations and no boundaries produces no issues."""
        issues = check_undeclared_boundaries({}, ())
        assert issues == []

    def test_boundary_matches_any_file(self) -> None:
        """Boundary function matches annotation regardless of file path."""
        annotations = {
            ("src/deep/nested/module.py", "handler"): [
                _annot("external_boundary")
            ],
        }
        boundaries = (
            BoundaryEntry(function="handler", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert issues == []

    def test_qualname_match(self) -> None:
        """Boundary function with class-qualified name matches annotation."""
        annotations = {
            ("src/api.py", "MyClass.handle"): [_annot("external_boundary")],
        }
        boundaries = (
            BoundaryEntry(function="MyClass.handle", transition="INGRESS"),
        )
        issues = check_undeclared_boundaries(annotations, boundaries)
        assert issues == []
