"""Manifest coherence checks — cross-reference code annotations against boundaries.

Detects two classes of inconsistency:
- **Orphaned annotations**: functions with wardline decorators in code but no
  matching boundary declaration in any overlay.
- **Undeclared boundaries**: overlay boundary entries whose function name does
  not appear as a decorated function in code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wardline.manifest.models import BoundaryEntry
    from wardline.scanner.context import WardlineAnnotation


@dataclass(frozen=True)
class CoherenceIssue:
    """A single coherence check result."""

    kind: str
    function: str
    file_path: str
    detail: str


def check_orphaned_annotations(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Find decorated functions with no matching boundary declaration.

    Args:
        annotations: Annotation map from ``discover_annotations``, keyed
            by ``(file_path, qualname)``.
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per orphaned annotation (kind
        ``"orphaned_annotation"``).
    """
    declared_functions = frozenset(b.function for b in boundaries)
    issues: list[CoherenceIssue] = []

    for (file_path, qualname), annots in sorted(annotations.items()):
        if qualname not in declared_functions:
            decorator_names = ", ".join(a.canonical_name for a in annots)
            issues.append(
                CoherenceIssue(
                    kind="orphaned_annotation",
                    function=qualname,
                    file_path=file_path,
                    detail=(
                        f"Function '{qualname}' in {file_path} has wardline "
                        f"decorators ({decorator_names}) but no boundary "
                        f"declaration in any overlay."
                    ),
                )
            )

    return issues


def check_undeclared_boundaries(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Find boundary declarations with no matching decorated function in code.

    Args:
        annotations: Annotation map from ``discover_annotations``.
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per undeclared boundary (kind
        ``"undeclared_boundary"``).
    """
    # Collect all qualnames that have annotations
    annotated_functions = frozenset(qualname for _, qualname in annotations)
    issues: list[CoherenceIssue] = []

    for boundary in boundaries:
        if boundary.function not in annotated_functions:
            issues.append(
                CoherenceIssue(
                    kind="undeclared_boundary",
                    function=boundary.function,
                    file_path="",
                    detail=(
                        f"Boundary declaration for '{boundary.function}' "
                        f"(transition: {boundary.transition}) has no matching "
                        f"wardline-decorated function in code."
                    ),
                )
            )

    return issues
