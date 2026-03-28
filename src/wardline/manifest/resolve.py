"""Boundary resolution — discover overlays, merge, collect overlay metadata.

Callers receive an opaque tuple of BoundaryEntry objects with
overlay_scope populated. The engine passes this to ScanContext.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING

from wardline.manifest.discovery import GovernanceError, discover_overlays
from wardline.manifest.loader import ManifestLoadError, ManifestPolicyError, load_overlay
from wardline.manifest.merge import merge
from wardline.manifest.scope import relative_path_within_scope

if TYPE_CHECKING:
    from pathlib import Path

    from wardline.manifest.models import (
        BoundaryEntry,
        ContractBinding,
        OptionalFieldEntry,
        WardlineManifest,
    )

logger = logging.getLogger(__name__)


def resolve_boundaries(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[tuple[BoundaryEntry, ...], tuple[Path, ...]]:
    """Discover overlays, merge each with *manifest*, return boundaries and overlay paths.

    Returns a two-tuple of ``(boundaries, overlay_paths)`` where *boundaries*
    contains all ``BoundaryEntry`` objects with ``overlay_scope`` populated and
    *overlay_paths* is the list of overlay files that were discovered.

    Error handling:
    - ``GovernanceError`` / ``ManifestWidenError``: propagate (policy violation).
    - I/O / parse errors from individual overlay files: log + skip.
    """
    overlay_paths = discover_overlays(root, manifest)

    all_boundaries: list[BoundaryEntry] = []
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except ManifestPolicyError:
            raise  # Policy violations (e.g. skip-promotion) must propagate
        except (ManifestLoadError, OSError) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        # Verify overlay_for matches actual file location
        overlay_dir = str(overlay_path.parent.relative_to(root))
        if not relative_path_within_scope(
            overlay_dir,
            overlay.overlay_for.rstrip("/"),
        ):
            raise GovernanceError(
                f"Overlay at {overlay_path} claims overlay_for='{overlay.overlay_for}' "
                f"but is located in '{overlay_dir}'"
            )

        # merge() is OUTSIDE the try — ManifestWidenError propagates
        resolved = merge(manifest, overlay)

        # Surface governance signals so they appear in verbose output.
        for signal in resolved.governance_signals:
            logger.warning("Governance signal [%s]: %s", overlay_path, signal)

        # Tag each boundary with the overlay's ABSOLUTE scope path
        scope = str((root / overlay.overlay_for).resolve())
        rel_overlay = str(overlay_path.relative_to(root))
        seen_functions: set[str] = set()
        for boundary in resolved.boundaries:
            if boundary.function in seen_functions:
                raise GovernanceError(
                    "Duplicate boundary declaration for function "
                    f"'{boundary.function}' in overlay '{rel_overlay}'"
                )
            seen_functions.add(boundary.function)
            scoped = replace(boundary, overlay_scope=scope, overlay_path=rel_overlay)
            all_boundaries.append(scoped)

    return tuple(all_boundaries), tuple(overlay_paths)


def resolve_optional_fields(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[OptionalFieldEntry, ...]:
    """Discover overlays and return optional-field declarations with scope."""
    overlay_paths = discover_overlays(root, manifest)

    all_optional_fields: list[OptionalFieldEntry] = []
    seen_fields: dict[tuple[str, str], OptionalFieldEntry] = {}
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except ManifestPolicyError:
            raise  # Policy violations (e.g. skip-promotion) must propagate
        except (ManifestLoadError, OSError) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        overlay_dir = str(overlay_path.parent.relative_to(root))
        if not relative_path_within_scope(
            overlay_dir,
            overlay.overlay_for.rstrip("/"),
        ):
            raise GovernanceError(
                f"Overlay at {overlay_path} claims overlay_for='{overlay.overlay_for}' "
                f"but is located in '{overlay_dir}'"
            )

        scope = str((root / overlay.overlay_for).resolve())
        rel_overlay = str(overlay_path.relative_to(root))
        for optional_field in overlay.optional_fields:
            scoped = replace(
                optional_field,
                overlay_scope=scope,
                overlay_path=rel_overlay,
            )
            key = (scoped.overlay_scope, scoped.field)
            existing = seen_fields.get(key)
            if existing is not None:
                if existing.approved_default != scoped.approved_default:
                    raise GovernanceError(
                        "Conflicting optional_fields declarations for "
                        f"field '{scoped.field}' in scope '{scoped.overlay_scope}': "
                        f"{existing.overlay_path} declares "
                        f"{existing.approved_default!r}, but {scoped.overlay_path} "
                        f"declares {scoped.approved_default!r}"
                    )
                raise GovernanceError(
                    "Duplicate optional_fields declaration for "
                    f"field '{scoped.field}' in scope '{scoped.overlay_scope}' "
                    f"across {existing.overlay_path} and {scoped.overlay_path}"
                )
            seen_fields[key] = scoped
            all_optional_fields.append(scoped)

    return tuple(all_optional_fields)


def resolve_contract_bindings(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[ContractBinding, ...]:
    """Discover overlays and return all contract binding declarations.

    Args:
        root: Manifest directory (root for overlay discovery).
        manifest: Loaded manifest model.

    Returns:
        All ``ContractBinding`` entries from discovered overlays.
    """
    overlay_paths = discover_overlays(root, manifest)

    all_bindings: list[ContractBinding] = []
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except ManifestPolicyError:
            raise  # Policy violations (e.g. skip-promotion) must propagate
        except (ManifestLoadError, OSError) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        overlay_dir = str(overlay_path.parent.relative_to(root))
        if not relative_path_within_scope(
            overlay_dir,
            overlay.overlay_for.rstrip("/"),
        ):
            raise GovernanceError(
                f"Overlay at {overlay_path} claims overlay_for='{overlay.overlay_for}' "
                f"but is located in '{overlay_dir}'"
            )

        all_bindings.extend(overlay.contract_bindings)

    return tuple(all_bindings)
