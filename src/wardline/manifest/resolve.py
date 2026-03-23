"""Boundary resolution — discover overlays, merge, collect boundaries.

Callers receive an opaque tuple of BoundaryEntry objects with
overlay_scope populated. The engine passes this to ScanContext.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.manifest.discovery import discover_overlays
from wardline.manifest.loader import ManifestLoadError, load_overlay
from wardline.manifest.merge import merge

if TYPE_CHECKING:
    from wardline.manifest.models import BoundaryEntry, WardlineManifest

logger = logging.getLogger(__name__)


def resolve_boundaries(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[BoundaryEntry, ...]:
    """Discover overlays, merge each with *manifest*, return all boundaries.

    Error handling:
    - ``GovernanceError`` / ``ManifestWidenError``: propagate (policy violation).
    - I/O / parse errors from individual overlay files: log + skip.
    """
    overlay_paths = discover_overlays(root, manifest)

    all_boundaries: list[BoundaryEntry] = []
    for overlay_path in overlay_paths:
        try:
            overlay = load_overlay(overlay_path)
        except (ManifestLoadError, OSError) as exc:
            logger.warning("Failed to load overlay %s: %s", overlay_path, exc)
            continue

        # merge() is OUTSIDE the try — ManifestWidenError propagates
        resolved = merge(manifest, overlay)

        # Tag each boundary with the overlay's ABSOLUTE scope path
        scope = str((root / overlay.overlay_for).resolve())
        for boundary in resolved.boundaries:
            scoped = replace(boundary, overlay_scope=scope)
            all_boundaries.append(scoped)

    return tuple(all_boundaries)
