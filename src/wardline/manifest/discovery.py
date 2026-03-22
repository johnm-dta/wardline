"""Manifest and overlay discovery — upward walk with symlink safety.

discover_manifest walks upward from a start path to find wardline.yaml,
stopping at .git or Path.home(). discover_overlays finds overlay files
within allowed directories only (secure default).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wardline.manifest.models import WardlineManifest

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "wardline.yaml"
OVERLAY_FILENAME = "wardline.overlay.yaml"


class GovernanceError(Exception):
    """Raised when an overlay is found in an undeclared directory."""


class ManifestNotFoundError(Exception):
    """Raised when no wardline.yaml is found in the upward walk."""


def discover_manifest(start_path: Path) -> Path | None:
    """Walk upward from start_path to find wardline.yaml.

    Stops at the first ``.git`` directory (VCS root) or
    ``Path.home()`` (safety net). Tracks visited inodes to detect
    symlink cycles.

    Returns the path to wardline.yaml, or None if not found.
    Logs WARNING on symlink cycle detection.
    """
    current = start_path.resolve()
    home = Path.home().resolve()
    visited_inodes: set[int] = set()

    while True:
        # Symlink cycle detection via inode tracking
        try:
            inode = os.stat(current).st_ino
        except OSError:
            logger.warning("Cannot stat directory %s during manifest walk", current)
            return None

        if inode in visited_inodes:
            logger.warning(
                "Symlink cycle detected at %s during manifest discovery", current
            )
            return None
        visited_inodes.add(inode)

        # Check for manifest in current directory
        candidate = current / MANIFEST_FILENAME
        if candidate.is_file():
            return candidate

        # Stop conditions: .git directory or home directory
        if (current / ".git").exists():
            return None

        if current == home:
            return None

        # Move to parent
        parent = current.parent
        if parent == current:
            # Reached filesystem root
            return None
        current = parent


def discover_overlays(
    root: Path,
    manifest: WardlineManifest,
    overlay_paths: list[str] | None = None,
) -> list[Path]:
    """Discover overlay files within allowed directories.

    Secure default: when no ``overlay_paths`` is provided, only
    directories declared in ``manifest.module_tiers`` are searched.

    The ``"*"`` literal sentinel enables unrestricted discovery
    across the entire root tree.

    Raises ``GovernanceError`` for overlays found in undeclared
    locations (with corrective guidance in the message).

    Args:
        root: Project root directory to search under.
        manifest: Loaded manifest (for module_tiers paths).
        overlay_paths: Explicit overlay path allowlist. ``["*"]``
            for unrestricted. None uses module_tiers default.
    """
    # Determine allowed directories
    if overlay_paths is not None and "*" in overlay_paths:
        # Unrestricted — find all overlays under root
        return _find_all_overlays(root)

    # Build allowlist from overlay_paths or module_tiers (secure default)
    allowed_dirs = (
        {root / p for p in overlay_paths}
        if overlay_paths is not None
        else {root / mt.path for mt in manifest.module_tiers}
    )

    found: list[Path] = []
    all_overlays = _find_all_overlays(root)

    for overlay_path in all_overlays:
        overlay_dir = overlay_path.parent
        if _is_within_allowed(overlay_dir, allowed_dirs, root):
            found.append(overlay_path)
        else:
            raise GovernanceError(
                f"Overlay found in undeclared directory: {overlay_path}. "
                f"Either add '{overlay_dir.relative_to(root)}/' to "
                f"`module_tiers` in `wardline.yaml`, or add it to "
                f"`overlay_paths` if overlay discovery should extend "
                f"beyond `module_tiers` directories."
            )

    return found


def _is_within_allowed(
    overlay_dir: Path, allowed_dirs: set[Path], root: Path
) -> bool:
    """Check if overlay_dir is within any allowed directory."""
    resolved_dir = overlay_dir.resolve()
    for allowed in allowed_dirs:
        resolved_allowed = allowed.resolve()
        try:
            resolved_dir.relative_to(resolved_allowed)
            return True
        except ValueError:
            continue
    return False


def _find_all_overlays(root: Path) -> list[Path]:
    """Find all wardline.overlay.yaml files under root.

    Uses os.walk with followlinks=False for symlink safety.
    """
    found: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        if OVERLAY_FILENAME in filenames:
            found.append(Path(dirpath) / OVERLAY_FILENAME)
    return sorted(found)
