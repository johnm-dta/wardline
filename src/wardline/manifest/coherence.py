"""Manifest coherence checks — cross-reference code annotations against boundaries.

Detects multiple classes of inconsistency:
- **Orphaned annotations**: functions with wardline decorators in code but no
  matching boundary declaration in any overlay.
- **Undeclared boundaries**: overlay boundary entries whose function name does
  not appear as a decorated function in code.
- **Unmatched contracts**: bounded_context contract declarations that don't
  match any code-level annotation.
- **Stale contract bindings**: contract_bindings entries pointing to
  non-existent functions.
- **Tier-topology consistency**: tier assignments consistent with declared
  data-flow topology.
- **Governance anomalies**: tier distribution, tier downgrades, upgrade without
  evidence, agent-originated policy changes, expired exceptions, and first-scan
  perimeter detection.
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from wardline.manifest.models import (
        BoundaryEntry,
        ContractBinding,
        ExceptionEntry,
        ModuleTierEntry,
        TierEntry,
    )
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


# ── Governance anomaly checks ─────────────────────────────────────


def check_tier_distribution(
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
    *,
    max_permissive_percent: float = 60.0,
) -> list[CoherenceIssue]:
    """Check if permissive tiers (3+4) exceed the allowed threshold.

    Args:
        tiers: Tier definitions from the manifest.
        module_tiers: Module-tier assignments.
        max_permissive_percent: Maximum allowed percentage of permissive
            tiers (tier >= 3). Default 60%.

    Returns:
        A GOVERNANCE WARNING if the threshold is exceeded.
    """
    if not module_tiers or not tiers:
        return []

    # Build a map from tier id to tier number.
    # ModuleTierEntry.default_taint references TierEntry.id (same namespace).
    tier_map: dict[str, int] = {t.id: t.tier for t in tiers}

    total = len(module_tiers)
    permissive = 0
    for mt in module_tiers:
        tier_num = tier_map.get(mt.default_taint)  # default_taint is a tier id reference
        if tier_num is not None and tier_num >= 3:
            permissive += 1

    pct = (permissive / total) * 100.0
    if pct > max_permissive_percent:
        return [
            CoherenceIssue(
                kind="tier_distribution",
                function="",
                file_path="",
                detail=(
                    f"Permissive tier distribution: {pct:.1f}% of modules are "
                    f"tier 3+ (threshold: {max_permissive_percent}%)."
                ),
            )
        ]
    return []


def check_tier_downgrades(
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
    baseline_path: Path,
) -> list[CoherenceIssue]:
    """Detect tier downgrades compared to a baseline.

    A downgrade is when a module's tier number increases (less restrictive).

    Args:
        tiers: Current tier definitions.
        module_tiers: Current module-tier assignments.
        baseline_path: Path to ``wardline.manifest.baseline.json``.

    Returns:
        GOVERNANCE WARNING for each downgraded module, or empty list
        if the baseline file does not exist.
    """
    if not baseline_path.exists():
        return []

    try:
        baseline_data = json.loads(baseline_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logging.getLogger("wardline").warning(
            "Cannot read baseline %s: %s — skipping tier downgrade check",
            baseline_path, exc,
        )
        return []
    baseline_modules: dict[str, str] = {
        entry["path"]: entry["default_taint"]
        for entry in baseline_data.get("module_tiers", [])
    }
    baseline_tiers: dict[str, int] = {
        entry["id"]: entry["tier"]
        for entry in baseline_data.get("tiers", [])
    }

    current_tier_map: dict[str, int] = {t.id: t.tier for t in tiers}

    issues: list[CoherenceIssue] = []
    for mt in module_tiers:
        if mt.path in baseline_modules:
            old_taint = baseline_modules[mt.path]
            old_tier = baseline_tiers.get(old_taint)
            new_tier = current_tier_map.get(mt.default_taint)
            if old_tier is not None and new_tier is not None and new_tier > old_tier:
                issues.append(
                    CoherenceIssue(
                        kind="tier_downgrade",
                        function="",
                        file_path=mt.path,
                        detail=(
                            f"Tier downgrade: module '{mt.path}' changed from "
                            f"tier {old_tier} to tier {new_tier}."
                        ),
                    )
                )
    return issues


def check_tier_upgrade_without_evidence(
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
    boundaries: tuple[BoundaryEntry, ...],
    baseline_path: Path,
) -> list[CoherenceIssue]:
    """Detect tier upgrades (stricter) without overlay boundary evidence.

    An upgrade is when a module's tier number decreases (more restrictive).
    If no boundary entry covers the upgraded module, a warning fires.

    Args:
        tiers: Current tier definitions.
        module_tiers: Current module-tier assignments.
        boundaries: All boundary entries from loaded overlays.
        baseline_path: Path to ``wardline.manifest.baseline.json``.

    Returns:
        GOVERNANCE WARNING for each upgrade without evidence.
    """
    if not baseline_path.exists():
        return []

    try:
        baseline_data = json.loads(baseline_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logging.getLogger("wardline").warning(
            "Cannot read baseline %s: %s — skipping tier upgrade check",
            baseline_path, exc,
        )
        return []
    baseline_modules: dict[str, str] = {
        entry["path"]: entry["default_taint"]
        for entry in baseline_data.get("module_tiers", [])
    }
    baseline_tiers: dict[str, int] = {
        entry["id"]: entry["tier"]
        for entry in baseline_data.get("tiers", [])
    }

    current_tier_map: dict[str, int] = {t.id: t.tier for t in tiers}

    # Collect boundary overlay scopes as evidence — these are absolute
    # paths that tell us which directory each boundary covers.
    boundary_scopes = frozenset(
        b.overlay_scope for b in boundaries if b.overlay_scope
    )

    issues: list[CoherenceIssue] = []
    for mt in module_tiers:
        if mt.path in baseline_modules:
            old_taint = baseline_modules[mt.path]
            old_tier = baseline_tiers.get(old_taint)
            new_tier = current_tier_map.get(mt.default_taint)
            if old_tier is not None and new_tier is not None and new_tier < old_tier:
                # Check if any boundary's overlay scope covers this module path.
                # Module paths are relative (e.g. "src/wardline/scanner"),
                # overlay scopes are absolute. A scope covers a module if
                # the scope path ends with the module path.
                module_prefix = mt.path.rstrip("/")
                has_evidence = any(
                    scope.endswith("/" + module_prefix)
                    or scope.endswith("/" + module_prefix + "/")
                    or scope == module_prefix
                    for scope in boundary_scopes
                )
                if not has_evidence:
                    issues.append(
                        CoherenceIssue(
                            kind="tier_upgrade_without_evidence",
                            function="",
                            file_path=mt.path,
                            detail=(
                                f"Tier upgrade without evidence: module "
                                f"'{mt.path}' changed from tier {old_tier} to "
                                f"tier {new_tier} but no overlay boundary "
                                f"covers this module."
                            ),
                        )
                    )
    return issues


def check_agent_originated_exceptions(
    exceptions: tuple[ExceptionEntry, ...],
) -> list[CoherenceIssue]:
    """Detect exceptions with unknown agent provenance.

    An exception with ``agent_originated=None`` (provenance unknown) fires
    a warning. Explicit ``True`` or ``False`` values are accepted.

    Args:
        exceptions: All exception entries from the manifest.

    Returns:
        GOVERNANCE WARNING for each exception with unknown provenance.
    """
    issues: list[CoherenceIssue] = []
    for exc in exceptions:
        if exc.agent_originated is None:
            issues.append(
                CoherenceIssue(
                    kind="agent_originated_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' has unknown agent provenance "
                        f"(agent_originated is null)."
                    ),
                )
            )
    return issues


def check_expired_exceptions(
    exceptions: tuple[ExceptionEntry, ...],
    *,
    max_exception_duration_days: int = 365,
    now: datetime.date | None = None,
) -> list[CoherenceIssue]:
    """Detect expired exceptions and far-future expiry dates.

    An exception fires a warning if:
    - Its ``expires`` date is in the past relative to ``now``.
    - Its ``expires`` date exceeds ``max_exception_duration_days`` from today,
      indicating a far-future expiry that circumvents the duration policy.

    Args:
        exceptions: All exception entries.
        max_exception_duration_days: Maximum allowed exception duration.
        now: Current date for clock injection (defaults to today).

    Returns:
        GOVERNANCE WARNING for each expired or far-future exception.
    """
    if now is None:
        now = datetime.date.today()

    max_expiry = now + datetime.timedelta(days=max_exception_duration_days)

    issues: list[CoherenceIssue] = []
    for exc in exceptions:
        if exc.expires is None:
            continue

        try:
            expiry_date = datetime.date.fromisoformat(exc.expires)
        except ValueError:
            issues.append(
                CoherenceIssue(
                    kind="expired_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' has invalid expires date "
                        f"'{exc.expires}' — cannot parse as ISO 8601."
                    ),
                )
            )
            continue

        if expiry_date < now:
            issues.append(
                CoherenceIssue(
                    kind="expired_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' expired on {exc.expires}."
                    ),
                )
            )
        elif expiry_date > max_expiry:
            issues.append(
                CoherenceIssue(
                    kind="expired_exception",
                    function="",
                    file_path=exc.location,
                    detail=(
                        f"Exception '{exc.id}' has far-future expiry "
                        f"{exc.expires} exceeding max_exception_duration_days "
                        f"({max_exception_duration_days})."
                    ),
                )
            )

    return issues


def check_first_scan_perimeter(
    perimeter_baseline_path: Path,
) -> list[CoherenceIssue]:
    """Emit GOVERNANCE INFO when no perimeter baseline exists (first scan).

    Args:
        perimeter_baseline_path: Path to ``wardline.perimeter.baseline.json``.

    Returns:
        GOVERNANCE INFO if the baseline file does not exist.
    """
    if not perimeter_baseline_path.exists():
        return [
            CoherenceIssue(
                kind="first_scan_perimeter",
                function="",
                file_path=str(perimeter_baseline_path),
                detail=(
                    "No perimeter baseline found. This appears to be a "
                    "first scan — perimeter listing will be generated."
                ),
            )
        ]
    return []


# ── Contract and topology coherence checks ────────────────────────


def check_unmatched_contracts(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    boundaries: tuple[BoundaryEntry, ...],
) -> list[CoherenceIssue]:
    """Find contract declarations in bounded_contexts with no matching annotation.

    For each boundary that declares a ``bounded_context`` with ``contracts``,
    verify the boundary's function has a matching annotation in code.  A
    contract declaration without a corresponding code-level annotation
    indicates a specification/implementation mismatch.

    Args:
        annotations: Annotation map from ``discover_annotations``, keyed
            by ``(file_path, qualname)``.
        boundaries: All boundary entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per unmatched contract (kind
        ``"unmatched_contract"``).
    """
    annotated_functions = frozenset(qualname for _, qualname in annotations)
    issues: list[CoherenceIssue] = []

    for boundary in boundaries:
        if boundary.bounded_context is None:
            continue

        contracts = boundary.bounded_context.get("contracts")
        if not contracts:
            continue

        if boundary.function not in annotated_functions:
            contract_names = ", ".join(
                c["name"] for c in contracts if isinstance(c, dict) and "name" in c
            )
            issues.append(
                CoherenceIssue(
                    kind="unmatched_contract",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares contracts "
                        f"({contract_names}) in bounded_context but has no "
                        f"matching wardline-decorated function in code."
                    ),
                )
            )

    return issues


def check_stale_contract_bindings(
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    contract_bindings: tuple[ContractBinding, ...],
) -> list[CoherenceIssue]:
    """Find contract_bindings entries pointing to non-existent functions.

    For each ``ContractBinding``, verify every function listed in
    ``functions`` exists as an annotated function in code.

    Args:
        annotations: Annotation map from ``discover_annotations``, keyed
            by ``(file_path, qualname)``.
        contract_bindings: All contract binding entries from loaded overlays.

    Returns:
        One ``CoherenceIssue`` per stale binding (kind
        ``"stale_contract_binding"``).
    """
    annotated_functions = frozenset(qualname for _, qualname in annotations)
    issues: list[CoherenceIssue] = []

    for binding in contract_bindings:
        for func_name in binding.functions:
            if func_name not in annotated_functions:
                issues.append(
                    CoherenceIssue(
                        kind="stale_contract_binding",
                        function=func_name,
                        file_path="",
                        detail=(
                            f"Contract binding '{binding.contract}' references "
                            f"function '{func_name}' which has no wardline-"
                            f"decorated function in code."
                        ),
                    )
                )

    return issues


def check_tier_topology_consistency(
    boundaries: tuple[BoundaryEntry, ...],
    tiers: tuple[TierEntry, ...],
    module_tiers: tuple[ModuleTierEntry, ...],
) -> list[CoherenceIssue]:
    """Verify tier assignments are consistent with declared data-flow topology.

    For each boundary that declares ``from_tier`` and/or ``to_tier``,
    verify the referenced tier numbers actually exist in the manifest's
    tier definitions.  Also checks that ``from_tier`` corresponds to a
    module tier assignment that feeds into the boundary's scope.

    Args:
        boundaries: All boundary entries from loaded overlays.
        tiers: Tier definitions from the manifest.
        module_tiers: Module-tier assignments.

    Returns:
        One ``CoherenceIssue`` per inconsistency (kind
        ``"tier_topology_inconsistency"``).
    """
    if not tiers:
        return []

    # Build set of valid tier numbers from manifest
    valid_tier_numbers = frozenset(t.tier for t in tiers)

    # Build a map from tier id to tier number
    tier_id_to_number: dict[str, int] = {t.id: t.tier for t in tiers}

    # Build a map from module path to tier number
    module_tier_map: dict[str, int] = {}
    for mt in module_tiers:
        tier_num = tier_id_to_number.get(mt.default_taint)
        if tier_num is not None:
            module_tier_map[mt.path] = tier_num

    issues: list[CoherenceIssue] = []

    for boundary in boundaries:
        # Check from_tier references a valid tier number
        if boundary.from_tier is not None and boundary.from_tier not in valid_tier_numbers:
            issues.append(
                CoherenceIssue(
                    kind="tier_topology_inconsistency",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares from_tier="
                        f"{boundary.from_tier} which is not a valid tier "
                        f"number in the manifest (valid: "
                        f"{sorted(valid_tier_numbers)})."
                    ),
                )
            )

        # Check to_tier references a valid tier number
        if boundary.to_tier is not None and boundary.to_tier not in valid_tier_numbers:
            issues.append(
                CoherenceIssue(
                    kind="tier_topology_inconsistency",
                    function=boundary.function,
                    file_path=boundary.overlay_path,
                    detail=(
                        f"Boundary '{boundary.function}' declares to_tier="
                        f"{boundary.to_tier} which is not a valid tier "
                        f"number in the manifest (valid: "
                        f"{sorted(valid_tier_numbers)})."
                    ),
                )
            )

        # Check that from_tier is consistent with the module tier feeding it.
        # The overlay_scope tells us which module this boundary lives in.
        if boundary.from_tier is not None and boundary.overlay_scope:
            for mod_path, mod_tier in module_tier_map.items():
                # Module path is relative (e.g. "src/wardline/scanner"),
                # overlay_scope is absolute.  Check if scope ends with
                # the module path.
                if (
                    boundary.overlay_scope.endswith("/" + mod_path)
                    or boundary.overlay_scope.endswith("/" + mod_path + "/")
                    or boundary.overlay_scope == mod_path
                ):
                    if mod_tier != boundary.from_tier:
                        issues.append(
                            CoherenceIssue(
                                kind="tier_topology_inconsistency",
                                function=boundary.function,
                                file_path=boundary.overlay_path,
                                detail=(
                                    f"Boundary '{boundary.function}' declares "
                                    f"from_tier={boundary.from_tier} but the "
                                    f"containing module '{mod_path}' has "
                                    f"tier {mod_tier}."
                                ),
                            )
                        )
                    break  # First match is sufficient

    return issues
