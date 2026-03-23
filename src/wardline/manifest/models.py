"""Manifest data models — frozen dataclasses for configuration objects.

All manifest models use ``@dataclass(frozen=True)`` because they are
loaded once at scan startup. Mutable manifests risk non-deterministic
behaviour across rules.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core.severity import GovernancePath

if TYPE_CHECKING:
    from wardline.core.severity import RuleId
    from wardline.core.taints import TaintState


@dataclass(frozen=True)
class ExceptionEntry:
    """A granted exception to a wardline rule finding."""

    id: str
    rule: str
    taint_state: str
    location: str
    exceptionability: str
    severity_at_grant: str
    rationale: str
    reviewer: str
    expires: str | None = None
    provenance: str | None = None
    agent_originated: bool | None = None
    ast_fingerprint: str = ""
    recurrence_count: int = 0
    governance_path: GovernancePath = GovernancePath.STANDARD
    last_refreshed_by: str | None = None
    last_refresh_rationale: str | None = None
    last_refreshed_at: str | None = None


@dataclass(frozen=True)
class FingerprintEntry:
    """Annotation fingerprint for baseline tracking."""

    qualified_name: str
    module: str
    decorators: tuple[str, ...]
    annotation_hash: str
    tier_context: int
    boundary_transition: str | None = None
    last_changed: str | None = None


@dataclass(frozen=True)
class TierEntry:
    """A tier declaration in the manifest."""

    id: str
    tier: int
    description: str = ""


@dataclass(frozen=True)
class ModuleTierEntry:
    """A module-level taint default."""

    path: str
    default_taint: str


@dataclass(frozen=True)
class DelegationGrant:
    """A delegation grant for exception authority."""

    path: str
    authority: str


@dataclass(frozen=True)
class DelegationConfig:
    """Delegation configuration."""

    default_authority: str = "RELAXED"
    grants: tuple[DelegationGrant, ...] = ()


@dataclass(frozen=True)
class RulesConfig:
    """Rules configuration — overrides to the default severity matrix."""

    overrides: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True)
class ManifestMetadata:
    """Manifest metadata — organisational and governance fields."""

    organisation: str = ""
    ratified_by: dict[str, str] | None = None
    ratification_date: str | None = None
    review_interval_days: int | None = None


@dataclass(frozen=True)
class BoundaryEntry:
    """A boundary declaration in an overlay."""

    function: str
    transition: str
    from_tier: int | None = None
    to_tier: int | None = None
    restored_tier: int | None = None
    provenance: dict[str, object] | None = None
    bounded_context: dict[str, object] | None = None
    overlay_scope: str = ""


@dataclass(frozen=True)
class ContractBinding:
    """Binds a named contract to implementing functions."""

    contract: str
    functions: tuple[str, ...]


@dataclass(frozen=True)
class WardlineManifest:
    """Root manifest — trust topology and governance policy."""

    tiers: tuple[TierEntry, ...] = ()
    rules: RulesConfig = field(default_factory=RulesConfig)
    delegation: DelegationConfig = field(default_factory=DelegationConfig)
    module_tiers: tuple[ModuleTierEntry, ...] = ()
    metadata: ManifestMetadata = field(default_factory=ManifestMetadata)


@dataclass(frozen=True)
class WardlineOverlay:
    """Overlay — local boundary declarations and rule tuning."""

    overlay_for: str = ""
    boundaries: tuple[BoundaryEntry, ...] = ()
    rule_overrides: tuple[dict[str, object], ...] = ()
    optional_fields: tuple[str, ...] = ()
    contract_bindings: tuple[ContractBinding, ...] = ()


class ScannerConfigError(Exception):
    """Raised when wardline.toml contains invalid configuration."""


# Known keys in the [wardline] section of wardline.toml.
_KNOWN_KEYS: frozenset[str] = frozenset({
    "target_paths",
    "exclude_paths",
    "enabled_rules",
    "disabled_rules",
    "default_taint",
    "analysis_level",
    "max_unknown_raw_percent",
    "allow_registry_mismatch",
    "allow_permissive_distribution",
})


@dataclass(frozen=True)
class ScannerConfig:
    """Scanner configuration loaded from ``wardline.toml``.

    Use the ``from_toml()`` factory to load and normalise from a file.
    The factory performs all post-load normalisation (path strings to
    ``pathlib.Path``, rule ID strings to ``RuleId`` enum, taint state
    tokens to ``TaintState`` enum) before constructing the frozen
    dataclass.
    """

    target_paths: tuple[Path, ...] = ()
    exclude_paths: tuple[Path, ...] = ()
    enabled_rules: tuple[RuleId, ...] = ()
    disabled_rules: tuple[RuleId, ...] = ()
    default_taint: TaintState | None = None
    analysis_level: int = 1
    max_unknown_raw_percent: float | None = None
    allow_registry_mismatch: bool = False
    allow_permissive_distribution: bool = False

    @classmethod
    def from_toml(cls, path: Path) -> ScannerConfig:
        """Load scanner config from a TOML file.

        Uses binary mode (``'rb'``) as required by ``tomllib``.
        Normalises paths, rule IDs, and taint state tokens.
        Raises ``ScannerConfigError`` for unknown keys or invalid values.
        """
        from wardline.core.severity import RuleId
        from wardline.core.taints import TaintState

        with open(path, "rb") as f:
            data = tomllib.load(f)

        wardline_section = data.get("wardline", data)

        # Validate: reject unknown keys
        unknown = set(wardline_section.keys()) - _KNOWN_KEYS
        if unknown:
            raise ScannerConfigError(
                f"unknown keys in wardline.toml: {sorted(unknown)}"
            )

        # Parse and validate target_paths — resolve relative to config
        # file's directory, not CWD, so paths work regardless of where
        # the user invokes ``wardline scan``.
        config_dir = path.resolve().parent
        target_paths = tuple(
            (config_dir / p).resolve() if not Path(p).is_absolute() else Path(p)
            for p in wardline_section.get("target_paths", [])
        )
        exclude_paths = tuple(
            (config_dir / p).resolve() if not Path(p).is_absolute() else Path(p)
            for p in wardline_section.get("exclude_paths", [])
        )

        # Parse and validate rule IDs
        enabled_rules: tuple[RuleId, ...] = ()
        for r in wardline_section.get("enabled_rules", []):
            try:
                enabled_rules = (*enabled_rules, RuleId(r))
            except ValueError:
                raise ScannerConfigError(
                    f"invalid rule ID in enabled_rules: {r!r}"
                ) from None

        disabled_rules: tuple[RuleId, ...] = ()
        for r in wardline_section.get("disabled_rules", []):
            try:
                disabled_rules = (*disabled_rules, RuleId(r))
            except ValueError:
                raise ScannerConfigError(
                    f"invalid rule ID in disabled_rules: {r!r}"
                ) from None

        # Parse and validate default_taint
        raw_taint = wardline_section.get("default_taint")
        default_taint: TaintState | None = None
        if raw_taint:
            try:
                default_taint = TaintState(raw_taint)
            except ValueError:
                raise ScannerConfigError(
                    f"invalid taint state: {raw_taint!r}"
                ) from None

        analysis_level = wardline_section.get("analysis_level", 1)

        # Parse max_unknown_raw_percent
        max_pct = wardline_section.get("max_unknown_raw_percent")
        if max_pct is not None:
            if not isinstance(max_pct, (int, float)):
                raise ScannerConfigError(
                    "max_unknown_raw_percent must be a number, "
                    f"got {type(max_pct).__name__}"
                )
            if max_pct < 0 or max_pct > 100:
                raise ScannerConfigError(
                    f"max_unknown_raw_percent must be 0-100, got {max_pct}"
                )

        return cls(
            target_paths=target_paths,
            exclude_paths=exclude_paths,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            default_taint=default_taint,
            analysis_level=analysis_level,
            max_unknown_raw_percent=max_pct,
            allow_registry_mismatch=bool(
                wardline_section.get("allow_registry_mismatch", False)
            ),
            allow_permissive_distribution=bool(
                wardline_section.get("allow_permissive_distribution", False)
            ),
        )
