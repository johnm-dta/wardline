"""YAML manifest loader with alias-bomb protection and schema validation.

Uses a SafeLoader subclass with alias-resolution counting to prevent
YAML bomb denial-of-service. All loading paths (manifest, overlay,
corpus) use this loader.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from wardline.manifest.models import (
    BoundaryEntry,
    ContractBinding,
    DelegationConfig,
    DelegationGrant,
    ManifestMetadata,
    ModuleTierEntry,
    RulesConfig,
    TierEntry,
    WardlineManifest,
    WardlineOverlay,
)

_SCHEMA_DIR = Path(__file__).parent / "schemas"

# Expected schema version — compared against document $id
EXPECTED_SCHEMA_VERSION = "0.1"

# File size limit: 1MB
MAX_FILE_SIZE = 1_048_576

# Alias limit defaults
DEFAULT_ALIAS_LIMIT = 1000
HARD_ALIAS_UPPER_BOUND = 10_000


class WardlineYAMLError(yaml.YAMLError):
    """Raised when YAML loading fails due to wardline-specific checks."""


class ManifestLoadError(Exception):
    """Raised when manifest loading fails (file size, schema, version)."""


def make_wardline_loader(
    alias_limit: int = DEFAULT_ALIAS_LIMIT,
) -> type[yaml.SafeLoader]:
    """Create a SafeLoader subclass with alias-resolution counting.

    PyYAML's SafeLoader does not accept constructor kwargs, so we use
    a factory that returns a configured subclass with the limit as a
    class attribute.

    Args:
        alias_limit: Maximum alias resolutions before raising.
            Capped at HARD_ALIAS_UPPER_BOUND to prevent threshold defeat.
    """
    effective_limit = min(alias_limit, HARD_ALIAS_UPPER_BOUND)

    class WardlineSafeLoader(yaml.SafeLoader):
        _alias_limit: int = effective_limit
        _alias_count: int = 0

        def compose_node(
            self, parent: Any, index: Any
        ) -> yaml.nodes.Node | None:
            if self.check_event(yaml.events.AliasEvent):  # type: ignore[no-untyped-call]
                self._alias_count += 1
                if self._alias_count > self._alias_limit:
                    raise WardlineYAMLError(
                        f"YAML alias limit exceeded ({self._alias_limit}). "
                        f"This may indicate a YAML bomb attack."
                    )
            return super().compose_node(parent, index)

    return WardlineSafeLoader


def _check_file_size(path: Path) -> None:
    """Raise ManifestLoadError if file exceeds MAX_FILE_SIZE."""
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ManifestLoadError(
            f"File {path} is {size} bytes, exceeding the "
            f"{MAX_FILE_SIZE} byte limit."
        )


def _check_schema_version(data: dict[str, Any], path: Path) -> None:
    """Check $id version against expected scanner version."""
    doc_id = data.get("$id", "")
    if doc_id and EXPECTED_SCHEMA_VERSION not in doc_id:
        raise ManifestLoadError(
            f"Manifest {path} targets schema version "
            f"'{doc_id}', this scanner bundles version "
            f"{EXPECTED_SCHEMA_VERSION} — update the manifest "
            f"or upgrade wardline."
        )


def _validate_schema(
    data: dict[str, Any], schema_name: str
) -> None:
    """Validate data against a named schema. Raises ManifestLoadError."""
    schema_path = _SCHEMA_DIR / schema_name
    schema = json.loads(schema_path.read_text())
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        raise ManifestLoadError(
            f"Schema validation failed: {e.message}"
        ) from e


def _load_yaml(path: Path, alias_limit: int = DEFAULT_ALIAS_LIMIT) -> Any:
    """Load a YAML file with alias-bomb protection.

    Uses yaml.load() with our SafeLoader subclass — NOT yaml.safe_load()
    which does not accept a Loader parameter.
    """
    _check_file_size(path)
    loader_cls = make_wardline_loader(alias_limit)
    with open(path) as f:
        return yaml.load(f, Loader=loader_cls)  # noqa: S506


def load_manifest(
    path: Path,
    alias_limit: int = DEFAULT_ALIAS_LIMIT,
) -> WardlineManifest:
    """Load and validate a wardline root manifest.

    Steps:
    1. File size check (1MB limit)
    2. YAML parse with alias-bomb protection
    3. $id version check
    4. Schema validation
    5. Dataclass construction
    """
    data = _load_yaml(path, alias_limit)
    if not isinstance(data, dict):
        raise ManifestLoadError(
            f"Manifest {path} must be a YAML mapping, got {type(data).__name__}"
        )

    _check_schema_version(data, path)
    _validate_schema(data, "wardline.schema.json")

    # Strip $id before constructing dataclass
    data.pop("$id", None)

    return _build_manifest(data)


def _build_manifest(data: dict[str, Any]) -> WardlineManifest:
    """Construct a WardlineManifest from validated data."""
    tiers = tuple(
        TierEntry(
            id=t["id"],
            tier=t["tier"],
            description=t.get("description", ""),
        )
        for t in data.get("tiers", [])
    )

    module_tiers = tuple(
        ModuleTierEntry(path=m["path"], default_taint=m["default_taint"])
        for m in data.get("module_tiers", [])
    )

    raw_delegation = data.get("delegation", {})
    delegation = DelegationConfig(
        default_authority=raw_delegation.get("default_authority", "RELAXED"),
        grants=tuple(
            DelegationGrant(path=g["path"], authority=g["authority"])
            for g in raw_delegation.get("grants", [])
        ),
    )

    raw_rules = data.get("rules", {})
    rules = RulesConfig(
        overrides=tuple(raw_rules.get("overrides", [])),
    )

    raw_meta = data.get("metadata", {})
    metadata = ManifestMetadata(
        organisation=raw_meta.get("organisation", ""),
        ratified_by=raw_meta.get("ratified_by"),
        ratification_date=raw_meta.get("ratification_date"),
        review_interval_days=raw_meta.get("review_interval_days"),
    )

    return WardlineManifest(
        tiers=tiers,
        rules=rules,
        delegation=delegation,
        module_tiers=module_tiers,
        metadata=metadata,
    )


def load_overlay(
    path: Path,
    alias_limit: int = DEFAULT_ALIAS_LIMIT,
) -> WardlineOverlay:
    """Load and validate a wardline overlay file."""
    data = _load_yaml(path, alias_limit)
    if not isinstance(data, dict):
        raise ManifestLoadError(
            f"Overlay {path} must be a YAML mapping, got {type(data).__name__}"
        )

    _check_schema_version(data, path)
    _validate_schema(data, "overlay.schema.json")

    data.pop("$id", None)

    return _build_overlay(data)


def _build_overlay(data: dict[str, Any]) -> WardlineOverlay:
    """Construct a WardlineOverlay from validated data."""
    boundaries = tuple(
        BoundaryEntry(
            function=b["function"],
            transition=b["transition"],
            from_tier=b.get("from_tier"),
            to_tier=b.get("to_tier"),
            restored_tier=b.get("restored_tier"),
            provenance=b.get("provenance"),
            bounded_context=b.get("bounded_context"),
        )
        for b in data.get("boundaries", [])
    )

    contract_bindings = tuple(
        ContractBinding(
            contract=cb["contract"],
            functions=tuple(cb["functions"]),
        )
        for cb in data.get("contract_bindings", [])
    )

    return WardlineOverlay(
        overlay_for=data.get("overlay_for", ""),
        boundaries=boundaries,
        rule_overrides=tuple(data.get("rule_overrides", [])),
        optional_fields=tuple(data.get("optional_fields", [])),
        contract_bindings=contract_bindings,
    )
