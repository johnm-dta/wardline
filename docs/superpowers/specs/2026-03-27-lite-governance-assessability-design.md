# Lite Governance Assessability

**Date:** 2026-03-27
**Status:** Draft
**Spec requirements:** WL-FIT-MAN-007, WL-FIT-MAN-009, WL-FIT-MAN-010, WL-FIT-MAN-011
**Normative sources:** Part I §14.3.2 (Governance profiles), §9.3 (Scope of governance), §13.1.1 (Root manifest schema), §14.6.2 (Worked example)

## Problem

The self-hosting repo has the *tools* for Lite governance but not the *evidence*. An assessor running the Lite governance checklist (§14.3.2) would fail four items:

1. **WL-FIT-MAN-007 (PARTIAL):** Ratification age machinery exists in `regime.py`, but `wardline.yaml` has no `ratified_by`, `ratification_date`, or `review_interval_days`. The regime verify `ratification_current` check silently passes when metadata is absent — it only checks for overdue, not for missing.
2. **WL-FIT-MAN-009 (PARTIAL):** `.github/CODEOWNERS` covers `wardline.yaml`, overlays, corpus, and baselines. Missing: `wardline.exceptions.json` (exception register) and `wardline.fingerprint.json` (fingerprint baseline).
3. **WL-FIT-MAN-010 (PARTIAL):** Fingerprint tooling (`wardline fingerprint update/diff`) exists and is tested. The governance posture connecting it to the Lite profile isn't declared.
4. **WL-FIT-MAN-011 (FAIL):** No temporal-separation declaration anywhere. An assessor cannot determine whether the project enforces temporal separation or uses the permitted Lite alternative.

## Design

### 1. `wardline.yaml` — ratification metadata

Add the three missing fields to the existing `metadata` section:

```yaml
metadata:
  organisation: "wardline"
  ratified_by:
    name: "John"
    role: "Project Lead"
  ratification_date: "2026-03-27"
  review_interval_days: 180
```

These fields already exist in the `ManifestMetadata` model and the `wardline.schema.json` — they just need values in the self-hosting manifest.

### 2. `wardline.yaml` — temporal separation declaration

Add `temporal_separation` inside the `metadata` block, matching the spec's worked example shape (§14.6.2):

```yaml
metadata:
  organisation: "wardline"
  ratified_by:
    name: "John"
    role: "Project Lead"
  ratification_date: "2026-03-27"
  review_interval_days: 180
  temporal_separation:
    alternative: "same-actor-with-retrospective"
    retrospective_window_days: 10
    rationale: >
      Single-developer project. Same-actor approval permitted for
      enforcement artefact changes with mandatory retrospective review
      within 10 business days. Policy artefact changes (tier definitions,
      boundary declarations, restoration provenance) require different-actor
      review per §9.3.1.
```

**Field semantics:**
- `alternative` — either `"same-actor-with-retrospective"` or absent (meaning enforced)
- `retrospective_window_days` — required when `alternative` is present
- `rationale` — required when `alternative` is present; free-text justification

When `temporal_separation` is absent from metadata, the manifest is declaring that temporal separation is enforced. This is the default posture — no declaration needed for the common case.

### 3. Schema change — `wardline.schema.json`

Add `temporal_separation` to the `metadata` properties (currently has `additionalProperties: false`, so this must be explicit):

```json
"temporal_separation": {
  "type": "object",
  "description": "Temporal separation posture declaration (§14.3.2). Absent means enforced.",
  "properties": {
    "alternative": {
      "type": "string",
      "enum": ["same-actor-with-retrospective"],
      "description": "The alternative to full temporal separation."
    },
    "retrospective_window_days": {
      "type": "integer",
      "minimum": 1,
      "description": "Maximum days before retrospective review must occur."
    },
    "rationale": {
      "type": "string",
      "description": "Free-text justification for the alternative."
    }
  },
  "required": ["alternative", "retrospective_window_days", "rationale"],
  "additionalProperties": false
}
```

All three fields are required when the object is present. When temporal separation is enforced, the entire `temporal_separation` object is simply omitted.

### 4. Model change — `ManifestMetadata`

Add a new frozen dataclass and field:

```python
@dataclass(frozen=True)
class TemporalSeparation:
    """Temporal separation alternative declaration (§14.3.2)."""

    alternative: str = "same-actor-with-retrospective"
    retrospective_window_days: int = 10
    rationale: str = ""
```

Add to `ManifestMetadata`:

```python
@dataclass(frozen=True)
class ManifestMetadata:
    organisation: str = ""
    ratified_by: MappingProxyType[str, str] | None = None
    ratification_date: str | None = None
    review_interval_days: int | None = None
    temporal_separation: TemporalSeparation | None = None  # NEW
```

`None` means enforced (the default). Present means a documented alternative.

### 5. Loader change — build `TemporalSeparation` from parsed data

In `loader.py`, when building `ManifestMetadata`, extract the `temporal_separation` sub-object:

```python
ts_data = meta_data.get("temporal_separation")
temporal_separation = None
if ts_data is not None:
    temporal_separation = TemporalSeparation(
        alternative=ts_data["alternative"],
        retrospective_window_days=ts_data["retrospective_window_days"],
        rationale=ts_data["rationale"],
    )
```

No additional loader-level validation needed beyond what the schema enforces — the schema already requires all three fields when the object is present.

### 6. `.github/CODEOWNERS` — add missing governance artefact paths

Add exception register and fingerprint baseline:

```
# Exception register
wardline.exceptions.json           @wardline/maintainers

# Fingerprint baseline
wardline.fingerprint.json          @wardline/maintainers
```

These are the two governance artefacts not currently path-protected. Per Lite checklist item 2 (§14.3.2): "CODEOWNERS (or equivalent) protects wardline.yaml, overlay files, and the exception register."

### 7. Regime verify — add ratification presence check

The existing `ratification_current` check in `regime_cmd.py` silently passes when ratification metadata is absent (it only checks overdue). Add a separate `ratification_metadata_present` check:

```python
# Check 10: Ratification metadata present
has_ratification = (
    manifest_m.ratification_date is not None
    and manifest_m.review_interval_days is not None
)
if has_ratification:
    checks.append({
        "check": "ratification_metadata_present",
        "passed": True,
        "severity": "ERROR",
        "evidence": "Ratification date and review interval declared.",
    })
else:
    missing = []
    if manifest_m.ratification_date is None:
        missing.append("ratification_date")
    if manifest_m.review_interval_days is None:
        missing.append("review_interval_days")
    checks.append({
        "check": "ratification_metadata_present",
        "passed": False,
        "severity": "ERROR",
        "evidence": f"Missing ratification metadata: {', '.join(missing)}.",
    })
```

This check is ERROR severity — missing ratification metadata means the Lite checklist item 1 ("has a current ratification") is structurally unfulfillable, not just overdue.

### 8. Regime verify — add temporal separation check

Add a check for temporal separation posture declaration:

```python
# Check 11: Temporal separation declared
# For Lite: either enforced (no temporal_separation field) or
# alternative documented with rationale.
if governance_profile == "lite":
    # Lite allows documented alternative
    checks.append({
        "check": "temporal_separation_declared",
        "passed": True,
        "severity": "WARNING",
        "evidence": (
            "Temporal separation alternative documented."
            if manifest_m.temporal_separation_alternative is not None
            else "Temporal separation enforced (no alternative declared)."
        ),
    })
else:
    # Assurance requires enforcement, no alternatives
    has_ts_alt = manifest_m.temporal_separation_alternative is not None
    checks.append({
        "check": "temporal_separation_declared",
        "passed": not has_ts_alt,
        "severity": "ERROR",
        "evidence": (
            "Assurance profile does not permit temporal separation alternatives."
            if has_ts_alt
            else "Temporal separation enforced."
        ),
    })
```

Note: `manifest_m` is a `ManifestMetrics` object, not the manifest itself. We need to thread the `temporal_separation` field through. Options:

- **Option A:** Add `temporal_separation_declared: bool` to `ManifestMetrics` (computed in `collect_manifest_metrics()`)
- **Option B:** Pass the manifest model directly to the verify function

**Option A** is simpler and follows the existing pattern — `ManifestMetrics` already carries computed governance booleans like `ratification_overdue`.

Add to `ManifestMetrics`:

```python
temporal_separation_alternative: str | None = None  # None = enforced
```

Populate in `collect_manifest_metrics()`:

```python
temporal_separation_alternative = (
    meta.temporal_separation.alternative
    if meta.temporal_separation is not None
    else None
)
```

Then the regime verify check uses `manifest_m.temporal_separation_alternative`.

## Testing

### Unit tests — model

| Test | Assertion |
|------|-----------|
| `test_temporal_separation_defaults` | Default values match spec |
| `test_manifest_metadata_temporal_separation_none_means_enforced` | `None` is the default |
| `test_manifest_metadata_temporal_separation_round_trip` | Construct with values, read back |

### Unit tests — loader

| Test | Assertion |
|------|-----------|
| `test_load_manifest_with_temporal_separation` | Full manifest with temporal_separation loads |
| `test_load_manifest_without_temporal_separation` | Absent temporal_separation → `None` |
| `test_schema_rejects_unknown_alternative` | Schema validation fails for invalid enum |
| `test_schema_requires_all_ts_fields` | Missing `rationale` when `alternative` present → fail |

### Unit tests — regime verify

| Test | Assertion |
|------|-----------|
| `test_ratification_metadata_present_check_passes` | With date + interval → pass |
| `test_ratification_metadata_present_check_fails` | Without date → fail with ERROR |
| `test_temporal_separation_declared_lite_with_alternative` | Lite + alternative → pass |
| `test_temporal_separation_declared_lite_enforced` | Lite + no alternative → pass |
| `test_temporal_separation_declared_assurance_with_alternative` | Assurance + alternative → fail |

### Integration — self-hosting

| Test | Assertion |
|------|-----------|
| `test_self_hosting_manifest_validates` | `wardline manifest validate` succeeds |
| `test_self_hosting_regime_verify_passes` | All regime verify checks pass |

## Files Changed

| File | Change |
|------|--------|
| `wardline.yaml` | Add ratification metadata + temporal_separation |
| `.github/CODEOWNERS` | Add exception register + fingerprint baseline paths |
| `src/wardline/manifest/schemas/wardline.schema.json` | Add temporal_separation to metadata |
| `src/wardline/manifest/models.py` | Add `TemporalSeparation` dataclass, field on `ManifestMetadata` |
| `src/wardline/manifest/loader.py` | Build `TemporalSeparation` from parsed data |
| `src/wardline/manifest/regime.py` | Add `temporal_separation_alternative` to `ManifestMetrics` |
| `src/wardline/cli/regime_cmd.py` | Add ratification-presence + temporal-separation checks |
| `tests/unit/manifest/test_models.py` | TemporalSeparation tests |
| `tests/unit/manifest/test_loader.py` | Loader validation tests |
| `tests/unit/cli/test_regime_cmd.py` | Regime verify check tests |

## Non-goals

- **Assurance profile implementation** — Gap 5 is Lite only. Assurance requires structured fingerprint governance, per-cell precision gates, and full temporal separation with no alternatives.
- **Automated temporal-separation enforcement** — the spec says Lite MAY document the alternative. We document it. Automated enforcement (e.g., checking PR author vs approver) is an Assurance concern.
- **Ratification expiry CI gate** — regime verify surfaces staleness as a finding. Making it a CI gate is a project policy decision, not a spec requirement.
- **Annotation change tracking mechanism** — WL-FIT-MAN-010 requires annotation change *visibility*. The existing `wardline fingerprint diff` + CODEOWNERS on `wardline.fingerprint.json` provides this. No new mechanism needed.
