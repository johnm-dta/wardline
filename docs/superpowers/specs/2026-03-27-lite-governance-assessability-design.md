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
- `alternative` — `"same-actor-with-retrospective"` or `"enforced"`
- `retrospective_window_days` — required when `alternative` is `"same-actor-with-retrospective"`
- `rationale` — required when `alternative` is `"same-actor-with-retrospective"`; free-text justification

When `temporal_separation` is absent from metadata, the posture is *undeclared* — an assessability gap. Projects SHOULD explicitly declare their posture. This prevents "absent" from silently meaning "enforced" — an assessor cannot distinguish "intentionally enforced" from "forgot to declare."

### 3. Schema change — `wardline.schema.json`

Add `temporal_separation` to the `metadata` properties (currently has `additionalProperties: false`, so this must be explicit):

```json
"temporal_separation": {
  "type": "object",
  "description": "Temporal separation posture declaration (§14.3.2).",
  "properties": {
    "alternative": {
      "type": "string",
      "enum": ["enforced", "same-actor-with-retrospective"],
      "description": "The declared posture: enforced or a named alternative."
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
  "required": ["alternative"],
  "additionalProperties": false
}
```

Only `alternative` is required at the schema level. `retrospective_window_days` and `rationale` are conditionally required — the loader validates that they are present when `alternative` is `"same-actor-with-retrospective"` and rejects them as noise when `alternative` is `"enforced"`.

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

`None` means undeclared (assessability gap). `TemporalSeparation(alternative="enforced")` means explicitly enforced. `TemporalSeparation(alternative="same-actor-with-retrospective", ...)` means documented alternative.

### 5. Loader change — build `TemporalSeparation` from parsed data

In `loader.py`, when building `ManifestMetadata`, extract the `temporal_separation` sub-object:

```python
ts_data = meta_data.get("temporal_separation")
temporal_separation = None
if ts_data is not None:
    alt = ts_data["alternative"]
    if alt == "same-actor-with-retrospective":
        # Conditional fields required for this alternative
        if "retrospective_window_days" not in ts_data:
            raise ManifestLoadError(
                "temporal_separation: retrospective_window_days required "
                "when alternative is same-actor-with-retrospective"
            )
        if not ts_data.get("rationale"):
            raise ManifestLoadError(
                "temporal_separation: rationale required "
                "when alternative is same-actor-with-retrospective"
            )
        temporal_separation = TemporalSeparation(
            alternative=alt,
            retrospective_window_days=ts_data["retrospective_window_days"],
            rationale=ts_data["rationale"],
        )
    elif alt == "enforced":
        # Enforced must not carry retrospective fields
        if "retrospective_window_days" in ts_data or "rationale" in ts_data:
            raise ManifestLoadError(
                "temporal_separation: retrospective_window_days and rationale "
                "must not be present when alternative is enforced"
            )
        temporal_separation = TemporalSeparation(alternative="enforced")
```

The loader enforces the conditional requirements that JSON Schema cannot express:
- `"same-actor-with-retrospective"` requires `retrospective_window_days` and non-empty `rationale`
- `"enforced"` must not carry those fields (they would be misleading noise)

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
    manifest_m.ratified_by_present
    and manifest_m.ratification_date is not None
    and manifest_m.review_interval_days is not None
)
if has_ratification:
    checks.append({
        "check": "ratification_metadata_present",
        "passed": True,
        "severity": "ERROR",
        "evidence": "Ratification authority, date, and review interval declared.",
    })
else:
    missing = []
    if not manifest_m.ratified_by_present:
        missing.append("ratified_by")
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

This check is ERROR severity — missing ratification metadata means the Lite checklist item 1 ("has a current ratification") is structurally unfulfillable, not just overdue. All three fields are required: `ratified_by` (the authority), `ratification_date` (when), and `review_interval_days` (how often).

Add `ratified_by_present: bool = False` to `ManifestMetrics`. Populate in `collect_manifest_metrics()`:

```python
ratified_by_present = meta.ratified_by is not None
```

### 8. Regime verify — add temporal separation check

Add a check for temporal separation posture declaration. The check must distinguish three states: explicitly declared alternative, explicitly declared enforced, and undeclared (assessability gap).

```python
# Check 11: Temporal separation declared
# temporal_separation_posture is one of:
#   "alternative:<name>" — documented alternative
#   "enforced"           — explicitly declared enforced
#   None                 — undeclared (assessability gap)
ts = manifest_m.temporal_separation_posture
if governance_profile == "lite":
    if ts is not None:
        checks.append({
            "check": "temporal_separation_declared",
            "passed": True,
            "severity": "WARNING",
            "evidence": (
                f"Temporal separation posture declared: {ts}."
            ),
        })
    else:
        checks.append({
            "check": "temporal_separation_declared",
            "passed": False,
            "severity": "WARNING",
            "evidence": (
                "Temporal separation posture not declared. "
                "Assessor cannot determine whether enforced or "
                "alternative applies. Add temporal_separation to "
                "manifest metadata."
            ),
        })
else:
    # Assurance requires enforcement, no alternatives
    if ts is not None and ts.startswith("alternative:"):
        checks.append({
            "check": "temporal_separation_declared",
            "passed": False,
            "severity": "ERROR",
            "evidence": (
                "Assurance profile does not permit temporal "
                "separation alternatives."
            ),
        })
    else:
        checks.append({
            "check": "temporal_separation_declared",
            "passed": ts == "enforced",
            "severity": "ERROR",
            "evidence": (
                "Temporal separation enforced."
                if ts == "enforced"
                else "Temporal separation posture not declared."
            ),
        })
```
```

### 9. Regime verify — add annotation change tracking check (MAN-010)

The Lite requirement (§14.3.2) is: "Changes to the annotation surface are flagged for human review. This MAY be implemented through VCS diff review." The assessable evidence is: `wardline.fingerprint.json` is CODEOWNERS-protected, so annotation-surface changes in PRs will require designated reviewer approval.

The spec allows Lite to satisfy this "through VCS diff review of annotation-bearing files rather than a full fingerprint baseline." This repo chooses the fingerprint baseline path as its Lite evidence mechanism — the baseline exists, CODEOWNERS protects it, and changes to it require review. Other Lite deployments may choose different evidence. The check below reflects this repo's chosen mechanism, not a framework-wide rule:


```python
# Check 12: Annotation change tracking
fingerprint_path = manifest_dir / "wardline.fingerprint.json"
if fingerprint_path.exists():
    checks.append({
        "check": "annotation_change_tracking",
        "passed": True,
        "severity": "WARNING",
        "evidence": "Fingerprint baseline present — annotation changes visible in diffs.",
    })
else:
    checks.append({
        "check": "annotation_change_tracking",
        "passed": False,
        "severity": "WARNING",
        "evidence": (
            "No fingerprint baseline found. Run 'wardline fingerprint update' "
            "to establish annotation change tracking."
        ),
    })
```

This is WARNING, not ERROR — Lite allows annotation tracking "through VCS diff review of annotation-bearing files rather than a full fingerprint baseline." But without even a baseline, there's no structured evidence of annotation-surface visibility.

Combined with the CODEOWNERS addition for `wardline.fingerprint.json` (§6), this makes MAN-010 assessable: the baseline exists, it's protected, and changes to it require review.

Note: `manifest_m` is a `ManifestMetrics` object, not the manifest itself. We need to thread the `temporal_separation` field through. Options:

- **Option A:** Add `temporal_separation_declared: bool` to `ManifestMetrics` (computed in `collect_manifest_metrics()`)
- **Option B:** Pass the manifest model directly to the verify function

**Option A** is simpler and follows the existing pattern — `ManifestMetrics` already carries computed governance booleans like `ratification_overdue`.

Add to `ManifestMetrics`:

```python
ratified_by_present: bool = False
temporal_separation_posture: str | None = None  # None = undeclared
```

Populate in `collect_manifest_metrics()`:

```python
ratified_by_present = meta.ratified_by is not None

temporal_separation_posture = None  # undeclared
if meta.temporal_separation is not None:
    alt = meta.temporal_separation.alternative
    if alt == "enforced":
        temporal_separation_posture = "enforced"
    else:
        temporal_separation_posture = f"alternative:{alt}"
```

Then the regime verify checks use `manifest_m.ratified_by_present` and `manifest_m.temporal_separation_posture`.

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
| `test_ratification_metadata_present_check_passes` | With ratified_by + date + interval → pass |
| `test_ratification_metadata_present_check_fails_missing_ratified_by` | Without ratified_by → fail with ERROR |
| `test_ratification_metadata_present_check_fails_missing_date` | Without date → fail with ERROR |
| `test_temporal_separation_declared_lite_with_alternative` | Lite + alternative → pass |
| `test_temporal_separation_declared_lite_enforced` | Lite + explicitly enforced → pass |
| `test_temporal_separation_declared_lite_undeclared` | Lite + absent → fail |
| `test_temporal_separation_declared_assurance_with_alternative` | Assurance + alternative → fail |
| `test_annotation_change_tracking_with_baseline` | Fingerprint baseline exists → pass |
| `test_annotation_change_tracking_no_baseline` | No baseline → fail with WARNING |

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
| `src/wardline/manifest/regime.py` | Add `ratified_by_present` and `temporal_separation_posture` to `ManifestMetrics` |
| `src/wardline/cli/regime_cmd.py` | Add ratification-presence + temporal-separation checks |
| `tests/unit/manifest/test_models.py` | TemporalSeparation tests |
| `tests/unit/manifest/test_loader.py` | Loader validation tests |
| `tests/unit/cli/test_regime_cmd.py` | Regime verify check tests |

## Non-goals

- **Assurance profile implementation** — Gap 5 is Lite only. Assurance requires structured fingerprint governance, per-cell precision gates, and full temporal separation with no alternatives.
- **Automated temporal-separation enforcement** — the spec says Lite MAY document the alternative. We document it. Automated enforcement (e.g., checking PR author vs approver) is an Assurance concern.
- **Ratification expiry CI gate** — regime verify surfaces staleness as a finding. Making it a CI gate is a project policy decision, not a spec requirement.
- **New annotation change tracking mechanism** — WL-FIT-MAN-010 is closed by the combination of fingerprint baseline existence check (§9) + CODEOWNERS protection (§6). No new tracking mechanism needed beyond existing `wardline fingerprint update/diff`.
