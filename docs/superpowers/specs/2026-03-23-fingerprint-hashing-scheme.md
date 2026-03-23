# Fingerprint Hashing Scheme — Design Note

**Date:** 2026-03-23
**Status:** Decision Record
**Context:** WP 2.3 (Full Governance CLI) needs a fingerprint hashing scheme
for `wardline fingerprint update/diff`. This note defines the scheme before
implementation starts.

## Decision

**Hash scope:** Per-function annotation fingerprint. The hash captures the
wardline decorator annotations on a function — not the function body, not
the signature, not the return type.

**Rationale:** The fingerprint answers "have the wardline governance
annotations changed?" — not "has the code changed?" (that's the AST
fingerprint from WP 1.4). Two distinct hashes serve two distinct purposes:

| Hash | Purpose | Changes when |
|------|---------|-------------|
| `ast_fingerprint` (WP 1.4) | Exception staleness detection | Function body changes structurally |
| `annotation_fingerprint` (WP 2.3) | Governance drift detection | Decorator annotations change |

## Algorithm

```
annotation_fingerprint = sha256(
    "{python_version}|{qualname}|{sorted_canonical_decorator_names}|{sorted_decorator_attrs}"
)[:16]
```

**Inputs:**
1. **Python version** (`major.minor`) — same rationale as AST fingerprint
2. **Qualname** — scopes the hash to the function
3. **Sorted canonical decorator names** — from the decorator registry
   (e.g., `["audit_critical", "external_boundary"]`). Sorted for determinism.
4. **Sorted decorator attributes** — the `_wardline_*` attrs on the function,
   serialized as sorted key=value pairs

**NOT included:**
- File path (intentionally — a function moved between files with the same
  annotations should have the same fingerprint)
- Function body / AST dump (that's the AST fingerprint's job)
- Non-wardline decorators (irrelevant to governance)

## Output Format

16-character hex string, same as AST fingerprint. Stored in
`wardline.fingerprint.json` as:

```json
{
  "qualified_name": "MyClass.handle",
  "module": "src/adapters/client.py",
  "decorators": ["external_boundary", "audit_critical"],
  "annotation_hash": "a1b2c3d4e5f67890",
  "tier_context": 4,
  "boundary_transition": "construction",
  "last_changed": "2026-03-23"
}
```

This matches the existing `FingerprintEntry` model in `models.py`.

## Diff Semantics

`wardline fingerprint diff` compares the current computed fingerprint against
the stored baseline. A change means the governance annotations on that
function have been modified — the function needs re-review against the
manifest's tier assignment.

## Implementation Notes

- Reuse `discover_annotations()` from `scanner/discovery.py` to get
  decorator metadata per function
- Reuse `_scope.py` for qualname resolution
- The fingerprint schema already exists: `schemas/fingerprint.schema.json`
- The `FingerprintEntry` model already exists in `models.py`
