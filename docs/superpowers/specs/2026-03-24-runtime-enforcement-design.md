# Runtime Enforcement Hooks Design — WP 3.2

**Date:** 2026-03-24
**Status:** Draft
**Scope:** Opt-in runtime tier enforcement — automatic decorator stamping, explicit stamping API, checking functions, WardlineBase integration
**Target release:** v0.4.0
**Dependencies:** WP 2.2 (NewType migration — shipped), `core/tiers.py` (AuthorityTier — exists)

## Problem

The first implementation of WP 3.2 failed a 7-reviewer panel because:
1. The runtime model (`_wardline_tier: int`) was disconnected from the decorator model (`_wardline_tier_source: TaintState`)
2. `WardlineBase.__init__` broke cooperative MRO (no `super().__init__()`, no `*args/**kwargs`)
3. `check_subclass_tier_consistency` read a non-existent attribute (`_wardline_transition_from_tier`)
4. No audit logging before raising — violations left no trace
5. The `ValidatedRecord` Protocol was correct but nothing in the system produced conforming objects

## Design

### 1. Trust Model Bridge (`core/tiers.py`)

Codify the `TaintState → AuthorityTier` mapping as a frozen dict:

```python
TAINT_TO_TIER: MappingProxyType[TaintState, AuthorityTier] = MappingProxyType({
    TaintState.AUDIT_TRAIL: AuthorityTier.TIER_1,
    TaintState.PIPELINE: AuthorityTier.TIER_2,
    TaintState.SHAPE_VALIDATED: AuthorityTier.TIER_3,
    TaintState.UNKNOWN_SEM_VALIDATED: AuthorityTier.TIER_3,
    TaintState.UNKNOWN_SHAPE_VALIDATED: AuthorityTier.TIER_3,
    TaintState.EXTERNAL_RAW: AuthorityTier.TIER_4,
    TaintState.UNKNOWN_RAW: AuthorityTier.TIER_4,
    TaintState.MIXED_RAW: AuthorityTier.TIER_4,
})
```

Runtime assertion: `len(TAINT_TO_TIER) == len(TaintState)`. This is the single source of truth for the scanner↔runtime bridge. `MappingProxyType` prevents mutation.

**Output tier derivation from decorators:**
- `_wardline_transition` decorators (e.g., `@validates_shape`): output tier = `TAINT_TO_TIER[transition[1]]` (the "to" state)
- `_wardline_tier_source` decorators (e.g., `@external_boundary`): output tier = `TAINT_TO_TIER[tier_source]`
- Supplementary decorators (e.g., `@audit_critical`): no tier — not a trust boundary

### 2. Automatic Stamping (Decorator Path)

When enforcement is enabled, the decorator wrapper in `decorators/_base.py` gains a post-call hook:

```python
result = unwrapped(*args, **kwargs)
if _enforcement_enabled and result is not None:
    _try_stamp_tier(result, output_tier, output_groups, stamped_by)
return result
```

`_try_stamp_tier` sets three attributes via `setattr`:
- `_wardline_tier: int` — the AuthorityTier value (1-4)
- `_wardline_groups: tuple[int, ...]` — the decorator's group memberships
- `_wardline_stamped_by: str` — qualname of the function that produced this data

Succeeds for dicts, class instances, dataclasses — anything with `__dict__` or `setattr` support. Silently skips primitives (int, str, bytes, tuple, frozenset). No error, no warning on skip.

**Output tier is computed once at decorator construction time** — not per call. The decorator factory resolves `_wardline_transition[1]` or `_wardline_tier_source` via `TAINT_TO_TIER` when the decorator is applied. If no tier can be derived (supplementary decorators), auto-stamping is skipped entirely.

**Zero overhead when disabled:** The `_enforcement_enabled` check is a single module-level bool test. When `False`, no stamping code runs.

### 3. Explicit Stamping API

**`stamp_tier(obj, tier, *, groups=(), stamped_by="")`**

Sets `_wardline_tier`, `_wardline_groups`, `_wardline_stamped_by` on `obj` via `setattr`. Always stamps (no enforcement flag check — this is the "I know what I'm doing" API). Validates tier is 1-4 (raises `ValueError` otherwise). Raises `TypeError` if the object doesn't support attribute setting.

**`TierStamped`** — A frozen dataclass wrapper for any value:

```python
@dataclass(frozen=True)
class TierStamped:
    value: Any
    _wardline_tier: int
    _wardline_groups: tuple[int, ...] = ()
    _wardline_stamped_by: str = ""
```

Satisfies `ValidatedRecord` Protocol. A first-class primitive — "here's a standard envelope for tier-tagged data, use it wherever you want." Frozen because tier metadata should not be mutated after stamping.

**`unstamp(obj)`** — Returns `obj.value` if `TierStamped`, otherwise returns `obj`. Lets consuming code handle both stamped and unwrapped transparently.

### 4. Checking API

Both no-ops when enforcement is disabled.

**`check_tier_boundary(obj, *, expected_min_tier, context="")`**

Reads `_wardline_tier` from the object. Raises `TierViolationError` if:
- No `_wardline_tier` attribute
- Value is not an int in range 1-4
- Tier is less trusted than `expected_min_tier` (higher number = less trusted)

**Audit logging:** Logs at WARNING level BEFORE raising — every violation leaves a trace even if the exception is caught. Log includes: object type, expected tier, actual tier, context string, `_wardline_stamped_by` if present.

**`check_validated_record(obj)`**

Structural check — verifies the object has `_wardline_tier` (int, 1-4) and `_wardline_groups` (tuple or set of ints). Does NOT check tier level — just that metadata is present and well-typed. Post-`isinstance` type validation since `runtime_checkable` Protocol only checks attribute existence.

Also logs before raising.

**`TierViolationError(TypeError)`** — includes `obj`, `expected_tier`, `actual_tier` attributes. `TypeError` is the correct base class (contract violation at the type/protocol level).

### 5. WardlineBase Integration

**`__init__` — cooperative, with enforcement:**

```python
def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)  # cooperative MRO first
    from wardline.runtime.enforcement import enforce_construction
    enforce_construction(self)
```

`*args/**kwargs` + `super().__init__()` ensures the MRO chain works for any multi-inheritance pattern. Enforcement runs AFTER the full init chain completes, so the instance is fully constructed.

**`enforce_construction(instance)`** — When enabled, checks tier consistency across decorated methods. Uses the REAL decorator attributes:
- Reads `_wardline_tier_source` (a `TaintState`) from each decorated method
- Maps to `AuthorityTier` via `TAINT_TO_TIER`
- Reads `_wardline_transition` to find bridging decorators
- If methods span multiple tiers without transition decorators bridging them, logs WARNING

Does not raise — mixed tiers in a class are a design smell, not necessarily a bug (a service class may legitimately have both ingest and read methods at different tiers).

### 6. ValidatedRecord Protocol (unchanged shape)

```python
@runtime_checkable
class ValidatedRecord(Protocol):
    @property
    def _wardline_tier(self) -> int: ...

    @property
    def _wardline_groups(self) -> tuple[int, ...]: ...
```

The protocol shape is correct as-is. The problem was that nothing produced conforming objects — now both automatic stamping and explicit `stamp_tier()`/`TierStamped` do.

`_wardline_stamped_by` is NOT part of the Protocol — optional audit metadata.

### 7. Enable/Disable

```python
# Programmatic
import wardline.runtime.enforcement
wardline.runtime.enforcement.enable()

# Environment variable (checked at import time)
WARDLINE_ENFORCE=1
```

**Thread safety:** `enable()`/`disable()` are startup configuration, not runtime toggles. Document this explicitly: "Call `enable()` once at application startup before spawning threads. Concurrent `enable()`/`disable()` during active checks is unsupported." This matches `logging.basicConfig()` and similar Python stdlib setup patterns.

### 8. Testing Strategy

**Trust model bridge:**
- `test_taint_to_tier_covers_all_states` — every TaintState maps to a tier
- `test_taint_to_tier_frozen` — MappingProxyType, mutation raises TypeError

**Automatic stamping:**
- `test_decorator_stamps_return_dict` — `@validates_shape` returns dict → `_wardline_tier=3`
- `test_decorator_stamps_return_instance` — class instance gets stamped
- `test_decorator_skips_primitives` — int/str return, no error, no stamp
- `test_decorator_no_stamp_when_disabled` — enforcement off, no stamping
- `test_stamped_by_records_qualname` — `_wardline_stamped_by` is function qualname
- `test_supplementary_decorator_no_stamp` — `@audit_critical` doesn't stamp

**Explicit API:**
- `test_stamp_tier_sets_attributes` — `stamp_tier(obj, 2)` sets `_wardline_tier=2`
- `test_stamp_tier_validates_range` — tier 0 or 5 raises ValueError
- `test_stamp_tier_raises_on_frozen` — frozen dataclass raises TypeError
- `test_tier_stamped_wrapper` — `TierStamped(value, tier=3)` satisfies ValidatedRecord
- `test_tier_stamped_frozen` — mutation raises
- `test_unstamp_returns_value` — unwraps TierStamped, passes through non-wrapped

**Checking:**
- `test_check_tier_boundary_passes` — tier 1, expected_min_tier=2 → OK
- `test_check_tier_boundary_fails` — tier 4, expected_min_tier=1 → TierViolationError
- `test_check_tier_boundary_no_tier` — no attribute → raises
- `test_check_tier_boundary_logs_before_raise` — caplog captures WARNING before error
- `test_check_validated_record_accepts_set_groups` — _wardline_groups as set (not just tuple)
- `test_check_noop_when_disabled` — all checks no-ops when off

**WardlineBase:**
- `test_init_cooperative_mro` — `class C(WardlineBase, SomeMixin)` construction works
- `test_init_with_args` — `super().__init__(*args, **kwargs)` passes through
- `test_enforce_construction_uses_real_attrs` — reads `_wardline_tier_source`, not `_wardline_transition_from_tier`
- `test_enforce_construction_warns_mixed_tiers` — class with tier 1 and tier 4 methods → WARNING

**Environment:**
- `test_wardline_enforce_env_var` — monkeypatch + importlib.reload → enabled at import

### 9. Files Changed

| File | Change |
|---|---|
| `core/tiers.py` | Add `TAINT_TO_TIER` mapping |
| `decorators/_base.py` | Add post-call stamping hook (enforcement-gated) |
| `runtime/enforcement.py` | Rewrite: stamping functions, checking functions, construction enforcement |
| `runtime/base.py` | Fix `__init__` (cooperative MRO + enforcement) |
| `runtime/protocols.py` | Unchanged (protocol shape is correct) |
| `runtime/__init__.py` | Export `stamp_tier`, `TierStamped`, `unstamp`, `enable`, `disable`, `is_enabled` |
| `tests/unit/runtime/test_enforcement.py` | Rewrite with ~30 tests |
| `tests/unit/core/test_tiers.py` | Add TAINT_TO_TIER tests |
