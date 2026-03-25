# mypy Tier Type Approach — Spike Decision

**Date:** 2026-03-23
**Status:** Decision Record
**Context:** WP 2.2 (mypy Plugin) — should tier types use `Annotated[Any, TierMarker]` or `NewType`?

## Recommendation: NewType (Approach B)

Use `NewType` for static checking. No mypy plugin needed.

## Findings

### Approach A: `Annotated[Any, TierMarker(N)]` (current)

- `Annotated[Any, TierMarker(1)]` resolves to `Any` — mypy sees no type information
- `x: Tier1 = fetch_tier4()` produces **NO error** without a custom plugin
- Plugin would need 150-300 lines of fragile mypy internals code
- **When plugin is NOT installed:** silent pass — users think they have safety but don't
- `Tier1[str]` parameterization requires additional generic alias complexity

### Approach B: `NewType` (recommended)

- `Tier1 = NewType("Tier1", object)` creates a distinct nominal type
- `x: Tier1 = fetch_tier4()` produces: `Incompatible types in assignment`
- `process(fetch_tier4())` produces: `Argument 1 has incompatible type "Tier4"; expected "Tier1"`
- **No plugin needed** — works with any standard mypy installation
- Explicit `Tier1(value)` construction = visible trust boundary crossing in code
- `Tier1[str]` not supported (acceptable — tiers are trust levels, not data shapes)

### Approach C: Hybrid (future option)

```python
# Static checking (mypy)
Tier1 = NewType("Tier1", object)

# Runtime introspection (scanner)
Tier1Annotated = Annotated[Tier1, TierMarker(1)]
```

Gives both static safety and runtime metadata. Consider if scanner needs
to read tier info from type annotations (currently it reads decorators).

## Comparison

| Criterion | Annotated[Any] | NewType |
|-----------|---------------|---------|
| mypy catches mismatches (no plugin) | NO | YES |
| Plugin required | Yes (150-300 LOC) | No |
| Failure when plugin absent | Silent pass | N/A |
| Runtime introspection | Yes | No (use hybrid) |
| Explicit construction | No | Yes (`Tier1(x)`) |
| Migration effort | None | Medium |

## Migration Path

1. Keep `TierMarker` for runtime introspection (scanner reads decorators, not types)
2. Change type aliases from `Annotated[Any, TierMarker(N)]` to `NewType("TierN", object)`
3. WP 2.2 scope shrinks dramatically — no plugin needed, just the type change + `ValidatedRecord` Protocol
4. If runtime introspection of type annotations is needed later, use hybrid approach

## Impact on WP 2.2

This decision **eliminates the need for a mypy plugin entirely** for tier mismatch detection.
WP 2.2 scope reduces to:
- Change type aliases to NewType
- Create `ValidatedRecord` Protocol in `runtime/protocols.py`
- Add integration tests for mypy catching tier mismatches
- Document the explicit construction pattern

Estimated effort drops from **L** to **S/M**.
