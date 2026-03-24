# Wardline Rust Migration Feasibility Study

**Date:** 2026-03-24
**Status:** Speculative research
**Context:** v0.3.0 just shipped (L3 call-graph taint, NewType tiers, governance CLI, SARIF metadata). This document explores what new features a Rust rewrite could unlock compared to the current Python implementation.

---

## Table of Contents

1. [Current Architecture Constraints](#1-current-architecture-constraints)
2. [New Capabilities: Things That Become Possible](#2-new-capabilities-things-that-become-possible)
3. [New Capabilities: Things That Become Practical](#3-new-capabilities-things-that-become-practical)
4. [Architectural Shifts: Fundamentally Different](#4-architectural-shifts-fundamentally-different)
5. [Feature Unlock Matrix](#5-feature-unlock-matrix)
6. [Recommended Migration Path](#6-recommended-migration-path)
7. [Appendix: Current Performance Profile](#appendix-a-current-performance-profile)
8. [Appendix: Current Type System Limitations](#appendix-b-current-type-system-limitations)
9. [Appendix: Current Static Analysis Limitations](#appendix-c-current-static-analysis-limitations)

---

## 1. Current Architecture Constraints

### Processing Model

The scanner engine (`scanner/engine.py`) is **entirely serial and single-threaded**. There is no parallelism at any layer:

- `ScanEngine.scan()` iterates targets sequentially via `os.walk`
- Each `.py` file is processed one at a time via `_scan_file()`
- Within each file, the three analysis passes (L1, L2, L3) run in strict sequence, then rules execute one by one
- No `concurrent.futures`, no `asyncio`, no `multiprocessing` anywhere in the scanner

### Performance Bounds

The sole performance target: **L3 self-hosting scan must complete in under 30 seconds** (`tests/integration/test_l3_performance.py`). No per-file budget, no throughput target, no memory cap.

### Analysis Levels

| Level | Scope | Complexity | Key Limitation |
|---|---|---|---|
| L1 — Function taint | Per-file, one AST walk | O(F + M) where F=functions, M=module_tier entries | Top-level imports only; conditional/dynamic imports invisible |
| L2 — Variable taint | Per-function forward pass | O(N x S) where N=tainted functions, S=body nodes | No fixed-point; dict copies at every branch; no cross-function flow |
| L3 — Call-graph taint | Per-file SCC + worklist | O(E + F^2) worst case per SCC | Intra-module only; cross-file calls all "unresolved" |

### Type System

- `Tier1`-`Tier4` are `NewType("TierN", object)` — **fully erased at runtime**
- `ValidatedRecord` is a `@runtime_checkable Protocol` — checks attribute **presence** only, not value validity
- Enforcement is opt-in via `WARDLINE_ENFORCE=1` global flag; `check_tier_boundary()` must be called manually
- Decorator metadata stored as mutable function attributes (`_wardline_groups`, `_wardline_tier_source`) — can be deleted, shadowed, or severed by any decorator in the chain

### Static Analysis

All 9 rules (PY-WL-001 through PY-WL-009) are **name-based pattern matchers on Python AST**:

- PY-WL-001 fires on any `.get(key, default)` regardless of receiver type
- PY-WL-006 fires on any method named `write` in a broad handler
- PY-WL-008 checks "rejection path" via syntactic name presence, not control flow reachability
- PY-WL-009 uses line numbers for "before/after" ordering, not actual execution paths

Cross-module analysis is deferred to "L4+" in the design docs. The callgraph approach spike measured only ~41% call-site resolution for cross-module analysis vs ~100% for intra-module.

---

## 2. New Capabilities: Things That Become Possible

### 2.1 Cross-Module Call-Graph Analysis (L4+)

Today's L3 is explicitly scoped to intra-module edges. The design docs note that cross-module analysis was deferred because Python's open-ended imports make it intractable at AST level, and even within a single module, L3 already needs a 30-second performance budget.

In Rust:

- `ruff_python_parser` (production-grade, powers the ruff linter) or `rustpython-parser` gives the same AST, but traversal is 50-100x faster with zero GC pressure
- A whole-project call graph becomes feasible: parse every `.py` file in parallel with `rayon`, build a cross-file adjacency map, run the same SCC + fixed-point algorithm across module boundaries
- This directly eliminates the two KFN patterns that required `analysis_level_required: 3` corpus annotations — `PY-WL-001-KFN-01` (cross-function default) and `PY-WL-004-KFN-01` (broad handler in imported module) would become structurally detectable

**Why Python can't do this:** The L3 convergence bound is `8 x |SCC|^2`. For a single-file SCC this is manageable, but for a whole-project SCC (many modules calling each other), the inner loop (rank comparison, lattice join) at Python interpreter speed makes this intractable. Rust's nanosecond-scale inner loop makes 1000-node SCCs feasible in milliseconds.

### 2.2 Type-Informed Rule Firing

Today every rule is name-based. A Rust-based scanner could:

- Integrate with `pyright`/`ruff` type stubs or LSP to resolve receiver types
- Only fire PY-WL-001 on actual `Mapping.get()` calls, eliminating false positives from unrelated `.get()` methods
- Only fire PY-WL-006 on actual `IO.write()` or `Logger.*()` calls

This is impractical in the current Python implementation because running mypy as a subprocess per file and correlating types back to AST nodes would blow the performance budget.

### 2.3 Incremental / Watch-Mode Scanning

A Rust binary can maintain a persistent in-memory file index with content hashes and only re-scan changed files. The current Python scanner has no caching between invocations — every `wardline scan` parses the entire target tree from scratch.

A Rust daemon could:

- Keep the cross-file call graph in memory
- Re-parse only changed files, update affected SCC components
- Deliver sub-second feedback on save
- Serve as an LSP diagnostic provider for editor integration

---

## 3. New Capabilities: Things That Become Practical

### 3.1 Parallel File Scanning

The engine has zero parallelism constructs. In Rust with `rayon`:

- File discovery + parsing: embarrassingly parallel
- L1 taint assignment: per-file, embarrassingly parallel
- L2 variable taint: per-function, embarrassingly parallel
- L3 call graph: per-SCC (after global graph construction), parallelizable across independent SCCs
- On an 8-core machine, the self-hosting scan drops from seconds to milliseconds

### 3.2 CI-Embedded Governance with Zero Install Cost

Today CI needs `uv`, Python 3.12, and the full `wardline[scanner]` dependency tree. A Rust binary is a single static executable:

- `wardline regime verify --gate` in CI adds ~10ms, not 2-3 seconds for Python startup
- Pre-commit hooks become viable (the current scanner is too slow for pre-commit on large repos)
- GitHub Action as a single binary download, no Python version matrix needed

### 3.3 SARIF as a Universal Governance Layer

Roughly half the command surface (manifest, exceptions, regime, coherence, fingerprint) is language-agnostic — pure data transformation on YAML/TOML/JSON. In Rust:

- Extract the governance layer as a standalone binary that consumes SARIF from any scanner (Semgrep, CodeQL, Bandit)
- The Python scanner becomes one of many frontends feeding into the wardline governance system
- This is the path to "wardline for Go", "wardline for TypeScript" — not by rewriting the rules, but by accepting SARIF and applying the tier/exception/regime model to any language's findings

---

## 4. Architectural Shifts: Fundamentally Different

### 4.1 Compile-Time Tier Safety Instead of Runtime Opt-In

Today's enforcement model:

- `_enforcement_enabled` global boolean, off by default
- `check_tier_boundary()` must be called manually at every boundary
- `ValidatedRecord` Protocol checks attribute presence, not value validity
- `NewType` tiers are erased at runtime — `Tier1(x)` is the identity function

In a Rust wardline SDK (for Rust projects being governed):

```rust
struct Tier1<T>(T);   // zero-cost newtype, NOT erased
struct Tier4<T>(T);   // distinct type at compile time

fn validate(raw: Tier4<String>) -> Result<Tier1<ValidatedEmail>, ValidationError> {
    // Tier4 is CONSUMED (moved), can't be reused
    let validated = parse_email(raw.0)?;
    Ok(Tier1(validated))
}

fn store(record: Tier1<ValidatedEmail>) { /* ... */ }
// store(Tier4("raw".into()))  <-- COMPILE ERROR, not a runtime check
```

The key shift: Python wardline **detects** tier violations after the fact (scan time or opt-in runtime). Rust wardline would **prevent** them at compile time. The tier model moves from "advisory with enforcement hooks" to "the type system won't let you write the bug."

### 4.2 Ownership Semantics for Taint Flow

Python's biggest structural blind spot: a `Tier4` value can be passed to ten different functions simultaneously, aliased through collections, stored in globals, and re-read later with no tracking. The L2 variable taint copies `dict(var_taints)` at every branch — expensive and still incomplete.

Rust's ownership model gives:

- **Move semantics**: a `Tier4<T>` value is consumed by the validation function — the caller can't accidentally use the raw value again
- **Borrow checker**: if a function borrows `&Tier4<T>`, it can read but not promote; only the owner can consume-and-promote
- **No hidden aliasing**: the compiler guarantees that tainted data isn't silently copied through shared references

This eliminates an entire class of false negatives that the Python scanner can never catch — data flow through aliasing, collection mutation, and re-reads from shared state.

### 4.3 Sealed Trait Implementations Instead of Structural Protocols

`ValidatedRecord` today is a structural protocol — any class with `_wardline_tier` and `_wardline_groups` attributes satisfies it, even if the values are garbage. In Rust:

```rust
pub(crate) trait ValidatedRecord: private::Sealed {
    fn tier(&self) -> AuthorityTier;
    fn groups(&self) -> &[GroupId];
}
```

Only types within the wardline crate can implement `Sealed`, so external types cannot falsely claim to be validated. A `#[derive(ValidatedRecord)]` proc-macro would enforce that the struct fields actually satisfy tier invariants at compile time.

### 4.4 Taint Lattice as Type-State Machine

The `taint_join` function computes least-upper-bounds over `TaintState`. In Rust this could be modeled as a type-level lattice (using const generics or phantom types), so that passing a `TaintState<EXTERNAL_RAW>` value to a function expecting `TaintState<AUDIT_TRAIL>` is a compile error, with the join only expressible through an explicit lattice-upcast operation that the type checker validates.

---

## 5. Feature Unlock Matrix

| Capability | Python Today | Rust Enables |
|---|---|---|
| Cross-module call graph (L4) | Impossible (perf + import model) | Feasible via parallel parsing + whole-project graph |
| Type-informed rule firing | Impossible without external type solver | Practical via pyright/ruff integration |
| Incremental watch-mode scanning | Impractical (no caching, slow startup) | Native with persistent in-memory index |
| Parallel file processing | Not implemented (serial, GIL) | Trivial with rayon |
| CI governance with zero install | 2-3s Python startup | Single static binary, ~10ms |
| Multi-language governance | Python-only scanner | SARIF-based universal governance layer |
| Compile-time tier safety | Runtime opt-in, erased NewTypes | Zero-cost newtypes, move semantics |
| Taint flow through ownership | Aliasing blind spots, dict copying | Ownership prevents hidden data flow |
| Sealed validation protocols | Structural (spoofable) | Sealed traits (compiler-enforced) |

---

## 6. Recommended Migration Path

### Phase 1: Governance Layer Extraction (High ROI, Low Risk)

Extract the language-agnostic governance layer as a Rust binary:

- **Manifest loading**: YAML/TOML parsing with schema validation and security guards (alias limits, file size). `serde` + `schemars` maps directly to the frozen dataclass model.
- **Exception register management**: JSON I/O with strict schema validation and lifecycle logic (add, refresh, expire, review, drift detection, recurrence tracking).
- **Regime / coherence checks**: All 8 coherence checks and 9 regime verify checks are pure data-structure comparisons. No AST or Python knowledge required.
- **SARIF consumption and emission**: The SARIF emitter is pure data transformation on frozen structs.
- **CLI surface**: `clap` replicates the Click surface. All config formats are language-agnostic.

This gives: CI speed, multi-language governance story, zero-install binary. The Python scanner remains as a frontend emitting SARIF.

### Phase 2: Scanner Acceleration (High ROI, Medium Risk)

Rewrite the scanner engine in Rust, consuming Python AST via `ruff_python_parser`:

- Parallel file discovery and parsing
- L1/L2/L3 taint in Rust with the same algorithm, 50-100x faster
- Cross-module call graph (L4) becomes feasible
- Incremental scanning with persistent file index

### Phase 3: Deep Analysis (High Value, High Effort)

- Type-informed rule firing via pyright/ruff type inference integration
- LSP diagnostic provider for editor integration
- Watch-mode daemon with sub-second feedback
- Rust SDK with compile-time tier safety for Rust projects

---

## Appendix A: Current Performance Profile

### Algorithmic Complexity by Level

**L1 — Function-level taint** (`scanner/taint/function_level.py`): O(F + M) per file. Single recursive AST walk. `resolve_module_default` does linear scan over `manifest.module_tiers` per file. One O(M log M) sort for most-specific path match.

**L2 — Variable-level taint** (`scanner/taint/variable_level.py`): O(N x S) where N = tainted functions, S = body size. One forward pass per function, no fixed-point. Dict copies (`dict(var_taints)`) at every control-flow branch — O(depth x V) allocator pressure for deeply nested functions.

**L3 — Call-graph taint** (`scanner/taint/callgraph_propagation.py`): Iterative Tarjan's SCC is O(V + E). Within each SCC, worklist worst case is O(N^3) per SCC (N^2 iterations, each doing O(N) callee lookups). Conservative convergence bound: `8 x |SCC|^2`. The lattice has 8 states, so practical convergence is fast.

### Known Redundancies

- Qualname map is built twice per L3 file (once for call-graph extraction, once for variable-level taint). No caching.
- `sorted()` calls throughout SCC processing for determinism add O(E log E) overhead.
- L1 `_walk_and_assign` and L2 `_resolve_expr` are still recursive (only `_qualnames.build_qualname_map` and `compute_sccs` were converted to iterative).

---

## Appendix B: Current Type System Limitations

### What Python's Type System Cannot Enforce for Tier Safety

1. **NewType is fully erased at runtime.** `Tier1(x)` is the identity function; no tier tag survives to runtime. `TIER_REGISTRY` is a separate side-channel needed purely because there is no runtime representation.

2. **Structural typing makes ValidatedRecord spoofable.** Any class with `_wardline_tier: int` and `_wardline_groups: tuple[int, ...]` attributes satisfies `isinstance(obj, ValidatedRecord)`, even with fabricated or invalid values.

3. **No tier propagation through data flow.** If code constructs a new dict from `Tier4` fields, the container has no tier label. The type system has no generic taint propagation; it is point-annotated.

4. **`_wardline_tier` on instances is not enforced by any owner.** `AuthoritativeField` enforces read-before-set but does not type-check what value is set. Direct `__dict__` writes bypass the descriptor entirely (documented limitation).

5. **No sealed/closed types.** Python cannot prevent a subclass from overriding `_wardline_tier` with an incompatible value.

6. **No affine/linear usage for trust-boundary crossing.** No way to express "this Tier4 value must be consumed by exactly one validation function before it can flow further."

7. **Decorator metadata is mutable function attributes.** `del fn._wardline_audit_critical` is legal. `functools.wraps` ordering is a documented footgun (`CRITICAL:` comment in `_base.py`). Severed `__wrapped__` chains silently hide all wardline attributes.

---

## Appendix C: Current Static Analysis Limitations

### What AST-Only Analysis Cannot Reason About

- **Type information**: Every pattern check is name-based or syntactic. No receiver type resolution.
- **Runtime dispatch**: Method calls through variables, `getattr(obj, method_name)()`, dispatch tables, and higher-order function arguments are all opaque.
- **Cross-module call edges**: L3 is intra-file only. Cross-file calls are all "unresolved."
- **`super()` resolution**: Requires MRO computation, which requires a complete class hierarchy — effectively cross-module.
- **Control flow and execution ordering**: PY-WL-009 uses line numbers for "before/after", not actual control flow paths. PY-WL-008's "rejection path" is syntactic name presence, not reachability.
- **Implicit data flow**: Attribute assignments (`self.data = raw_input`), collection mutations (`my_list.append(raw)`), and return values stored by callers are not tracked at L2.
- **Conditional imports**: Only `if TYPE_CHECKING:` is handled; other conditional imports are invisible.
- **Dynamic imports**: `importlib.import_module()` with non-literal arguments is silently skipped.
- **Re-export chains**: Module A re-exports a wardline decorator; Module B imports from A and gets `UNKNOWN_RAW` silently.

### False Negative Patterns Architecturally Hard to Fix in Python

| Pattern | Why It's Hard | Rust Equivalent |
|---|---|---|
| Aliased method calls (`getter = data.get; getter(...)`) | Requires data-flow + type info | Type-resolved call graph |
| Dynamic dispatch (`getattr(data, "get")(...)`) | Runtime string, generally undecidable | Trait objects have bounded dispatch |
| Cross-module hidden patterns | Requires whole-project call graph | Parallel cross-file analysis |
| Decorator-based taint laundering | Wrapper hides `@external_boundary` | Proc-macro generates sealed trait impl |
| Re-export chains | Import resolution across modules | Crate boundary analysis via `.rlib` |
