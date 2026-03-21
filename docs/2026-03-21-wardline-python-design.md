# Wardline for Python — Implementation Design

**Date:** 2026-03-21
**Status:** Draft (post-review revision — incorporates findings from 7-reviewer plan review: architecture, reality, quality, systems, Python, security, test suite)
**Parent specification:** Wardline Framework Specification v0.2.0 (Part I + Part II-A)

---

## 1. What We're Building

Wardline for Python is the reference implementation of the Wardline semantic boundary enforcement framework. It makes institutional security knowledge — which data is authoritative, where trust boundaries lie, which code paths must fail fast — machine-readable and enforceable through Python's existing decorator, type annotation, and AST infrastructure.

The implementation comprises five deliverable components, each mapping to a Wardline conformance profile:

| Component | Conformance Profile | Role |
|-----------|-------------------|------|
| Decorator library | Foundation | Metadata vocabulary — decorators that set `_wardline_*` attributes on callables |
| AST scanner | Wardline-Core | Enforcement engine — two-pass AST analysis with tier-aware severity grading |
| Manifest system | (shared) | Trust topology — YAML/JSON manifest loading, validation, merge |
| Governance CLI | Wardline-Governance | Orchestration — manifest validation, fingerprint, corpus, regime status |
| mypy plugin | Wardline-Type | Type-layer — tier metadata in `Annotated`, flow diagnostics |

All components ship as a single `wardline` Python package (Python 3.12+). The decorator library has zero non-stdlib dependencies. The scanner and CLI add `pyyaml`, `jsonschema`, and `click`.

**Package split trigger condition:** Split the decorator library into a separate `wardline-decorators` package (zero deps, `>=3.9` floor for `typing.Annotated`) when any downstream adopter needs decorators without accepting scanner dependencies (`pyyaml`, `jsonschema`, `click`). The `[project.optional-dependencies]` groups defined in Section 10 keep this split path open from day one.

**Python 3.12+ rationale:** The scanner requires `StrEnum` (3.11+) and uses `ast.Constant` as the canonical literal node (canonical since 3.8 when `ast.Num`/`ast.Str`/`ast.Bytes` were deprecated; the deprecated aliases were removed in 3.12, making `ast.Constant` the sole remaining form). The decorator library itself could work on 3.9+ but is bundled at the scanner's floor for MVP. If/when the package splits, the decorator library can drop to `>=3.9`.

## 2. Source Layout

```
wardline/
├── pyproject.toml
├── wardline.yaml                    # Wardline's own trust topology (self-hosting)
├── wardline.toml                    # Scanner operational config
├── docs/
│   └── 2026-03-21-wardline-python-design.md
├── src/
│   └── wardline/
│       ├── __init__.py              # Public API re-exports
│       ├── _version.py
│       │
│       ├── core/                    # Pure data model (no deps, no side effects)
│       │   ├── __init__.py
│       │   ├── tiers.py             # AuthorityTier enum (1–4)
│       │   ├── taints.py            # 8 TaintState values + join lattice
│       │   ├── severity.py          # Severity, Exceptionability enums
│       │   ├── matrix.py            # 9×8 severity matrix (72 cells: 9 Python binding rules × 8 taint states, includes WL-001 split into PY-WL-001/002)
│       │   └── registry.py          # Canonical decorator name registry (single source of truth for scanner + library)
│       │
│       ├── runtime/                 # Runtime enforcement machinery (imports core, has behavioural code)
│       │   ├── __init__.py
│       │   ├── types.py             # Tier markers (Annotated), FailFast
│       │   ├── descriptors.py       # AuthoritativeField descriptor
│       │   ├── base.py              # WardlineBase with __init_subclass__
│       │   └── protocols.py         # ValidatedRecord Protocol, trust-typed interfaces (WP-8, post-MVP — create when mypy plugin begins)
│       │
│       ├── decorators/              # Annotation vocabulary (imports core, not runtime)
│       │   ├── __init__.py          # Re-exports all decorators
│       │   ├── _base.py             # Decorator factory infrastructure
│       │   ├── authority.py         # Group 1: external_boundary, validates_shape, etc.
│       │   ├── audit.py             # Group 2: audit_critical
│       │   ├── plugin.py            # Group 3: system_plugin
│       │   ├── provenance.py        # Group 4: int_data
│       │   ├── schema.py            # Group 5: all_fields_mapped, output_schema, schema_default
│       │   ├── boundaries.py        # Groups 6, 16, 17: layer, trust_boundary, restoration
│       │   ├── safety.py            # Group 7: parse_at_init
│       │   ├── secrets.py           # Group 8: handles_secrets
│       │   ├── operations.py        # Groups 9–10: idempotent, atomic, fail_closed, etc.
│       │   ├── sensitivity.py       # Group 11: handles_pii, handles_classified
│       │   ├── determinism.py       # Group 12: deterministic, time_dependent
│       │   ├── concurrency.py       # Group 13: thread_safe, ordered_after
│       │   ├── access.py            # Group 14: requires_identity, privileged_operation
│       │   └── lifecycle.py         # Group 15: test_only, deprecated_by, feature_gated
│       │
│       ├── manifest/                # Trust topology system
│       │   ├── __init__.py
│       │   ├── loader.py            # YAML/JSON loading (yaml.safe_load only) + schema validation
│       │   ├── models.py            # Dataclass models for all manifest types
│       │   ├── merge.py             # Overlay merge (narrow-only invariant)
│       │   ├── coherence.py         # Manifest coherence checks
│       │   ├── discovery.py         # Walk upward to find wardline.yaml, find overlays
│       │   └── schemas/             # JSON Schema files (0.x — unstable until v1.0)
│       │       ├── wardline.schema.json
│       │       ├── overlay.schema.json
│       │       ├── exceptions.schema.json
│       │       └── fingerprint.schema.json
│       │
│       ├── scanner/                 # AST enforcement engine
│       │   ├── __init__.py
│       │   ├── engine.py            # Two-pass orchestrator
│       │   ├── discovery.py         # Decorator metadata discovery from AST
│       │   ├── context.py           # ScanContext, Finding dataclasses
│       │   ├── sarif.py             # SARIF v2.1.0 output
│       │   ├── rules/
│       │   │   ├── __init__.py
│       │   │   ├── base.py          # RuleBase + registration
│       │   │   ├── py_wl_001.py     # Dict key access with fallback default
│       │   │   ├── py_wl_002.py     # Attribute access with fallback default
│       │   │   ├── py_wl_003.py     # Existence-checking as structural gate
│       │   │   ├── py_wl_004.py     # Broad exception handlers
│       │   │   ├── py_wl_005.py     # Silent exception handling
│       │   │   ├── py_wl_006.py     # Audit writes in broad handlers (post-MVP)
│       │   │   ├── py_wl_007.py     # Runtime type-checking internal data (post-MVP)
│       │   │   ├── py_wl_008.py     # Validation with no rejection path (post-MVP)
│       │   │   └── py_wl_009.py     # Semantic without prior shape validation (post-MVP)
│       │   └── taint/
│       │       ├── __init__.py
│       │       └── function_level.py  # Level 1: per-function taint from decorator
│       │
│       └── cli/                     # Governance CLI
│           ├── __init__.py
│           ├── main.py              # Click entrypoint
│           ├── scan.py              # wardline scan
│           ├── manifest_cmds.py     # wardline manifest validate/coherence
│           ├── corpus_cmds.py       # wardline corpus verify
│           ├── fingerprint_cmds.py  # wardline fingerprint update/diff
│           ├── regime_cmds.py       # wardline regime status/verify
│           └── exception_cmds.py    # wardline exception add/expire/review
│
├── corpus/                          # Golden corpus
│   ├── corpus_manifest.yaml         # Maps specimens to expected (rule, taint, severity, verdict)
│   └── specimens/                   # Organised per spec: corpus/{rule}/{taint_state}/
│       ├── PY-WL-001/
│       │   ├── AUDIT_TRAIL/
│       │   │   ├── positive/        # True positives (should fire)
│       │   │   └── negative/        # True negatives (should not fire)
│       │   ├── EXTERNAL_RAW/
│       │   │   ├── positive/
│       │   │   └── negative/
│       │   └── ...
│       ├── PY-WL-002/
│       │   └── ...
│       └── ...
│
└── tests/
    ├── conftest.py
    ├── unit/
    │   ├── core/
    │   │   ├── test_tiers.py
    │   │   ├── test_taints.py       # Exhaustive lattice tests (all 28 pairs + 8 self-joins)
    │   │   └── test_matrix.py       # Independently-encoded expected values, not self-referential
    │   ├── runtime/
    │   │   ├── test_descriptors.py   # Including __dict__ bypass test (known residual)
    │   │   ├── test_base.py          # __init_subclass__ + metaclass compatibility
    │   │   └── test_types.py
    │   ├── decorators/
    │   │   └── test_decorators.py
    │   ├── manifest/
    │   │   ├── test_loader.py
    │   │   ├── test_merge.py
    │   │   └── test_coherence.py
    │   └── scanner/
    │       ├── test_discovery.py
    │       ├── test_rules.py        # Per-rule parameterised tests
    │       ├── test_taint.py
    │       ├── test_sarif.py
    │       └── test_registry_sync.py  # Bidirectional registry consistency
    └── integration/
        ├── test_scan_pipeline.py    # Full scan on fixture projects
        ├── test_determinism.py      # Run scanner twice, assert byte-identical SARIF
        └── test_self_hosting.py     # Wardline scans itself
```

**Note:** Post-MVP taint files (`variable_level.py`, `callgraph.py`) and post-MVP rule files (PY-WL-006 through PY-WL-009) are created only when work on those WPs begins. They do not appear as empty stubs in the MVP branch.

**Note:** The stub `main.py` at the repository root will be removed during WP-0 scaffolding.

## 3. Dependency Graph

```
Core Data Model  ──(no deps, pure data: enums, lattice, matrix, registry)
      │
      ├──────────────> Runtime  (imports core; behavioural: descriptors, base classes, protocols)
      │
      ├──────────────> Decorator Library  (imports core enums; does NOT import runtime)
      │
      ├──────────────> Manifest System   (imports core enums)
      │                      │
      └──> AST Scanner ──────┘  (imports core + manifest; reads decorator conventions from AST)
                │
                v
           CLI  (imports all above)
                │
                v
           Golden Corpus + Self-Hosting Gate
```

The scanner does NOT import the decorator library at runtime. It reads decorator names from AST nodes. This means the decorator library and scanner have no circular dependency — the scanner knows the decorator naming conventions, not their implementations.

**Soft coupling and bidirectional registry check:** The scanner depends on the decorator library's *naming conventions* even though it doesn't import the library. A canonical name registry in `core/registry.py` is the single source of truth for decorator identifiers (names, group numbers, expected arguments). Both the decorator library and the scanner reference this registry.

Version skew detection is **bidirectional**: at scan startup, the scanner checks that (a) every decorator name in its registry is present in the installed decorator library's export list, and (b) every wardline decorator the library exports is present in the scanner's registry. This prevents silent enforcement decay from renames — a renamed decorator that the scanner doesn't know about produces a non-zero exit code in strict mode (strict mode is the default; non-strict requires an explicit `--allow-registry-mismatch` flag), not silent false negatives. If the scanner encounters an unrecognised decorator starting with `@wardline` or `_wardline_*` in scanned code, it emits a WARNING-level finding.

**Runtime introspection path coverage:** The bidirectional registry check covers the scanner's AST-based decorator name lookup. There is a second metadata-reading path: `WardlineBase.__init_subclass__` traverses the `__wrapped__` chain to find `_wardline_*` attributes at runtime. Both paths must stay in sync with `core/registry.py`. The `test_registry_sync.py` test suite must verify both the scanner's registry lookup AND the runtime `__wrapped__` chain traversal against the same canonical registry.

## 4. Work Packages and Build Order

### WP-0: Project Scaffolding

**Goal:** Build infrastructure that every subsequent WP depends on.

- Restructure to `src/wardline/` layout
- Remove orphaned `main.py` from repo root
- Update `pyproject.toml`:
  - Build system: hatchling with src layout (including `[build-system]` table)
  - Dependencies: `pyyaml>=6.0`, `jsonschema>=4.20`, `click>=8.1`
  - Optional dependency groups: `scanner`, `cli`, `dev` (see Section 10)
  - Dev dependencies: `pytest>=8.0`, `pytest-cov`, `mypy>=1.8`, `ruff>=0.4`
  - Entry point: `wardline = "wardline.cli.main:cli"`
- Configure ruff and mypy in `pyproject.toml`
- Create package `__init__.py` files
- Verify `uv run pytest` works with an empty test
- **Automated `yaml.safe_load()` enforcement:** Add a ruff rule or CI grep check that fails the build on any call to `yaml.load(` without `Loader=SafeLoader`. This prevents single-line regressions from `safe_load` to `load` — a code-execution vulnerability on user-supplied YAML. Include in CI from day one. This is the self-enforcing invariant for the `yaml.safe_load()` mandate.

### WP-0b: Self-Hosting Manifest Design

**Goal:** Design `wardline.yaml` tier assignments for the scanner's own modules BEFORE manifest schema work (WP-3) begins. This transforms an informal planning intent ("design before WP-3") into a checked artefact.

- Create a comment-only `wardline.yaml` at the repo root that names the intended tier for each scanner module
- Document the rationale for each tier assignment (especially any Tier 3/4 assignments for modules containing `dict.get()` or `except Exception`)
- This manifest is not machine-validated until WP-3c (loader), but its content guides schema design decisions in WP-3a
- **Tier assignment policy:** Distinguish legitimate tier assignments from "silence the gate" downgrades. Each Tier 3 or Tier 4 assignment must have a documented rationale referencing the module's actual data flow semantics, not its convenience for the self-hosting gate

### WP-1: Core Data Model

**Goal:** Encode the specification's truth tables as tested Python code.

**WP-1a: Enums and Constants**
- `AuthorityTier` IntEnum: `TIER_1 = 1` through `TIER_4 = 4`
- **Serialisation note:** `AuthorityTier` values appear in SARIF output as `wardline.enclosingTier` (integer). This is intentional — the spec uses integer tier numbers (1-4) in SARIF property bags. `TaintState` uses `StrEnum` because taint state tokens are string identifiers (`AUDIT_TRAIL`, `PIPELINE`, etc.). The mixed serialisation (integer tiers, string taint states) is consistent with the spec's SARIF example (§10.1) where `wardline.enclosingTier: 1` and `wardline.taintState: "AUDIT_TRAIL"` appear in the same property bag.
- `TaintState` StrEnum: 8 canonical tokens — **values MUST be assigned explicitly as uppercase strings** (e.g., `AUDIT_TRAIL = "AUDIT_TRAIL"`, `PIPELINE = "PIPELINE"`, etc.). Do NOT use `auto()` — `StrEnum` with `auto()` produces lowercase values (`"audit_trail"`), which would silently break SARIF output, matrix lookups, and corpus matching where the spec uses uppercase tokens. Add a serialisation round-trip test to `test_taints.py` asserting `str(TaintState.AUDIT_TRAIL) == "AUDIT_TRAIL"`.
- `Severity` StrEnum: `ERROR = "ERROR"`, `WARNING = "WARNING"`, `SUPPRESS = "SUPPRESS"` — explicit string assignments, not `auto()`
- `Exceptionability` StrEnum: `UNCONDITIONAL = "UNCONDITIONAL"`, `STANDARD = "STANDARD"`, `RELAXED = "RELAXED"`, `TRANSPARENT = "TRANSPARENT"` — explicit string assignments, not `auto()`
- `RuleId` StrEnum: `PY_WL_001 = "PY-WL-001"` through `PY_WL_009 = "PY-WL-009"` — note the member names use underscores but the string values use hyphens per the spec's SARIF format. `auto()` cannot produce hyphenated values. Add a round-trip test asserting `str(RuleId.PY_WL_001) == "PY-WL-001"`.
- `core/registry.py`: canonical decorator name list with group numbers, expected arguments, and a registry version string

**WP-1b: Taint Join Lattice**
- `taint_join(a: TaintState, b: TaintState) -> TaintState`
- Hardcoded dict of 28 non-trivial pairs (upper triangle, excluding self-joins); self-joins handled via identity check before lookup (`join(a, a) == a` for all states)
- Lookup function that normalises operand order (commutative — `join(a,b) == join(b,a)`)
- Properties to test: commutativity (all 64 ordered pairs), associativity, idempotency, MIXED_RAW is absorbing element
- MIXED_RAW absorbing element: for all X in TaintState, `taint_join(MIXED_RAW, X) == MIXED_RAW`. This is the most critical lattice property — MIXED_RAW is bottom (⊥) and any merge of unlike states reaches it. Test this as an explicit named test case, not merely as an emergent property of the 28-pair exhaustive test.

**WP-1c: Severity Matrix**
- `SeverityCell` frozen dataclass (`@dataclass(frozen=True)`): `severity: Severity`, `exceptionability: Exceptionability` — frozen because severity cells are immutable lookup values; mutable cells could be accidentally modified during a scan, producing non-deterministic results across rules
- `SEVERITY_MATRIX: dict[tuple[RuleId, TaintState], SeverityCell]`
- `lookup(rule, taint) -> SeverityCell` — raises `KeyError` for unrecognised `(rule, taint)` combinations (should never happen with validated inputs; a `KeyError` here indicates a bug in the caller or an incomplete matrix). Do not return a default or sentinel — fail loudly.
- Initialised from the spec's 9×8 table (72 cells total; 9 Python rules × 8 taint states, includes WL-001 split into PY-WL-001/002)
- **Test requirement:** Expected values MUST be encoded independently as a separate fixture table (e.g., a list of `(rule, taint, expected_severity, expected_exceptionability)` tuples), NOT derived from the `SEVERITY_MATRIX` dict being tested. A test that reads from `SEVERITY_MATRIX` and asserts against itself proves nothing.

**WP-1d: Runtime Constructs** (in `runtime/` sub-package, not `core/`)
- `TierMarker` class for use with `Annotated`
- `Tier1 = Annotated[T, TierMarker(1)]` (and Tier2-4) — note: `T` is a `TypeVar` for generic use; concrete aliases like `Tier1Str = Annotated[str, TierMarker(1)]` are also valid
- `FailFast` annotation marker
- `AuthoritativeField` descriptor: stores in `obj.__dict__["_authoritative_{name}"]`, raises `AuthoritativeAccessError` on access-before-set. Known residual: `__dict__` manipulation bypasses the sentinel — test this bypass explicitly.
- **Security posture clarification:** `AuthoritativeField` is a **development-time assertion**, not a security control. It catches accidental access-before-set during normal development but cannot prevent deliberate bypass via `__dict__` manipulation — a fundamental Python descriptor protocol limitation. Do NOT rely on `AuthoritativeField` as a security boundary. Document this explicitly in the descriptor's docstring. The static analysis scanner (PY-WL-007, post-MVP) provides the enforcement-layer coverage: a scanner rule that detects `__dict__` assignment patterns targeting `_authoritative_`-prefixed keys (`ast.Subscript` on `ast.Attribute(attr='__dict__')` with a string constant containing `_authoritative_`) is the compensating control. Until PY-WL-007 ships, `__dict__` bypass is an undetected path — document this as a known residual risk for adopters who deploy runtime enforcement before the scanner covers it.
- `WardlineBase` class with `__init_subclass__` that checks subclass methods for wardline decorators. Uses cooperative `super().__init_subclass__()` and does NOT use a metaclass — this ensures compatibility with `ABCMeta`, Django's `ModelBase`, SQLAlchemy's `DeclarativeMeta`, and other metaclass-using frameworks. **`super()` call ordering:** The implementation MUST call `super().__init_subclass__(**kwargs)` BEFORE performing wardline-specific validation. If `WardlineBase.__init_subclass__` raises before calling `super()`, cooperative inheritance breaks silently for any class inheriting from both `WardlineBase` and another `__init_subclass__`-defining class. Test against `ABCMeta` composition explicitly. **Additional test case:** verify that a class inheriting from both `WardlineBase` and a second class that defines `__init_subclass__` sees both hooks fire.
- `ValidatedRecord` Protocol and trust-typed interfaces
- **Deferred to WP-8 (mypy plugin):** `ValidatedRecord` Protocol and trust-typed interfaces in `runtime/protocols.py` — these have one concrete consumer: the mypy plugin (WP-8, Phase 3, post-MVP). Including them in WP-1d would add scope to the critical path for a feature whose consumer is two phases away. Create `protocols.py` when WP-8 begins, not before.

### WP-1.5: Tracer Bullet

**Goal:** Validate the core assumption — that the AST-pattern-to-SARIF pipeline is tractable — before committing to WP-3+. The critical path runs 25+ sequential sub-tasks before integration feedback; this spike provides integration feedback after WP-1.

- Hardcode one rule (PY-WL-004: broad exception handlers) — no manifest
- Hardcode one taint state (EXTERNAL_RAW)
- Hardcode severity lookup (ERROR/STANDARD from the matrix)
- Parse a single fixture file with `ast.parse()` — covering both `FunctionDef` and `AsyncFunctionDef`
- Emit a single SARIF result with the required wardline property bags
- **Registry validation step:** Replace the hardcoded decorator name with a lookup from `core/registry.py` for at least one step. This validates the registry API before it is frozen and two parallel streams depend on it. Cost: trivial. Value: confirms the registry's structure before WP-2 and WP-4 begin.
- **RuleBase metaclass interaction proof-of-concept:** Implement a minimal version of the `RuleBase` pattern (with `@typing.final` methods, `__init_subclass__` runtime guard, and `ast.NodeVisitor` dispatch) and verify: (a) subclass with `visit_FunctionDef` override raises `TypeError`, (b) subclass that fails to implement `visit_function` raises `TypeError` from ABCMeta (if `RuleBase` inherits from `abc.ABC`), (c) valid subclass passes both checks and receives dispatch calls. This de-risks the WP-4a design.
- **Minimum validation assertion:** Assert that the SARIF output validates against the vendored SARIF JSON Schema. This is one assertion — not a test suite — but it validates the core pipeline assumption.
- Run it. Confirm: AST pattern matching works, SARIF validates, severity lookup returns the right cell, registry lookup works, RuleBase pattern is sound.

This is a **learning artefact, not production code**. Discard it after validation. Its purpose is to de-risk the design before 6 more work packages are committed to the current architecture.

**Teardown ownership:** The tracer bullet code is discarded at the opening of WP-4a (scanner infrastructure), not at the end of WP-1.5. This ensures the working code is deleted before production infrastructure exists. If left until later, it will be tested accidentally. Make the teardown a named deliverable at the start of WP-4: 'Remove WP-1.5 tracer bullet code before creating production scanner infrastructure.'

### WP-2: Decorator Library

**Goal:** Provide the annotation vocabulary that makes institutional knowledge machine-readable.

**WP-2a: Decorator Factory** (`_base.py`)
- `wardline_decorator(group: int, name: str, **semantic_attrs)` — returns a decorator
- The decorator sets two kinds of attributes on the target:
  - **Group flag:** `_wardline_groups` — a `set[int]` accumulating which groups are present (supports stacking)
  - **Semantic attributes:** `_wardline_{semantic_name}` — meaningful attributes the scanner uses (e.g., `_wardline_tier_source`, `_wardline_transition`). These are the primary discovery mechanism.
- **Attribute ordering requirement:** `_wardline_*` attributes MUST be set on the wrapper AFTER `functools.wraps()` is called. If set before, a subsequent third-party decorator that calls `update_wrapper` will overwrite them. The factory must call `functools.wraps(fn)(wrapper)` first, then set `_wardline_*` attributes on `wrapper`.
- **Outer decorator clobber limitation:** The attribute ordering fix protects against inner decorators (decorators applied before the wardline decorator in the stack). It does NOT protect against outer decorators applied after the wardline decorator — since decorators are applied bottom-up, an outer decorator that calls `functools.update_wrapper()` will overwrite `_wardline_*` attributes. This is a known limitation. The AST scanner is immune (it reads decorator names from AST, not runtime attributes). However, any runtime introspection path (`WardlineBase.__init_subclass__`, `ValidatedRecord` Protocol checking) must traverse the `__wrapped__` chain to find wardline metadata, not rely solely on top-level `_wardline_*` attributes. **Chain exhaustion fallback policy:** If `__wrapped__` chain traversal reaches a callable without `_wardline_*` attributes (chain exhausted or severed by a non-wardline decorator that calls `update_wrapper` but does not preserve `__wrapped__`), return `None`/empty metadata. Do NOT raise. Log at DEBUG level: "wardline decorator detected in AST but not recoverable via __wrapped__ chain for {qualname}". This is a silent degradation path — the runtime introspection cannot recover the metadata, but the AST scanner is immune (it reads decorator names from source, not runtime attributes). Test: `tests/unit/decorators/test_decorators.py` must include a test that applies a simulated `update_wrapper`-calling decorator on top of a wardline decorator and verifies that (a) the AST scanner still discovers the wardline decorator and (b) `__wrapped__` chain traversal recovers `_wardline_*` attributes, and (c) a severed chain (decorator that calls `update_wrapper` without preserving `__wrapped__`) returns `None` without raising.
- Works on functions, methods, staticmethods, classmethods
- Stacking: multiple wardline decorators on the same target compose without conflict (group flags accumulate, semantic attrs merge)
- Test: decorated function remains callable, retains signature, exposes metadata

**WP-2b: Group 1 Decorators** (Authority Tier Flow) — highest priority

Each Group 1 decorator uses the factory to set semantic attributes that the scanner reads:

- `@external_boundary` — sets `_wardline_tier_source = TaintState.EXTERNAL_RAW`
- `@validates_shape` — sets `_wardline_transition = (4, 3)`
- `@validates_semantic` — sets `_wardline_transition = (3, 2)`
- `@validates_external` — sets `_wardline_transition = (4, 2)`
- `@tier1_read` — sets `_wardline_tier_source = TaintState.AUDIT_TRAIL`
- `@audit_writer` — sets `_wardline_tier_source = TaintState.AUDIT_TRAIL` + `_wardline_audit_writer = True`
- `@authoritative_construction` — sets `_wardline_transition = (2, 1)`

The scanner discovers these via AST (matching decorator names from `core/registry.py`), not by reading the attributes at runtime.

**WP-2c: Group 2 Decorator**
- `@audit_critical` — sets `_wardline_audit_critical = True`

**WP-2d: Groups 3–5 Decorators**
- `@system_plugin`, `@int_data`
- `@all_fields_mapped(source=Class)`, `@output_schema(fields=[...])`, `schema_default(expr)`

**WP-2e: Groups 6–17 Decorators**
- Each is a one-liner using the factory
- Lower priority for MVP but straightforward to implement

### WP-3: Manifest System

**Goal:** Parse and validate the machine-readable trust topology.

**WP-3a: JSON Schemas**
- `wardline.schema.json` — tier definitions, rule config, delegation, module-tier mappings, metadata
- `overlay.schema.json` — boundaries, rule overrides, optional fields, contract bindings
- `exceptions.schema.json` — exception register entries with reviewer, rationale, expiry
- **Threat control fields (design now, implement Phase 2):** The exceptions schema MUST include fields for threat controls identified in spec §9.3 and §9.3.2, even though the enforcement logic is Phase 2:
  - `agent_originated: boolean` — whether this exception was authored by an AI agent (spec §9.3 framework invariant: agent-originated governance changes must be distinguishable from human-originated ones)
  - `recurrence_count: integer` — how many times an exception for the same (rule, location) tuple has been renewed (spec §9.4: second+ renewal triggers governance escalation)
  - `governance_path: enum["standard", "expedited"]` — enables the expedited governance ratio metric (spec §9.4)
  These fields are included in the `0.x` schema from day one so that any exception register entries created during early adoption already carry the metadata that Phase 2 enforcement will require. Retrofitting these fields onto existing entries is a data migration; including them from the start avoids that.
- `fingerprint.schema.json` — per-function annotation hash records
- Include `$id` with version (e.g., `"$id": "https://wardline.dev/schemas/0.1/wardline.schema.json"`), descriptions, required fields, enum constraints, `additionalProperties: false`
- **`wardline.toml` validation and governance:** While `wardline.toml` is scanner operational configuration (not part of the manifest system), it controls the enforcement perimeter and rule configuration — making it functionally equivalent to a policy artefact for security purposes. A malformed or poisoned `wardline.toml` that excludes modules from the enforcement perimeter silently disables wardline for those modules. Add a TOML schema or validation step in WP-5a that validates `wardline.toml` at scan startup. A malformed `wardline.toml` should produce a structured error (exit code 2), not silent misconfiguration. At minimum, validate: known keys only (reject typos), valid rule IDs, valid taint state tokens, valid paths. **CODEOWNERS protection:** Add `wardline.toml` to CODEOWNERS alongside corpus files, requiring designated reviewer approval for changes. **Perimeter change detection:** When the enforcement perimeter changes between scans (files or directories added/removed from the scanned set), emit a GOVERNANCE-level finding. This makes perimeter reduction visible to reviewers.
- **Schema stability policy:** MVP schemas are versioned `0.x` (unstable). Breaking changes are permitted with a version bump in `$id`. From v1.0 onward, breaking changes require a migration path. The `$id` version is the contract — consumers check it.

**WP-3b: Data Models** (`@dataclass(frozen=True)`, not Pydantic)

All manifest data models MUST use `@dataclass(frozen=True)`. These are configuration objects loaded once at scan startup. Mutable manifest dataclasses create a risk: scanner rules or merge logic could accidentally mutate the loaded manifest during a scan, producing non-deterministic behaviour across rules (one rule sees the original manifest, another sees a mutated copy).

- `WardlineManifest` (frozen): tiers, rules, delegation, module_tiers, metadata
- `WardlineOverlay` (frozen): overlay_for, boundaries, rule_overrides, optional_fields, contract_bindings
- `ExceptionEntry` (frozen): id, rule, taint_state, location, exceptionability, severity_at_grant, rationale, reviewer, expires, provenance
- `FingerprintEntry` (frozen): qualified_name, module, decorators, annotation_hash, tier_context, boundary_transition, last_changed
- `ScannerConfig` (frozen): loaded from `wardline.toml` — if post-load normalisation is needed, use a two-phase approach (mutable builder → frozen config)
- **Round-trip test:** Add a test verifying model construction from YAML, field validation, and that manifest objects are not mutatable (attempting attribute assignment raises `FrozenInstanceError`)

**WP-3c: Loader and Discovery**
- `discover_manifest(start_path: Path) -> Path` — walk upward to find `wardline.yaml`. If not found, emit a clear error (not a crash with a generic FileNotFoundError). **Walk upper bound:** `discover_manifest()` stops walking upward at the first `.git` directory (VCS root, primary bound) or the user's home directory (`Path.home()`, secondary safety net for non-git environments), whichever is encountered first. If neither is found before reaching the filesystem root, emit a clear error. This prevents slow or confusing behaviour in containerised environments where no manifest exists and the walk would reach `/`. **Symlink safety:** The upward walk MUST NOT follow symlinks that would create cycles. Track visited directory inodes to detect symlink loops. In containerised CI environments, `Path.home()` may be `/root` or `/` — the `.git` stop condition is the primary bound; `Path.home()` is the fallback.
- `load_manifest(path: Path) -> WardlineManifest` — load with **`yaml.safe_load()` only** (NEVER `yaml.load()` — code execution vulnerability on user-supplied YAML). **YAML bomb protection:** Before parsing, check input file size against a maximum limit (default: 1MB). `yaml.safe_load()` prevents code execution but does not prevent denial-of-service via deeply nested YAML anchors/aliases (billion laughs attack). A file-size limit is the simplest mitigation. Schema-validate against `wardline.schema.json`. **`$id` version check:** Before schema validation, extract the `$id` from the loaded document and compare it to the scanner's expected schema version. If the `$id` version does not match, emit a structured error: "manifest targets schema version X.Y, this scanner bundles X.Z — update the manifest or upgrade wardline." This transforms an unhelpful `additionalProperties` rejection into an actionable version mismatch message. Parse into dataclass.
- `discover_overlays(root: Path) -> list[Path]` — find all `wardline.overlay.yaml` files. **Overlay allowlist:** If `wardline.yaml` or `wardline.toml` contains an `overlay_paths` field (list of allowed directory paths), only discover overlays in those directories. If an overlay is found in an undeclared location (e.g., a vendored or generated directory), emit a GOVERNANCE-level ERROR finding. This prevents malicious overlay injection in unexpected directories. If no `overlay_paths` field is present, all directories are allowed (backwards-compatible default).
- `load_overlay(path: Path) -> WardlineOverlay` — load with `yaml.safe_load()`, schema-validate, parse
- **YAML 1.1 quoting:** PyYAML defaults to YAML 1.1 where unquoted `NO` becomes boolean `false` (the "Norway problem"). Document in `wardline.yaml` that all string identifiers MUST be quoted. Schema validation catches type mismatches (e.g., a boolean where a string is expected), providing a safety net.
- **YAML 1.1 coercion tests:** `tests/unit/manifest/test_loader.py` MUST include test fixtures for the following YAML 1.1 silent coercion hazards:
  - **Boolean coercion (Norway problem):** A manifest where a string field holds `NO`, `OFF`, `YES`, `ON` — PyYAML silently coerces these to boolean. Verify schema validation catches the type mismatch with a clear user-facing error.
  - **Sexagesimal coercion:** A manifest where a string field holds `1:30` (coerced to integer 5400) or a version-like string with a colon. Verify schema validation catches the type mismatch.
  - **Float coercion:** A manifest where a string field holds `1e3` (coerced to float 1000.0). Verify schema validation catches the type mismatch.
  These are safety nets — without these tests, the `additionalProperties: false` + `"type": "string"` schema constraints are untested for coercion edge cases.
- **`ruamel.yaml` considered and deferred:** `ruamel.yaml` (YAML 1.2, no Norway problem) was considered as an alternative to PyYAML. Deferred because PyYAML is more widely deployed, has fewer transitive dependencies, and the schema validation safety net catches the practical impact. Revisit if YAML 1.1 coercion causes repeated user confusion.
- **Scan-time path validation:** At scan startup, cross-reference every `module_tiers` path entry in `wardline.yaml` against the file tree being scanned. Emit a WARNING for any path that matches zero files. This catches the most common manifest-code drift scenario (module renamed, manifest not updated).

**WP-3d: Overlay Merge**
- `merge(base: WardlineManifest, overlay: WardlineOverlay) -> ResolvedManifest`
- Enforce narrow-only invariant: overlay cannot relax tiers, lower severity, or grant undelegated exceptions
- Raise `ManifestWidenError` on violation with a structured, actionable error message identifying: (1) which overlay file caused the violation, (2) which field was widened (tier, severity, or exception grant), (3) the base value and the attempted overlay value. An overlay violation is a significant governance event — the error must be clear enough for a developer to fix without debugging the merge logic.

**WP-3e: Coherence Checks**

MVP-adjacent (include before self-hosting gate):
- Orphaned annotations (decorators without manifest declaration) — silently breaks enforcement if missed
- Undeclared boundaries (manifest declarations without code decorators) — manifest claims a boundary exists where no code annotation marks it

MVP-adjacent (implement before self-hosting gate):
- **Three governance-level anomaly signals from spec §9.3.2** (the spec uses SHOULD, not MUST, but a reference implementation should demonstrate the capability):
  - Tier downgrade detection: any change that lowers a data source's tier (e.g., Tier 1 → Tier 2) — emit ERROR governance-level finding
  - Tier upgrade without evidence: Tier 4 → Tier 1 or Tier 4 → Tier 2 without corresponding boundary declarations — emit ERROR governance-level finding
  - Agent-originated policy change: any policy artefact change authored by an agent — emit ERROR governance-level finding requiring human ratification
  These signals run as manifest-level checks (not code-level) and can run before the scanner. They appear in SARIF output with `ruleId: "GOVERNANCE-*"` prefix.

Post-MVP:
- Tier-topology consistency
- Unmatched contracts
- Stale contract bindings

### WP-4: AST Scanner

**Goal:** The enforcement engine. Two-pass AST analysis producing SARIF output.

**Critical AST requirement:** Every rule visitor and the taint assignment pass MUST visit both `ast.FunctionDef` and `ast.AsyncFunctionDef`. Python 3.12 codebases use async functions extensively. If only `visit_FunctionDef` is implemented, every `async def` function is silently excluded from scanning — a systematic false-negative across the entire scanner. The `RuleBase` class (WP-4a) should enforce this by requiring subclasses to implement `visit_function(node, is_async)` rather than separate `visit_FunctionDef`/`visit_AsyncFunctionDef` methods.

**WP-4a: Scanner Infrastructure**
- `Finding` frozen dataclass (`@dataclass(frozen=True)`): rule_id, file_path, line, col, end_line, end_col, message, severity, exceptionability, taint_state, analysis_level, source_snippet (literal source span for corpus verification) — frozen because findings are immutable records; mutation after creation is a bug
- `ScanContext` frozen dataclass (`@dataclass(frozen=True)`): resolved manifest, file path, module taint defaults, function-level taint map — frozen after construction to prevent accidental mutation during rule execution
- `ScanEngine`: orchestrates discovery → taint computation → rule execution → SARIF emission. **Test requirement:** Add unit tests for `ScanEngine` orchestration covering: (a) normal multi-file scan, (b) one file fails to parse while others succeed — the scan MUST continue on remaining files and emit a structured error for the failed file (not abort), (c) `PermissionError` on a directory during file discovery — skip with structured warning.
- File discovery: walk source tree, filter by manifest enforcement perimeter. **Symlink safety:** Use `os.walk(followlinks=False)` or track visited inodes to prevent infinite loops from symlink cycles. **Filesystem error handling:** `PermissionError` on directories and broken symlinks MUST be caught and reported as structured warnings, not crashes. These are realistic in CI environments with unusual mount configurations.
- `RuleBase` abstract class (inherits from both `ast.NodeVisitor` and `abc.ABC`): implements `visit_FunctionDef` and `visit_AsyncFunctionDef` as `@typing.final` methods that both delegate to an abstract `visit_function(node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None`. `visit_function` is declared as `@abstractmethod` — ABCMeta enforces implementation. A runtime guard in `__init_subclass__` raises `TypeError` if a subclass overrides `visit_FunctionDef` or `visit_AsyncFunctionDef` directly. **`super().__init_subclass__()` call ordering:** Call `super().__init_subclass__(**kwargs)` BEFORE performing the override check, consistent with WP-1d's WardlineBase pattern. Rationale: `ast.NodeVisitor` dispatches by calling `visit_{classname}`, so a subclass that only defines `visit_function` would receive zero dispatch calls from the standard `visit()` machinery. The `@final` routing pattern preserves NodeVisitor dispatch while enforcing the unified method.
- **Rule crash handling:** Rule execution in `ScanEngine` MUST wrap each rule's `visit_function()` call in a try/except that catches unexpected exceptions and emits a `TOOL-ERROR` finding (with the rule ID, file path, and exception message) rather than silently skipping the rule or crashing the scan. A crashing rule that is caught and silenced produces systematic false negatives indistinguishable from "no findings." The `TOOL-ERROR` finding makes the failure visible in SARIF output.

**WP-4b: Decorator Discovery from AST**
- Parse decorator expressions using `ast.parse()` (no imports)
- Match decorator names against canonical names from `core/registry.py`
- Extract decorator arguments (e.g., `from_tier`, `to_tier`)
- Build map: `dict[tuple[str, str], set[WardlineAnnotation]]` keyed by `(module_path, qualname)`
- **Nested functions:** Python's `outer.<locals>.inner` qualname format for nested functions is a valid map key. Nested functions inherit the outermost enclosing decorated function's taint (conservative, correct for Level 1).
- **Import alias resolution strategy:** Build a per-file import table mapping `local_name → canonical_wardline_name` during the discovery pass. Resolution handles:
  - `from wardline import external_boundary` → direct match
  - `from wardline.decorators.authority import external_boundary` → direct match
  - `import wardline` + `wardline.external_boundary` → qualified match
  - `from wardline import external_boundary as eb` → alias tracked in per-file import table
  - Unresolvable aliases (chained re-exports, dynamic imports, `importlib.import_module`, `__import__`, star imports) — the scanner handles these in three ways: (1) For `importlib.import_module("wardline")` and `__import__("wardline")` call patterns: the scanner detects these AST patterns (`ast.Call` with the importlib/`__import__` function name and a string argument containing 'wardline') and emits a WARNING-level finding: 'Dynamic import of wardline detected; decorators applied via dynamic import are not analysed.' (2) For star imports (`from wardline import *`): the scanner detects `ast.ImportFrom` with `names=[ast.alias(name='*')]` and emits a WARNING. (3) For chained re-exports through intermediate modules (e.g., `from myproject.boundaries import external_boundary` where the intermediate module re-exports from wardline): the per-file import table cannot resolve these. **Resolution failure signal (CRITICAL — not silent):** When the scanner detects a decorator name that appears to be wardline-related (matches a `@wardline`-prefixed name pattern or a name found in `core/registry.py`) but cannot resolve its import to a canonical wardline decorator, it MUST emit a WARNING-level finding with a distinct rule ID or message category (e.g., `WARDLINE-UNRESOLVED-DECORATOR`) rather than silently assigning `UNKNOWN_RAW`. This distinguishes "resolution failed" (the scanner could not trace the import) from "correctly undeclared" (the module is not in the manifest). Without this signal, enforcement decay from import resolution failures is invisible — the function silently gets `UNKNOWN_RAW` taint identical to a legitimately undeclared module. The `wardline explain` command (WP-5b) MUST surface this distinction: when explaining a function that is `UNKNOWN_RAW`, it must indicate whether the taint was assigned because (a) the module is not declared in the manifest, or (b) a wardline-like decorator was detected but could not be resolved. A future enhancement (post-MVP) could add one-hop re-export resolution by reading the intermediate module's imports. Functions decorated via `exec()`, `eval()`, or other metaprogramming are a permanent false-negative surface — document this in the scanner's limitations.
  - `if TYPE_CHECKING: from wardline import ...` → conditional imports are not resolved (decorator is not applied at runtime anyway)

**WP-4c: Level 1 Taint Assignment**
- Decorated functions: taint from decorator (e.g., `@external_boundary` → `EXTERNAL_RAW`)
- Undecorated functions in declared modules: taint from manifest's `module_tiers`
- Undecorated functions in undeclared modules: `UNKNOWN_RAW`
- Build `dict[tuple[str, str], TaintState]` for the whole codebase
- Must process both `FunctionDef` and `AsyncFunctionDef` nodes

**WP-4d: Pattern Rules PY-WL-001 through PY-WL-005**

Each rule is an `ast.NodeVisitor` subclass (visiting both sync and async function defs):

| Rule | AST Pattern | Implementation |
|------|------------|----------------|
| PY-WL-001 | `ast.Call` where `func` is `Attribute(attr='get')` or `Attribute(attr='setdefault')` with ≥2 args; also `ast.Call` where `func` is `Name(id='defaultdict')` (constructor-time default fabrication) | Check for default argument presence. Also recognise `schema_default()` wrapper — in MVP, `schema_default()` suppresses PY-WL-001 unconditionally (presence-only, no overlay verification). This is a **known conformance gap** closed in Phase 2 when the overlay system ships. **Graduated suppression (MVP):** Rather than suppress PY-WL-001 silently on `schema_default()` presence, the MVP scanner emits a WARNING-severity finding with ruleId `PY-WL-001-UNVERIFIED-DEFAULT` and message: 'schema_default() suppresses PY-WL-001 but overlay verification is not yet implemented — this suppression is un-governed.' This gives adopters visibility of every unverified suppression without blocking development. Phase 2 replaces the WARNING with silence when overlay verification passes. This transforms the Phase 2 triage wave from 'find and verify all schema_default() calls' into 'resolve all PY-WL-001-UNVERIFIED-DEFAULT findings in the SARIF' — a machine-searchable migration path. |
| PY-WL-002 | `ast.Call` where `func` is `Name(id='getattr')` with 3 args | Three-argument `getattr()`. Note: `hasattr()` is assigned exclusively to PY-WL-003 (see classification note below). |
| PY-WL-003 | `ast.Compare` with `In` operator; `ast.Call` to `hasattr`; `ast.MatchMapping` and `ast.MatchClass` nodes (structural pattern matching — `match/case` with mapping patterns performs existence-checking semantically equivalent to `if key in dict`) | All existence-checking patterns in one rule |
| PY-WL-004 | `ast.ExceptHandler` where `type` is `Name(id='Exception')` or `None` | Bare except or `except Exception` |
| PY-WL-005 | `ast.ExceptHandler` where body is `[Pass()]` (silent handler) or `[Expr(Constant(value=Ellipsis))]` (except: ...) | Note: `body == []` (empty list) cannot occur — Python's parser raises `SyntaxError` for exception handlers with no body. Do not guard against it. **Additional silent handler patterns:** `body` containing only `continue` (in a loop) or `break` (in a loop) should be treated as silent handlers for PY-WL-005 — the exception is caught and execution continues without any action on the exception itself. Lambda expressions containing `.get()` calls are in scope for PY-WL-001 — lambdas are `ast.Lambda` nodes and MUST be visited by the scanner. Add a corpus specimen that verifies the scanner either catches or consistently misses lambda `.get()` calls. If lambda scanning is deferred, add a named test case documenting this as a known false-negative surface with a corpus TN specimen confirming the behaviour. |

**`except*` (ExceptionGroup) scope:** Python 3.11 introduced `except*` blocks (`ast.TryStar` node) for `ExceptionGroup` handling. The MVP scanner targets Python 3.12+ codebases, which may use `except*`. PY-WL-004 and PY-WL-005 MUST handle `ast.TryStar` nodes in addition to `ast.ExceptHandler`. An `except*` block that catches broadly or silently is the same anti-pattern as a broad `except` — the AST node type differs but the semantic concern is identical. Add corpus specimens for both `ast.ExceptHandler` and `ast.TryStar` patterns.

Each rule looks up severity from the matrix using the enclosing function's taint state.

**`hasattr()` classification:** The parent spec lists `hasattr()` in both PY-WL-002 (attribute access with fallback) and PY-WL-003 (existence-checking as structural gate). These rules have different severity matrices. This plan assigns `hasattr()` exclusively to PY-WL-003 (existence-checking) because `hasattr` is structurally an existence check, not an attribute access with fallback. PY-WL-002 covers only three-argument `getattr()`. This is an explicit design decision that differs from the spec's dual mention — document it in the scanner's rule descriptions.

**WP-4e: Context-Dependent Rules PY-WL-006 through PY-WL-009** (post-MVP)

PY-WL-006 through PY-WL-009 are **suppressed entirely in the MVP scanner** — they do not emit findings. Emitting low-confidence findings under governance-grade rule IDs risks polluting exception registers with findings that later taint analysis will invalidate.

| Rule | Requires | Implementation |
|------|----------|----------------|
| PY-WL-006 | Audit context | PY-WL-004 pattern, but only when enclosing function has `@audit_writer` or `@audit_critical` — AND the broad handler wraps a call to an audit-decorated function |
| PY-WL-007 | Tier context | `isinstance()` calls where enclosing function's taint is AUDIT_TRAIL or PIPELINE |
| PY-WL-008 | Structural analysis | Functions with validation decorators — check body for at least one rejection path. Valid rejection paths: `raise`, conditional early `return`, call to unconditionally-raising function (2-hop). **NOT valid:** `assert` (stripped by `-O`), `if False: raise` (unreachable — scanner SHOULD detect constant-False guards), `return None` without preceding conditional (unconditional, not a rejection). |
| PY-WL-009 | Annotation ordering | Functions with `@validates_semantic` — check that their parameters trace to functions with `@validates_shape`. The MVP approximation (module-level co-presence check) **produces false negatives for cross-module flows (the common case)** since shape validators are typically in `adapters/` while semantic validators are in `domain/`. PY-WL-009 is effectively advisory-only until Level 2+ taint analysis (WP-7) enables cross-function flow tracking. |

**WP-4f: SARIF Output**
- `SarifReport` dataclass with `to_dict() -> dict`
- SARIF v2.1.0 structure: `$schema`, `version`, `runs[0].tool`, `runs[0].results`
- Wardline property bags per result: `wardline.rule`, `wardline.taintState`, `wardline.severity`, `wardline.exceptionability`, `wardline.analysisLevel`
- Run-level properties: `wardline.controlLaw`, `wardline.manifestHash`, `wardline.deterministic`, `wardline.registryVersion`, `wardline.propertyBagVersion`, `wardline.implementedRules`, `wardline.conformanceGaps`, `wardline.unresolvedDecoratorCount`, `wardline.unknownRawFunctionCount`
  - `wardline.unresolvedDecoratorCount` — integer count of functions where a wardline-like decorator was detected in AST but could not be resolved to a canonical decorator (see WP-4b resolution failure signal). This is the primary ambient metric for import resolution failures. A non-zero value warrants investigation via `wardline explain`.
  - `wardline.unknownRawFunctionCount` — integer count of all functions assigned `UNKNOWN_RAW` taint (both from unresolved decorators and from undeclared modules). The difference `unknownRawFunctionCount - unresolvedDecoratorCount` is the count of functions in modules not declared in the manifest.
  - `wardline.propertyBagVersion` — version string for the wardline SARIF property bag schema (e.g., `"0.1"`). This is a distinct versioned contract from the JSON manifest schemas. If property bag keys are added, renamed, or semantically changed, this version increments. Downstream consumers (CI gates, SIEM, assessors) use this to detect schema drift. This is a one-way door: property bags emitted without a version field cannot be distinguished from later bags with different semantics.
  - `wardline.implementedRules` — array of rule ID strings that this scanner actively enforces (e.g., `["PY-WL-001", "PY-WL-002", "PY-WL-003", "PY-WL-004", "PY-WL-005"]`). Rules that are registered but suppressed (PY-WL-006 through PY-WL-009 in MVP) are NOT included. This satisfies the Wardline-Core requirement that the tool's documentation declare which rules it implements, and makes the MVP's partial implementation legible to assessors from SARIF output alone.
  - `wardline.conformanceGaps` — list of string tokens identifying known deviations from the spec's normative requirements. Empty list for a fully conformant scan. MVP value: `["PY-WL-001-SCHEMA-DEFAULT-UNVERIFIED"]` (schema_default() suppresses PY-WL-001 without overlay verification — see Section 5 conformance gap note). This makes the conformance gap machine-readable from the first release so downstream governance tools can detect un-verified suppressions.
- **Determinism requirements:**
  - Multi-file output MUST be sorted by file path before serialisation (filesystem traversal order is not guaranteed on all platforms)
  - No `set` iteration in output paths — use sorted collections
  - `--verification-mode` flag omits `run.invocations` timestamps for byte-identical corpus evaluation
  - `manifestHash` is computed over a **canonical serialisation** of manifest content (not raw file bytes — avoids timestamp-sensitive fields). **Canonical serialisation algorithm:** JSON encoding with sorted keys, no trailing whitespace, no platform-dependent float representation (use `json.dumps(obj, sort_keys=True, separators=(',', ':'))` for deterministic output). This is a normative specification, not an implementation detail — two implementations of the same spec must produce identical hashes for logically identical manifests. Test: verify that two logically identical manifests with different YAML key ordering produce the same `manifestHash`.
- `to_json(path: Path)` — write SARIF file
- Test: validate output against SARIF JSON Schema
- **Determinism test:** `tests/integration/test_determinism.py` runs the scanner twice on the same fixture project and asserts byte-for-byte equality of SARIF output (both single-file and multi-file fixtures)
- **Snippet text source:** Finding snippets in SARIF `locations[0].physicalLocation.region.snippet.text` MUST use the literal source substring extracted from the original file, NOT `ast.unparse()` output. `ast.unparse()` normalises whitespace and parenthesisation, which would cause corpus verification to fail silently when comparing against specimen `expected_match.text` (which uses literal source text per spec §10). The scanner must extract source spans by reading the original file bytes at the line/column ranges from the AST node's `lineno`/`col_offset`/`end_lineno`/`end_col_offset`. **Encoding handling:** Read source files as UTF-8 (Python's default source encoding per PEP 3120). If a file has a BOM (byte order mark), strip it before offset calculation. If a file cannot be decoded as UTF-8, emit a structured warning and skip snippet extraction (use empty string) rather than crashing. Test: `tests/unit/scanner/test_sarif.py` must include a multi-line expression specimen and verify that the snippet preserves original formatting.
- **Vendored SARIF schema:** The SARIF v2.1.0 JSON Schema is vendored at `src/wardline/scanner/schemas/sarif-2.1.0.schema.json` with a source comment and SHA-256 hash. Tests validate SARIF output against this vendored copy, not a network-fetched version. A CI test (`tests/unit/scanner/test_sarif.py`) fetches the canonical schema from the OASIS GitHub and compares its hash to the vendored copy — this makes schema staleness visible without making regular CI network-dependent. **Test isolation:** The network-fetching test MUST be marked with `@pytest.mark.network` (or `skipIf` guarded) so it is excluded from default test runs and does not fail in air-gapped CI environments. Run it on a schedule (e.g., weekly), not on every commit.

### WP-5: CLI

**Goal:** User-facing commands for scanning, manifest validation, and governance.

**WP-5a: Core Structure**
- Click group: `@click.group()` on `cli()`
- Subcommands as Click commands in separate modules
- Common options: `--manifest`, `--config`, `--output`, `--verbose`, `--verification-mode`
- **`--verbose` / `--debug` logging:** Structured logging to stderr with scan context (file, function, taint state, rule being evaluated). `--verbose` shows scan progress and high-level decisions. `--debug` shows per-node AST matching detail. This is the primary mechanism for debugging unexpected results.
- **Error handling:** AST parse errors (syntax errors in target code), manifest not found, YAML load failures, and schema validation errors all produce structured error messages to stderr with non-zero exit codes — not stack traces.

**WP-5b: MVP Commands**
- `wardline scan <path> [--output FILE] [--manifest FILE]` — run scanner, emit SARIF, exit 0 (clean) or 1 (findings)
- `wardline manifest validate [FILE]` — validate manifest against schema, exit 0 or 1
- `wardline corpus verify [--corpus-dir DIR]` — run bootstrap corpus, report per-rule precision/recall. This is MVP scope because precision/recall measurement is a framework invariant (spec §10), not a post-MVP luxury. MVP cannot claim Wardline-Core conformance without measurement.
- `wardline explain <function_qualname> [--manifest FILE]` — minimal taint resolution debugger. For a specified function, prints: (1) resolved taint state and how it was determined (decorator match, `module_tiers` manifest entry, or `UNKNOWN_RAW` fallback), (2) which module-tier entry matched (if any), (3) which rules were evaluated at what severity. This is approximately 50 lines of implementation once WP-4c (taint assignment) is complete and is the primary tool for diagnosing false negatives caused by manifest misconfiguration. Without this, early adopters have no way to distinguish 'scanner is working correctly and this function is clean' from 'this function is silently UNKNOWN_RAW because the manifest is wrong.' The full post-MVP version (WP-5c) adds per-rule match details, exception status, and schema_default() resolution.

**WP-5c: Post-MVP Commands**
- `wardline manifest coherence` — run 5 coherence checks
- `wardline fingerprint update` — compute fingerprint, write JSON
- `wardline fingerprint diff` — compare current to baseline
- `wardline regime status` — report enforcement state
- `wardline exception add/expire/review` — manage exception register
- **Extend `wardline explain`** with per-rule match details, exception status, and `schema_default()` resolution. The MVP `wardline explain` (WP-5b) shows taint resolution and rule evaluation at the function level. The post-MVP extension adds: for each rule, whether any AST pattern matches were found; whether any matches were suppressed (by `schema_default()`, by exception register, or by taint state); and full overlay verification status. This is the primary false-negative debugging tool.

### WP-6: Golden Corpus

**Goal:** Curated specimens that verify scanner correctness and measure precision/recall.

**WP-6a: Bootstrap Corpus (MVP)**
- 36-46 specimens covering UNCONDITIONAL cells, Tier 1/Tier 4 taint states, and all 8 taint-flow scenario types from spec §10 property 6
- Structure: `corpus/specimens/{rule}/{taint_state}/{positive|negative}/specimen_NNN.yaml` — per spec §10, specimens use **YAML format** with mandatory fields: `id`, `rule`, `taint_state`, `expected_severity`, `expected_exceptionability`, `verdict` (true_positive / true_negative), `fragment` (the Python source to scan), `expected_match` (with `text` as literal source substring)
- `corpus/corpus_manifest.yaml` maps each specimen to expected results with SHA-256 hashes for integrity. **Hash failure behaviour:** If a specimen file is present but its SHA-256 hash does not match the corpus manifest, `wardline corpus verify` MUST emit an ERROR (not silently skip the specimen). A hash mismatch indicates either a modified specimen or a stale corpus manifest — both require investigation.
- **CODEOWNERS protection:** Corpus files are protected by CODEOWNERS — changes require designated reviewer approval
- **Taint-flow specimens:** The bootstrap corpus must include all 8 taint-flow scenario types from spec §10 property 6:
  1. Direct boundary-to-boundary (positive): T4 return reaching T1 sink without validation
  2. Direct boundary-to-boundary (negative/clean): T4 return reaching T1 sink with shape and semantic validation
  3. Two-hop indirection: T4 data through up to two undecorated helpers to T1 sink
  4. Shape-only reaching T2 sink: T3 (shape-validated) data reaching T2 sink without semantic validation
  5. Container contamination: cross-tier container merge reaching a consumer at a different tier
  6. Join semantics: merge of two different-tier values produces MIXED_RAW
  7. Declared-domain-default clean: correctly declared `schema_default()` does not fire PY-WL-001
  8. Declared-domain-default without overlay: `schema_default()` without overlay declaration fires PY-WL-001
- **UNKNOWN_RAW specimens:** Include specimens with UNKNOWN_RAW taint for at least PY-WL-001 and PY-WL-004

**WP-6b: Full Corpus (post-MVP)**
- 126+ specimens (1 TP + 1 TN per non-SUPPRESS cell in 9×8 matrix)
- Adversarial specimens: at least 1 adversarial false-positive and 1 adversarial false-negative per rule (minimum 10 adversarial total)
- Evasion-variant specimens: helper wrappers, conditional assignments, schema-level defaults (per spec §7 "living pattern catalogue")
- Precision/recall computation per cell (rule × taint state), not just per rule

**WP-6c: Self-Hosting Gate**
- `wardline.yaml` at repo root declaring the scanner's own modules and tiers — designed BEFORE WP-3 (see Section 11, Risk 3)
- `wardline scan src/` passes with zero ERROR findings (or documented exceptions in `wardline.exceptions.json`)
- **Coverage metric gate:** Coverage metric gate has two parts: (1) 80% of functions in modules declared at Tier 1 (`AUDIT_TRAIL`) or Tier 4 (`EXTERNAL_RAW`) must have explicit tier declarations via decorator (not just module-level `module_tiers` fallback). Module-level `module_tiers` entries alone do not count toward the decorator-level coverage numerator — they provide taint defaults but do not prove annotation investment. (2) Tier-distribution check: if more than 60% of all declared functions are at the most permissive tiers (Tier 3 or Tier 4), emit an **ERROR** governance-level finding. This prevents the gate from being satisfied by annotating everything at SUPPRESS-friendly tiers. The distribution check is ERROR from day one — a WARNING-only distribution check is trivially ignorable and undermines the self-hosting gate's integrity. A developer under pressure can declare scanner internals at Tier 3 across the board, satisfy the 80% decorator coverage floor, and pass the gate without proving the code is clean. An ERROR forces the conversation. An override flag (`--allow-permissive-distribution`) is available for exceptional circumstances but must be documented in CI config, making the override visible to reviewers.
- **Determinism check:** Run the scanner twice, assert byte-identical SARIF output
- **Regression baseline:** Commit the self-hosting SARIF output as a baseline. CI diffs each new scan against the baseline — a change that silently suppresses a previous finding is visible in the diff.
- CI gate: self-hosting check runs on every commit
- **Corpus must not import the decorator library directly** — specimens contain Python source fragments as strings in YAML, not importable modules. This prevents decorator library changes from breaking corpus specimens through import-time side effects.
- **Corpus YAML loading security:** The corpus loader MUST use `yaml.safe_load()` for loading specimen YAML files, consistent with the manifest loader. Corpus YAML is user-editable and loaded at CI time. **Corpus runner execution model:** The corpus runner MUST use `ast.parse()` only on specimen `fragment` fields. It MUST NOT use `exec()`, `eval()`, or `compile()` with `exec` mode on specimen content. Add a test verifying the corpus runner does not call these functions on specimen data.

### WP-7: Level 2 and Level 3 Taint (post-MVP)

**WP-7a: Level 2 — Variable-Level Taint**
- Track taint state per variable within a function body
- Assignment from tainted source propagates: `x = external_func()` → `x` is `EXTERNAL_RAW`
- `taint_join` at control flow merge points (if/else branches assigning to same variable)
- Function return: effective taint is join of all return paths

**WP-7b: Level 3 — Call-Graph Taint Inference**
- Build call graph from AST (function calls → target resolution)
- Worklist algorithm: for each function, compute effective taint from callers + annotations
- Iterate until fixed point (guaranteed: finite lattice, monotonic join)
- Enables cross-function tier-flow detection
- Note: consider `astroid` for call-graph inference. Beware version-pinning conflicts with pylint — `astroid` version requirements have historically caused installation conflicts. Evaluate whether stdlib `ast` + manual name resolution is sufficient before adding this dependency.

### WP-8: mypy Plugin (Phase 3, not MVP)

- Custom mypy plugin using `mypy.plugin` API
- Read `Annotated[str, TierMarker(1)]` metadata from type annotations
- Flag tier mismatches: `Tier4` value flowing to `Tier1` parameter without validation
- Separate from scanner — runs at IDE/development time

### WP-9: ruff Rules (Phase 4, not MVP)

- Implement PY-WL-001 through PY-WL-005 as ruff plugin rules
- Per-file AST matching only — no manifest, no tier-graded severity
- Advisory: fires in IDE for immediate feedback
- Separate project or ruff plugin contribution

## 5. MVP Scope

The MVP is the smallest thing that produces a self-hosting enforcement loop:

| In MVP | Not in MVP |
|--------|------------|
| Core data model (WP-1, complete) | Level 2/3 taint analysis (WP-7) |
| Tracer bullet (WP-1.5) | — |
| Runtime constructs in `runtime/` (WP-1d) | — |
| Group 1 + 2 decorators (WP-2a–2c) | Groups 3–17 decorators (WP-2d–2e) |
| `schema_default()` access-site marker (WP-2d, partial) | Full Group 5 decorator set |
| `wardline.yaml` + `wardline.toml` (WP-3a–3c) | Full overlay system, exception register, fingerprints (WP-3d) |
| Orphaned annotation + undeclared boundary checks (WP-3e, partial) | Remaining 3 coherence checks |
| Rules PY-WL-001 through PY-WL-005 (WP-4d) | Rules PY-WL-006 through PY-WL-009 (suppressed in MVP) |
| `schema_default()` presence-only suppression for PY-WL-001 (WP-4d) | Overlay-verified suppression (Phase 2) |
| Level 1 taint only (WP-4c) | Variable/call-graph taint |
| SARIF output with determinism (WP-4f) | SARIF aggregation |
| `wardline scan` + `wardline manifest validate` + `wardline corpus verify` (WP-5a–5b) | Other CLI commands (WP-5c) |
| Bootstrap corpus, 36–46 YAML specimens (WP-6a) | Full corpus 126+ (WP-6b) |
| Self-hosting gate with coverage metric (WP-6c) | mypy plugin (WP-8), ruff rules (WP-9) |

**Note on `schema_default()` conformance gap:** The parent spec's normative interface contract (Part II-A §A.3, item 3) requires `schema_default()` suppression with overlay verification of the declared approved default. Since overlays are post-MVP, the MVP scanner performs **presence-only suppression** — `schema_default()` wrapping a `.get()` call suppresses PY-WL-001 unconditionally without checking the overlay. This is a **documented conformance gap** closed in Phase 2 when the overlay system ships.

## 6. Critical Path

```
WP-0 (scaffold) + WP-0b (self-hosting manifest design)
  → WP-1a+1b+1c+1d (core model + runtime)
    → WP-1.5 (tracer bullet — validate AST→SARIF pipeline + registry + RuleBase pattern)
      → WP-2a+2b (decorator factory + Group 1)
        → WP-3a+3b+3c (schemas, models, loader — MVP only)
          → WP-4a+4b+4c (scanner infra, discovery, L1 taint)
            → WP-4d (rules 001–005)
              → WP-4f (SARIF output)
                → WP-5a+5b (CLI: scan + validate + corpus verify)
                  → WP-6a (bootstrap corpus)
                    → WP-6c (self-hosting gate)
```

**Note:** WP-3d (overlay merge) and WP-3e (coherence checks beyond orphaned annotations/undeclared boundaries) are post-MVP. They are parallel to the WP-4+ critical path, not on it. The critical path includes only WP-3a (schemas), WP-3b (data models), and WP-3c (loader/discovery).

**Self-hosting wardline.yaml must be designed before WP-3.** The scanner's own code uses `dict.get()` and `except Exception`. Tier assignments for scanner modules must be designed up front (see Risk 3), not retrofitted at WP-6c when the self-hosting gate first runs.

## 7. Parallelisation Opportunities

**Synchronisation requirement before parallel streams begin:** The `_wardline_*` attribute naming convention (e.g., `_wardline_tier_source`, `_wardline_transition`, `_wardline_groups`) is the interface contract between WP-2 (decorator library) and WP-4 (scanner). Before Streams A and B proceed in parallel, the attribute naming specification must be locked in `core/registry.py` — extending the registry to store not only decorator names but also the attribute names each decorator sets. Any change to this specification after parallel work begins is a synchronisation event requiring both streams to update. Treat `core/registry.py` as a frozen interface after WP-1 completion.

Once WP-1 is complete:
- **Stream A:** WP-2 (all decorator groups) — independent of manifest work
- **Stream B:** WP-3 (manifest system) — independent of decorator work
- **Stream C:** Corpus specimen authoring — corpus *skeleton* (directory structure, YAML template, corpus manifest format, and true-negative specimens testing scanner silence) can start alongside WP-4a/4b. Only true-positive specimens (which test specific AST patterns firing) require WP-4d rule implementations to be finalised. Separating skeleton from positive specimens allows the corpus structure and TN specimens to be ready before the rules land, compressing the WP-6a timeline.

Once WP-4a (scanner infra) is complete:
- Each rule (PY-WL-001 through PY-WL-005) can be implemented independently
- SARIF output (WP-4f) can be developed against mock findings

CLI sub-commands (WP-5) are independent of each other once the skeleton exists.

## 8. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Package structure | Single `wardline` package with optional dep groups | Decorators are tiny; scanner needs them; split trigger defined (Section 1) |
| Build system | hatchling with `src/` layout | Modern, minimal config, works with uv |
| AST library | stdlib `ast` only | Zero deps for Level 1–2; `astroid` evaluated for Level 3 (beware pylint conflicts) |
| Data models | `@dataclass(frozen=True)` + `jsonschema` | Minimal deps; Pydantic is overkill for config loading; frozen prevents mutation during scan |
| CLI framework | `click` | Mature, no magic, no Pydantic dependency |
| SARIF generation | Hand-rolled dataclasses | `sarif-om` is unmaintained; SARIF structure is well-specified |
| Taint lattice encoding | Hardcoded dict of 28 non-trivial pairs + identity check | Spec-defined, not derivable; exhaustively testable |
| Decorator metadata convention | `_wardline_*` attributes on callable (set AFTER `functools.wraps`) | Standard Python attribute access; discoverable from AST via decorator names |
| Scanner ↔ decorator coupling | Scanner reads decorator **names** from AST via `core/registry.py`, not attributes | No import-time coupling; bidirectional version-skew check at scan startup |
| `core/` vs `runtime/` split | Pure data in `core/`; behavioural code in `runtime/` | Keeps scanner's import of `core/` free of runtime side effects |
| YAML loading | `yaml.safe_load()` only, never `yaml.load()` | Prevents code execution on user-supplied manifests |
| Schema versioning | `0.x` (unstable) until v1.0; `$id` carries version | Prevents premature contract lock-in |
| Self-hosting gate | Zero-ERROR + 80% coverage floor + determinism check + regression baseline | Distinguishes silence from correctness |
| SARIF property bag versioning | `wardline.propertyBagVersion` on every run | One-way door — bags emitted without version are indistinguishable from later bags with different semantics |
| Self-hosting coverage scope | Decorator-level coverage on Tier 1/4 modules + tier-distribution check (ERROR) | Module-level `module_tiers` alone is too easily gamed; distribution check is ERROR from day one to prevent SUPPRESS-tier flooding |
| AuthoritativeField posture | Development-time assertion, not security control | Python descriptor protocol cannot prevent `__dict__` bypass; scanner PY-WL-007 is the enforcement layer |
| Manifest walk bound | Stop at `.git` or `Path.home()` | Prevents runaway walk to `/` in containers |

## 9. Testing Strategy

| Component | Test Type | Coverage Target | Key Invariants | Test Command |
|-----------|-----------|-----------------|----------------|-------------|
| Core model | Unit (parameterised) | 100% | Lattice commutativity/associativity/idempotency/MIXED_RAW-absorbing, matrix completeness (independently-encoded expected values — fixture table MUST NOT read from SEVERITY_MATRIX dict under test; see WP-1c) | `uv run pytest tests/unit/core/ -v` |
| Runtime | Unit | 100% | Descriptor access-before-set, `__dict__` bypass, `__init_subclass__` + ABCMeta compat | `uv run pytest tests/unit/runtime/ -v` |
| Decorators | Unit | 100% | Attrs set correctly, stacking works, signatures preserved, `__wrapped__` chain, `functools.wraps` ordering | `uv run pytest tests/unit/decorators/ -v` |
| Manifest | Unit + fixture files | 95% | Schema validation, narrow-only invariant, `yaml.safe_load()` used, path validation | `uv run pytest tests/unit/manifest/ -v` |
| Scanner rules | Unit + corpus specimens | 95% (PY-WL-001–005 only) | Each rule fires on positive specimens, silent on negative; async functions scanned; `ast.TryStar` (except*) handled by PY-WL-004/005. Corpus-driven tests load YAML fragment specimens via the corpus loader — test fixtures do NOT import the wardline decorator library (corpus isolation per WP-6c). | `uv run pytest tests/unit/scanner/ -v` |
| Scanner discovery | Unit | 95% | All four import alias patterns resolved; `as` rebinding tracked; star import emits WARNING; `importlib.import_module("wardline")` emits WARNING; re-export chain produces UNKNOWN_RAW silently (documented false-negative); `if TYPE_CHECKING` imports ignored | `uv run pytest tests/unit/scanner/test_discovery.py -v` |
| Registry sync | Unit | 100% | Bidirectional check passes; renamed decorator detected; missing registry entry detected; unknown `@wardline`-prefixed decorator in scanned code emits WARNING | `uv run pytest tests/unit/scanner/test_registry_sync.py -v` |
| Manifest coherence | Unit + fixtures | 90% | Orphaned annotations detected; undeclared boundaries detected; tier-distribution ERROR fires when >60% permissive; governance anomaly signals fire for tier downgrade and upgrade-without-evidence | `uv run pytest tests/unit/manifest/test_coherence.py -v` |
| Scanner taint | Unit + integration | 90% | Taint propagation matches spec; both FunctionDef and AsyncFunctionDef | `uv run pytest tests/unit/scanner/test_taint.py -v` |
| SARIF output | Unit + schema validation | 95% | Output validates against SARIF JSON Schema; deterministic; wardline property bags present on all results (`wardline.rule`, `wardline.taintState`, `wardline.severity`, `wardline.exceptionability`, `wardline.analysisLevel`) and on run (`wardline.controlLaw`, `wardline.manifestHash`, `wardline.deterministic`, `wardline.propertyBagVersion`, `wardline.implementedRules`, `wardline.conformanceGaps`). Schema validation alone does not validate extension property bags — explicit assertions required. | `uv run pytest tests/unit/scanner/test_sarif.py -v` |
| CLI | Integration (Click test runner) | 85% | Commands exit 0/1 correctly, output is valid | `uv run pytest tests/integration/ -v` |
| Determinism | Integration (`@pytest.mark.integration`) | Pass/fail | Byte-identical SARIF on repeated runs (single + multi-file) | `uv run pytest tests/integration/test_determinism.py -v` |
| Self-hosting | CI gate (`@pytest.mark.integration`) | Pass/fail + 80% coverage | Wardline scans its own source cleanly; coverage floor met | `uv run pytest tests/integration/test_self_hosting.py -v` |

**Note on 'Coverage Target' column:** For most rows, this column refers to pytest **branch** coverage (not line coverage). Branch coverage is specified because wardline is a governance tool — line coverage misses untested conditional branches that could contain silent failures. Use `--cov-branch` with pytest-cov. The canonical full-suite coverage command is: `uv run pytest --cov=wardline --cov-branch tests/ -v`. For the 'Self-hosting' row, the column refers to the annotation-surface coverage metric (percentage of functions with explicit wardline tier declarations) — a different measurement. See WP-6c for the self-hosting coverage metric definition.

**Test isolation:** `test_self_hosting.py` and `test_determinism.py` MUST be marked with `@pytest.mark.integration` so they never run in the same pytest invocation as unit tests. Unit test runs should be fast and isolated; integration tests exercise the full scanner pipeline and are slower.

## 10. Dependencies

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/wardline"]

[project]
name = "wardline"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "pyyaml>=6.0",
    "jsonschema>=4.20",
    "click>=8.1",
]

[project.scripts]
wardline = "wardline.cli.main:cli"

[project.optional-dependencies]
# Note: these optional dependency groups are **documentary placeholders**, not
# functional isolation. All three runtime deps (pyyaml, jsonschema, click) are in
# the base `dependencies` list, so `pip install wardline` and `pip install
# wardline[scanner]` produce identical installs. The groups document the future
# split boundary: when the package splits into `wardline-decorators` (zero deps)
# and `wardline` (scanner + CLI), the base `dependencies` become empty and these
# groups become the actual dependency specifications. Until the split, they serve
# as documentation of which dep belongs to which component.
scanner = [
    "pyyaml>=6.0",
    "jsonschema>=4.20",
]
cli = [
    "click>=8.1",
]
dev = [
    "pytest>=8.0",
    "pytest-cov>=4.0",
    "mypy>=1.8",
    "ruff>=0.4",
]
```

## 11. Risk Areas

1. **PY-WL-008 (no rejection path):** Requires structural analysis of function bodies — the hardest rule. Valid rejection paths: `raise`, conditional early `return`, call to unconditionally-raising function (2-hop). **NOT valid:** `assert` (stripped by `-O`), `if False: raise` (unreachable — detect constant-False guards), `return None` without preceding conditional (unconditional). Start with the positive heuristic and add negative exclusions.

2. **PY-WL-009 (semantic without shape):** Requires call-graph or annotation ordering. **The MVP approximation (module-level co-presence check) produces false negatives for cross-module flows (the common case)**, since shape validators are typically in `adapters/` while semantic validators are in `domain/`. PY-WL-009 is suppressed entirely in the MVP — do not emit findings. Accurate detection requires Level 2+ taint analysis (WP-7).

3. **Self-hosting bootstrap:** The scanner's own code uses `dict.get()` and `except Exception`. Design `wardline.yaml` module tier declarations for scanner internals BEFORE WP-3 (manifest schema design), not after. If scanner modules are declared at tiers where violations SUPPRESS, the self-hosting gate proves only that tier declarations were chosen to silence findings — not that the code is clean. Use the coverage metric gate (80% floor) to prevent this. Tier-downgrade to unblock development is the path of least resistance; establish a policy that distinguishes legitimate tier assignments from "silence the gate" downgrades.

4. **SARIF property bags:** Custom properties may not display in VS Code SARIF Viewer or GitHub Code Scanning. Test with real consumers early.

5. **Decorator discovery from AST:** Must handle import aliases including `as` rebinding (`from wardline import external_boundary as eb`). Per-file import table approach defined in WP-4b. Star imports (`from wardline import *`) and dynamic imports are documented false-negative surfaces.

6. **`WardlineBase` metaclass compatibility:** `WardlineBase.__init_subclass__` uses cooperative `super()` and does NOT use a metaclass. Tested against `ABCMeta`. Projects using Django's `ModelBase` or SQLAlchemy's `DeclarativeMeta` should work but are untested — document as a known compatibility question.

7. **Registry rename → silent enforcement decay:** If a decorator is renamed in the library but the scanner's registry isn't updated, the function falls to `UNKNOWN_RAW` taint and the self-hosting gate passes (fewer findings = silence). The bidirectional registry check at scan startup (Section 3) prevents this.

8. **Manifest-code drift:** Module renames without manifest updates silently change taint classification to `UNKNOWN_RAW`. The scan-time path validation warning (WP-3c) catches the most common case.

9. **`except*` (ExceptionGroup) handling:** Python 3.11 introduced `except*` blocks for ExceptionGroup handling. The scanner targets Python 3.12+ codebases which may use `except*`. If PY-WL-004 and PY-WL-005 only visit `ast.ExceptHandler` and not `ast.TryStar`, every `except*` block is a systematic false-negative. The risk is proportional to ExceptionGroup adoption in the target codebase.

10. **Phase 2 exception register threat surface:** When the exception register ships in Phase 2, it must implement the spec's required threat controls: agent-authorship detection (spec §9.3), recurrence tracking on (rule, location) tuples (spec §9.4), expedited governance ratio computation (spec §9.4), and governance fatigue detection signals (spec §9.3.2). A Phase 2 implementation that ships the exception register without these controls creates a governance bypass surface — agents can inject exceptions with plausible rationale, renew expired exceptions indefinitely, or overwhelm review capacity with volume. Design the threat control fields into the exceptions schema at WP-3a (see Section 4, WP-3a) so the data model is ready when enforcement logic ships.

## 12. Post-MVP Roadmap

Effort estimates are relative — Phase 2 is the largest, Phase 3 roughly 80% of Phase 2 scope, Phase 4 is the smallest. Actual duration depends on developer count, Python AST familiarity, and ramp-up time.

| Phase | Components | Relative Size |
|-------|-----------|---------------|
| Phase 2 (post-MVP) | Groups 3–17 decorators, overlay system (closing `schema_default()` conformance gap), exception register, fingerprint, PY-WL-006–009, Level 2 taint, full corpus, `wardline explain` | Largest — broadens enforcement surface |
| Phase 3 | Level 3 taint (call-graph), mypy plugin, full governance CLI | Medium — deepens analysis |
| Phase 4 | ruff rules (advisory), runtime enforcement hooks, SARIF aggregation | Smallest — complements existing tools |

**MVP-to-Phase-2 migration considerations:**
- **Migration tool ordering constraint (BLOCKING):** The `--migrate-mvp` command MUST ship in the same release as the overlay system, or before it. It MUST NOT ship after. If the overlay system ships without the migration command, every adopter codebase that accumulated `PY-WL-001-UNVERIFIED-DEFAULT` WARNINGs during MVP will have those findings convert to ERRORs simultaneously with no automated resolution path. This is a non-idempotent state change affecting downstream users without a recovery tool — a migration cliff. Pin this ordering as a blocking dependency in Phase 2 planning.
- **schema_default() triage:** Every `schema_default()`-wrapped `.get()` call accumulated during MVP will emit `PY-WL-001-UNVERIFIED-DEFAULT` WARNING findings. When Phase 2 adds overlay verification, these findings resolve automatically for calls that have matching overlay declarations. Calls without overlay declarations become ERROR findings. The `wardline exception review` command (WP-5c) includes a `--migrate-mvp` flag that re-evaluates MVP-era exceptions and `PY-WL-001-UNVERIFIED-DEFAULT` findings against Phase 2 overlay-verified suppression logic.
- **Exception register entries:** Any exception register entries created during MVP that would have been structurally suppressed (not governance-excepted) under Phase 2 semantics should be flagged for re-review. The `--migrate-mvp` flag handles this.
- **Exception register threat controls (Phase 2 scope note):** The exceptions schema includes `agent_originated`, `recurrence_count`, and `governance_path` fields from day one (WP-3a). However, enforcement logic for these fields is Phase 2 scope. **Adopter warning:** Document explicitly that in MVP, these threat control fields are schema-only — they are recorded but not enforced. Adopters using early builds should not rely on these fields as active governance controls. Phase 2 enforcement includes: agent-authorship detection, recurrence tracking, expedited governance ratio computation, and governance fatigue detection. Consider bringing `agent_originated` field enforcement (tagging, not blocking) forward to MVP-adjacent scope — tagging agent-originated exceptions from day one prevents a data retrofit.
- **SARIF property bag version:** Increment `wardline.propertyBagVersion` from `"0.1"` to `"0.2"` when Phase 2 changes property bag semantics (e.g., adding `MIXED_TRACKED` to `wardline.taintState` enum, adding new rule IDs to `wardline.implementedRules`).
