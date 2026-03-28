# Wardline

[![CI](https://github.com/johnm-dta/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/johnm-dta/wardline/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/johnm-dta/wardline/graph/badge.svg)](https://codecov.io/gh/johnm-dta/wardline)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-strict-blue.svg)](https://mypy-lang.org/)

Wardline defines a four-tier trust hierarchy for Python codebases and statically verifies that data flows respect those boundaries. It catches trust-boundary violations — untrusted input reaching privileged code, missing validation at tier transitions — via AST analysis with taint propagation. Results are emitted as SARIF v2.1.0 for direct integration with GitHub Code Scanning and CI pipelines.

## Install

```bash
pip install wardline
```

Dev setup:

```bash
git clone https://github.com/johnm-dta/wardline.git
cd wardline
uv sync --all-extras
```

## Quickstart

Create `wardline.yaml` in your project root:

```yaml
$schema: "wardline/v0.1"

tiers:
  - id: INTERNAL
    tier: 1
    description: "Trusted internal code"
  - id: BOUNDARY
    tier: 2
    description: "Validated boundary layer"
  - id: EXTERNAL
    tier: 4
    description: "Untrusted external input"

module_tiers:
  - path: "src/myapp/core/"
    tier_id: INTERNAL
  - path: "src/myapp/api/"
    tier_id: EXTERNAL
```

Run the scanner:

```bash
wardline scan src/
```

Violations are reported with rule IDs, file locations, and remediation guidance. Pass `--sarif` to write SARIF output for CI ingestion.

## Architecture

| Subsystem | Description |
|-----------|-------------|
| `core/` | Trust tiers, taint lattice, severity matrix |
| `scanner/` | AST-based static analysis with taint propagation |
| `scanner/rules/` | Pluggable rule implementations (PY-WL-001 through PY-WL-009) |
| `scanner/taint/` | Three-phase taint assignment (variable, function, callgraph) |
| `manifest/` | YAML manifest loading, overlay merge, coherence validation |
| `decorators/` | `@audit`, `@authority`, `@validates_shape` and friends |
| `runtime/` | Descriptor-based boundary enforcement at execution time |
| `cli/` | Click-based CLI (`scan`, `explain`, `manifest`, `corpus`) |

## Rules

| Rule | Detects |
|------|---------|
| PY-WL-001 | Dict key access with fallback default |
| PY-WL-002 | Attribute access with fallback default |
| PY-WL-003 | Existence-checking as structural gate |
| PY-WL-004 | Broad exception handlers |
| PY-WL-005 | Silent exception handlers |
| PY-WL-006 | Audit-critical writes in broad handlers |
| PY-WL-007 | Runtime type-checking on internal data |
| PY-WL-008 | Validation with no rejection path |
| PY-WL-009 | Semantic validation without shape validation |

## Development

```bash
uv run pytest                    # Unit tests
uv run ruff check src/           # Lint
uv run mypy src/                 # Type-check (strict)
```

## Links

[Specification](docs/spec/) | [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md) | [License](LICENSE)
