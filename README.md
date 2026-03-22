# Wardline

Semantic boundary enforcement framework for Python.

Wardline defines trust tiers for your codebase and statically verifies that data
flows respect those boundaries. It catches trust-boundary violations — untrusted
input reaching privileged code, missing validation at tier transitions, and
policy drift — before they reach production.

## Features

- **Tiered trust model** — Assign modules to trust tiers (Tier 1 internal
  through Tier 4 untrusted) with configurable severity and taint propagation.
- **AST scanner** — Static analysis engine with pluggable rules (PY-WL-001
  through PY-WL-005) that detect boundary violations in Python source.
- **SARIF output** — Scanner results in SARIF format for GitHub Code Scanning
  and CI integration.
- **Decorator library** — `@audit`, `@authority`, and schema annotations to mark
  trust transitions directly in code.
- **YAML manifests** — Declare tier assignments and policies in
  `wardline.yaml` with overlay support for monorepos.
- **Runtime enforcement** — Descriptor-based boundary checks at execution time.

## Requirements

- Python 3.12+

## Installation

```bash
pip install wardline
```

For development:

```bash
git clone https://github.com/tachyon-beep/wardline.git
cd wardline
uv sync --all-extras
```

## Quick Start

1. Create a `wardline.yaml` in your project root defining tier assignments:

   ```yaml
   $schema: "wardline/v0.1"

   tiers:
     - id: "INTERNAL"
       tier: 1
       description: "Trusted internal code"
     - id: "EXTERNAL"
       tier: 4
       description: "Untrusted input"

   module_tiers:
     - path: "src/myapp/core/"
       tier_id: "INTERNAL"
     - path: "src/myapp/api/"
       tier_id: "EXTERNAL"
   ```

2. Run the scanner:

   ```bash
   wardline scan src/
   ```

3. Review results — violations are reported with rule IDs, locations, and
   suggested fixes.

## CLI Commands

| Command              | Description                           |
| -------------------- | ------------------------------------- |
| `wardline scan`      | Run the AST scanner against source    |
| `wardline explain`   | Explain a rule or violation           |
| `wardline manifest`  | Validate and inspect manifests        |
| `wardline corpus`    | Manage test corpus specimens          |

## Development

```bash
# Run tests
uv run pytest

# Lint and type-check
uv run ruff check src/
uv run mypy src/

# Run integration tests
uv run pytest -m integration
```

## License

[MIT](LICENSE)
