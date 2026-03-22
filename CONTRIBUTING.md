# Contributing to Wardline

Thank you for your interest in contributing to Wardline! This document provides
guidelines and information for contributors.

## Development Setup

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Getting Started

```bash
# Clone the repository
git clone https://github.com/tachyon-beep/wardline.git
cd wardline

# Install dependencies (including dev extras)
uv sync --all-extras

# Run the test suite
uv run pytest

# Run linting
uv run ruff check src/

# Run type checking
uv run mypy src/
```

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`
2. **Write tests** for any new functionality
3. **Ensure all checks pass** before submitting:
   ```bash
   uv run ruff check src/
   uv run mypy src/
   uv run pytest
   ```
4. **Open a pull request** against `main`

## Code Style

- Code is formatted and linted with [Ruff](https://docs.astral.sh/ruff/)
- Type annotations are required — the project uses `mypy --strict`
- Target Python version is 3.12+

## Project Structure

```
src/wardline/
├── core/          # Tier registry, severity, taint matrix
├── decorators/    # @audit, @authority, schema annotations
├── runtime/       # Descriptor-based enforcement
├── manifest/      # YAML manifest loading, merging, coherence
├── scanner/       # AST scanner engine and rules
│   ├── rules/     # PY-WL-001 through PY-WL-005
│   └── taint/     # Function-level taint analysis
└── cli/           # Click-based CLI commands
```

## Scanner Rules

If you're adding a new scanner rule:

1. Create `src/wardline/scanner/rules/py_wl_NNN.py`
2. Subclass the rule base from `rules/base.py`
3. Add test specimens to `corpus/` if applicable
4. Add tests covering positive, negative, and edge cases

## Reporting Bugs

Please use [GitHub Issues](https://github.com/tachyon-beep/wardline/issues) and
include:

- Python version and OS
- Minimal reproduction steps
- Expected vs. actual behavior
- Any relevant `wardline.yaml` configuration

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
