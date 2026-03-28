# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

### Added

- Core data model: tiered trust hierarchy (Tier 1–4) with severity levels and
  taint propagation rules.
- Decorator library: `@audit`, `@authority`, and schema-based boundary
  annotations for marking trust transitions in code.
- Manifest system: YAML-based `wardline.yaml` configuration with overlay
  support, discovery, merge, and coherence validation.
- AST scanner engine with pluggable rule architecture and five built-in rules
  (PY-WL-001 through PY-WL-005).
- Function-level taint analysis for tracking data flow across trust boundaries.
- SARIF output for scanner results, enabling integration with GitHub Code
  Scanning and other SARIF-compatible tools.
- CLI with `scan`, `explain`, `manifest`, and `corpus` command groups.
- Corpus test suite with specimen files for validation.
- Runtime descriptor system for boundary enforcement at execution time.

[Unreleased]: https://github.com/johnm-dta/wardline/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/johnm-dta/wardline/releases/tag/v0.1.0
