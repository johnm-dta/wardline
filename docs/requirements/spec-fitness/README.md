# Spec Fitness Requirements Baseline

This folder turns the normative Wardline specification in [docs/spec/](/home/john/wardline/docs/spec) into a project-facing requirements baseline that can be tested against the current Python implementation.

The intent is practical fitness assessment, not restating the entire spec. Each requirement here is:

- anchored in one or more normative spec sections
- phrased so it can be verified against the repo
- scoped to the current Wardline Python reference implementation
- tagged with a suggested verification method

Some records also carry `informative_sources` when a non-normative binding section helps interpret how a normative requirement is realised in this repo. Informative sources do not create conformance obligations on their own; they explain implementation shape.

## How To Use It

1. Pick one of the requirement files below.
2. For each requirement, gather evidence from `src/`, `tests/`, `docs/`, generated SARIF, or manifest/schema fixtures.
3. Mark the requirement as:
   - `pass` when the implementation clearly satisfies it
   - `partial` when support exists but the spec contract is incomplete
   - `fail` when the implementation contradicts or omits the requirement
   - `not_assessed` when evidence has not yet been gathered
4. Record the evidence path and any gap notes in the assessment template.

## File Layout

- [01-framework-core.yaml](01-framework-core.yaml): authority model, taint-state invariants, effective-state closure, annotation vocabulary expressiveness
- [02-manifest-governance.yaml](02-manifest-governance.yaml): manifests, overlays, governance profile, coherence checks, agent-authored change detection
- [03-scanner-conformance.yaml](03-scanner-conformance.yaml): scanner rules, corpus, SARIF, living catalogue, taint propagation, corpus independence
- [04-python-binding.yaml](04-python-binding.yaml): Python decorator and runtime contract
- [05-enforcement-layers.yaml](05-enforcement-layers.yaml): §8 enforcement layer requirements — static analysis, structural verification, taint flow, SARIF output
- [06-governance-operations.yaml](06-governance-operations.yaml): §9 governance model operations — exceptionability, fingerprinting, audit logging, control law, exception recurrence
- [07-conformance-profiles.yaml](07-conformance-profiles.yaml): §14 conformance criteria, enforcement/governance profiles, regime documentation, assessment procedure
- [assessment-template.md](assessment-template.md): a lightweight worksheet for a repo fitness pass

## Requirement Schema

Each YAML record uses these fields:

- `id`: stable requirement identifier for local assessment work
- `title`: short human-readable name
- `statement`: the testable requirement
- `normative_sources`: exact normative spec anchors that justify the requirement
- `informative_sources` *(optional)*: non-normative sections that help interpret binding-specific implementation details
- `verification`: suggested assessment approach
- `fitness_dimensions`: what aspect of product fitness this requirement measures
- `notes`: tailoring guidance for this repo

## Spec Coverage

The baseline covers normative requirements from the following spec sections:

| Spec Section | Fitness File(s) | Coverage |
|---|---|---|
| §1 What a Wardline Is | 01-framework-core | Effective-state closure, five required components |
| §2 Problem Statement | 05-enforcement-layers | ACF coverage claims |
| §4–5 Authority Tier Model | 01-framework-core | Taint vocabulary, join algebra, tier mapping, transitions, dependency taint |
| §6 Annotation Vocabulary | 01-framework-core | 17-group expressiveness |
| §7 Pattern Rules | 03-scanner-conformance | Living catalogue, rejection paths, WL-001 suppression, matrix deviations |
| §8 Enforcement Layers | 05-enforcement-layers | Static analysis, structural verification, taint flow, SARIF output |
| §9 Governance Model | 02-manifest, 06-governance | Coherence, exceptionability, fingerprinting, audit logging, control law |
| §10 Verification Properties | 03-scanner, 07-conformance | Corpus, precision/recall, taint propagation, determinism |
| §13 Manifest Format | 02-manifest-governance | Schema validation, overlays, boundaries, contracts, ratification |
| §14 Conformance | 07-conformance-profiles | Ten criteria, profiles, regimes, assessment procedure |
| §A Python Binding | 04-python-binding | AST discovery, decorators, SARIF properties, verification mode |

Sections §3 (non-goals), §11 (language evaluation criteria), §12 (residual risks), and §B (Java binding) are non-normative or out of scope for this Python implementation baseline.

## Scope Notes

- The authoritative source remains `docs/spec/`; if this folder and the normative spec disagree, the spec wins.
- This baseline covers the full normative surface of the spec as it applies to the Python reference implementation.
- The baseline is suitable for manual assessment today and can later be promoted into automated traceability or conformance tooling.
