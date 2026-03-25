# Spec Fitness Requirements Baseline

This folder turns the normative Wardline specification in [docs/spec/](/home/john/wardline/docs/spec) into a project-facing requirements baseline that can be tested against the current Python implementation.

The intent is practical fitness assessment, not restating the entire spec. Each requirement here is:

- traceable back to one or more normative spec sections
- phrased so it can be verified against the repo
- scoped to the current Wardline Python reference implementation
- tagged with a suggested verification method

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

- [01-framework-core.yaml](/home/john/wardline/docs/requirements/spec-fitness/01-framework-core.yaml): authority model and taint-state invariants
- [02-manifest-governance.yaml](/home/john/wardline/docs/requirements/spec-fitness/02-manifest-governance.yaml): manifests, overlays, governance, and coherence
- [03-scanner-conformance.yaml](/home/john/wardline/docs/requirements/spec-fitness/03-scanner-conformance.yaml): scanner, corpus, SARIF, and regime-level conformance
- [04-python-binding.yaml](/home/john/wardline/docs/requirements/spec-fitness/04-python-binding.yaml): Python decorator and runtime contract
- [assessment-template.md](/home/john/wardline/docs/requirements/spec-fitness/assessment-template.md): a lightweight worksheet for a repo fitness pass

## Requirement Schema

Each YAML record uses these fields:

- `id`: stable requirement identifier for local assessment work
- `title`: short human-readable name
- `statement`: the testable requirement
- `normative_sources`: exact spec anchors that justify the requirement
- `verification`: suggested assessment approach
- `fitness_dimensions`: what aspect of product fitness this requirement measures
- `notes`: tailoring guidance for this repo

## Scope Notes

- The authoritative source remains `docs/spec/`; if this folder and the normative spec disagree, the spec wins.
- These requirements are intentionally stronger on areas that are assessable in this repo today: the Python binding, manifest model, scanner engine, SARIF output, governance artefacts, and corpus/test surface.
- This baseline is suitable for manual assessment today and can later be promoted into automated traceability or conformance tooling.
