# Wardline Documentation

## Directory Structure

| Directory | Purpose | Status |
|-----------|---------|--------|
| [spec/](spec/) | Wardline Framework Specification v0.2.0 (normative) | Living reference |
| [design/](design/) | Active design documents and architecture specs | Active |
| [plans/](plans/) | Implementation plans and roadmaps | Active |
| [audits/](audits/) | Conformance audits and remediation tracking | Active |
| [archive/](archive/) | Completed work artifacts (v0.2.0 plans, reviews, research) | Historical |

## Reading Order

1. **New to Wardline?** Start with [spec/wardline-lite.md](spec/wardline-lite.md) for a 5-question practical overview.
2. **Building or reviewing?** The [spec/](spec/) directory contains the full normative specification (Part I framework, Part II language bindings).
3. **Contributing?** Check [plans/2026-03-23-post-mvp-roadmap.md](plans/2026-03-23-post-mvp-roadmap.md) for the release roadmap, then look at active plans for the current milestone.
4. **Auditing?** The [audits/](audits/) directory contains the rule conformance audit and its remediation status.

## Conventions

- **Date-prefixed filenames** (`YYYY-MM-DD-name.md`) indicate when a document was created, not when it was last modified. Use `git log` for modification history.
- **Active vs archived:** If a document's work is fully delivered and merged, it belongs in `archive/`. If it's still consulted for ongoing work, it stays in its category directory.
