# Semantic Equivalent Catalogue

**Spec requirement:** Part I SS7 para 2 — "Language bindings MUST maintain version-tracked lists of semantic equivalents for each pattern rule, extending detection coverage as new evasion variants are identified."

**Version:** 1.0.0 (initial catalogue from 35-agent conformance audit, 2026-03-25)

This directory contains one file per binding rule documenting:
- All known syntactic patterns that produce the same semantic effect as the detected pattern
- Detection status (DETECTED / NOT DETECTED / PARTIALLY DETECTED)
- Priority for future detection work (HIGH / MEDIUM / LOW)
- Agent production likelihood (how likely an AI agent is to produce this pattern)

## Files

| Rule | Framework Rule | File |
|------|---------------|------|
| PY-WL-001 | WL-001 (dict access) | [py-wl-001.md](py-wl-001.md) |
| PY-WL-002 | WL-001 (attribute access) | [py-wl-002.md](py-wl-002.md) |
| PY-WL-003 | WL-002 | [py-wl-003.md](py-wl-003.md) |
| PY-WL-004 | WL-003 | [py-wl-004.md](py-wl-004.md) |
| PY-WL-005 | WL-004 | [py-wl-005.md](py-wl-005.md) |
| PY-WL-006 | WL-005 | [py-wl-006.md](py-wl-006.md) |
| PY-WL-007 | WL-006 | [py-wl-007.md](py-wl-007.md) |
| PY-WL-008 | WL-007 | [py-wl-008.md](py-wl-008.md) |
| PY-WL-009 | WL-008 | [py-wl-009.md](py-wl-009.md) |

## Maintenance

When adding new detection patterns or identifying new evasion variants:
1. Update the relevant rule's catalogue file
2. Change detection status as patterns are implemented
3. Bump the version in this README
4. Catalogue changes are tracked in the annotation fingerprint baseline
