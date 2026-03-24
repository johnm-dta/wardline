# wardline-flake8

Advisory wardline rules for flake8 — fires on structural patterns that `wardline scan` evaluates with full taint context.

## Evidence Pack Warning

**This plugin's output is NOT authoritative and MUST NOT be used in IRAP evidence packs.**

Only `wardline scan` output — which includes taint context, severity grading, and exception register awareness — is valid for compliance evidence. This plugin provides early developer feedback only.

## Installation

```bash
pip install wardline-flake8
```

## Usage

The plugin activates automatically once installed. All codes use the `WL` prefix.

```bash
# Run only wardline rules
flake8 --select=WL .

# Run alongside other plugins
flake8 --extend-select=WL .

# Disable wardline rules in a global run
flake8 --extend-ignore=WL .
```

## Error Codes

| Code | Pattern | Description |
|------|---------|-------------|
| WL001 | `dict.get(key, default)`, `setdefault(key, default)`, `defaultdict(factory)` | Dict key access with fallback default |
| WL002 | `getattr(obj, name, default)` | Attribute access with fallback default |
| WL003 | `key in d`, `hasattr()`, `match/case` | Existence checking as structural gate |
| WL004 | `except Exception`, bare `except:`, `except*` | Broad exception handler |
| WL005 | `except: pass`, `except: ...`, `except: continue/break` | Silent exception handler |

All messages include `[advisory]` to indicate non-authoritative status.

## CI Integration

### Opt-in (recommended)

Add to your CI configuration:

```bash
flake8 --select=WL src/ tests/
```

### Alongside existing flake8 config

```ini
# setup.cfg or .flake8
[flake8]
extend-select = WL
```

### Suppressing individual findings

```python
d.get("key", "default")  # noqa: WL001
```

## Known Limitations

1. **More false positives than `wardline scan`** — no taint context, no exception register.
2. **WL001 fires on `schema_default()` call sites** that `wardline scan` suppresses as governed defaults.
3. **WL003 fires on ALL `in` operators** — no type resolution to distinguish dict/list/set/string.
4. **No exception register awareness** — teams with legitimately excepted findings must use `# noqa`.

## Relationship to wardline scan

This plugin reimplements pattern detection only. For authoritative analysis with taint context, severity grading, and compliance output, run:

```bash
wardline scan --rules=PY-WL-001,PY-WL-002,PY-WL-003,PY-WL-004,PY-WL-005
```
