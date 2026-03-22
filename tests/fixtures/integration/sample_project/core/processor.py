"""Fixture: core module with PY-WL-002 and PY-WL-003 patterns.

This file lives under core/ which has PIPELINE default taint
in the fixture manifest.
"""


def process_record(record):
    """PY-WL-002: getattr with fallback default."""
    value = getattr(record, "status", "unknown")
    return value


def check_field(data):
    """PY-WL-003: existence check with 'in' operator."""
    if "required_field" in data:
        return data["required_field"]
    return None


def safe_lookup(obj):
    """PY-WL-003: hasattr existence check."""
    if hasattr(obj, "computed_value"):
        return obj.computed_value
    return None
