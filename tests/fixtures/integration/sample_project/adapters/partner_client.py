"""Fixture: adapter module with PY-WL-001 and PY-WL-004 patterns.

This file lives under adapters/ which has EXTERNAL_RAW default taint
in the fixture manifest.
"""


def fetch_partner_data(config):
    """PY-WL-001: dict.get with fallback default."""
    timeout = config.get("timeout", 30)
    return timeout


def parse_response(data):
    """PY-WL-004: broad exception handler."""
    try:
        result = data["value"]
    except Exception:
        result = None
    return result


def retry_request(url):
    """PY-WL-004 + PY-WL-005: broad AND silent handler."""
    try:  # noqa: SIM105 — intentional test fixture for scanner rule detection
        pass
    except Exception:
        pass
