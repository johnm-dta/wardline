def process(data):
    """Looks like fabricated default but uses or-fallback, not .get(key, default)."""
    value = data.get("key") or "fallback_value"
    return value
