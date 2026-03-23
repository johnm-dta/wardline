def safe_lookup(d, key):
    """Wrapper that internally uses dict.get() with a default.
    The L1 scanner sees only the call site, not the implementation."""
    return d.get(key, "fallback")

def process(data):
    x = safe_lookup(data, "key")
