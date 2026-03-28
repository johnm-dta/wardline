def process_mixed(trusted_data, raw_input):
    """MIXED_RAW context: broad handler on mixed-tier data."""
    combined = {**trusted_data, "external": raw_input}
    try:
        result = transform(combined)
    except Exception:
        result = fallback(combined)
    return result
