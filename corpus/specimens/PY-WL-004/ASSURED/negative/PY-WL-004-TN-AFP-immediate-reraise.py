def transform(data):
    """Broad handler that immediately re-raises — scanner exempts this pattern."""
    try:
        result = parse_and_validate(data)
    except Exception:
        raise
    return result
