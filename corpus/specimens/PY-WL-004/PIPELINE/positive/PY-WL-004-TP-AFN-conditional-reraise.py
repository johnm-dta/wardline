def process_batch(items):
    """Looks like reraise but condition means some exceptions are swallowed."""
    try:
        result = transform(items)
    except Exception as e:
        if isinstance(e, KeyboardInterrupt):
            raise
        return []
    return result
