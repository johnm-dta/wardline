def resolve_handler(obj, name):
    """Looks like getattr with default but uses 2-arg form plus separate conditional."""
    handler = getattr(obj, name)
    if handler is None:
        handler = default_handler
    return handler
