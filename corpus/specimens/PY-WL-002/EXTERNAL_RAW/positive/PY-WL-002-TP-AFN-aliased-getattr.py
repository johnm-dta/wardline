def resolve_attribute(obj, name):
    """3-arg getattr looks safe because name is variable, but default is present."""
    value = getattr(obj, name, None)
    return value
