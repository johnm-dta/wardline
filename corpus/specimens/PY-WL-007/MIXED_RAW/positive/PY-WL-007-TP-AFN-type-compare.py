def normalize(value):
    """type() comparison disguised as isinstance-free but is still runtime type check."""
    if type(value) is str:
        return value.strip()
    if type(value) is int:
        return str(value)
    return repr(value)
