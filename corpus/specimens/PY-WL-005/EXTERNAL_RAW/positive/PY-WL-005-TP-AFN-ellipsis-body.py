def try_parse(text):
    """Ellipsis in handler looks like type stub but silently swallows."""
    try:
        return int(text)
    except ValueError:
        ...
