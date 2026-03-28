def get_raw_config(source):
    """First hop: fetches raw config object."""
    return source.load()

def extract_setting(config):
    """Second hop: extracts setting with fallback default."""
    return getattr(config, "timeout", 30)
