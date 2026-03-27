def safe_access(data, key):
    """Existence check disguised as validation via boolean chain."""
    if key in data and len(data[key]) > 0:
        return data[key]
    return None
