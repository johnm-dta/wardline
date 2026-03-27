from wardline.decorators import validates_semantic

@validates_semantic
def check_constraints(data):
    """Shape check is bare isinstance(data, object) — result discarded, so not real validation."""
    isinstance(data, object)
    if data["priority"] > 100:
        raise ValueError("priority too high")
    return data
