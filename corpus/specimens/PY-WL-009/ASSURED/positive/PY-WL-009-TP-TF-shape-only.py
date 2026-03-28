from wardline.decorators import validates_semantic

def shape_validate(data):
    """Shape validator in a separate function — not visible to semantic boundary."""
    if not isinstance(data, dict):
        raise TypeError("expected dict")
    return data

@validates_semantic
def check_business_logic(data):
    """Semantic boundary has no local shape evidence before subscript access."""
    if data["priority"] > 100:
        raise ValueError("priority too high")
    return data
