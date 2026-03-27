from wardline.decorators import validates_semantic

@validates_semantic
def check_business_rules(data):
    """Shape check (isinstance) precedes semantic check on subscript access."""
    if not isinstance(data, dict):
        raise TypeError("expected mapping")
    if "priority" in data and data["priority"] > 10:
        raise ValueError("priority exceeds maximum")
    return data
