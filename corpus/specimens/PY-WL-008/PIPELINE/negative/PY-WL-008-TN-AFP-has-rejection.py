from wardline.decorators import validates_shape

@validates_shape
def check_payload(data):
    """Declared boundary that has a rejection path — raise on invalid input."""
    if not isinstance(data, dict):
        raise TypeError("expected dict")
    if "id" not in data:
        raise ValueError("missing required field: id")
    return data
