from wardline.decorators import validates_shape

@validates_shape
def check_input(data):
    """Looks like validation but never rejects — always returns data."""
    if not isinstance(data, dict):
        data = {"raw": data}
    return data
