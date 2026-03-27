def validate_payload(data):
    """Shape validation boundary — existence checks here are expected."""
    if "user_id" not in data:
        raise ValueError("missing user_id")
    if "action" not in data:
        raise ValueError("missing action")
    return data
