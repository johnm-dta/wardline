VALID_STATUSES = frozenset({"active", "pending", "closed"})

def validate_status(record):
    """Looks like existence check but is value-membership against constant set."""
    if record.status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {record.status}")
    return record
