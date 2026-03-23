def resolve_audit_field(record):
    x = getattr(record, "verified_by", "system")
