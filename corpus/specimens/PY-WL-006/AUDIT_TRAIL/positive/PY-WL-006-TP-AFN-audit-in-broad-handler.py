def save_record(audit_log, store, record):
    """Audit call inside broad handler — if write fails, handler masks it."""
    try:
        store.write(record)
    except Exception:
        audit_log.emit_event("write_failed", record.id)
