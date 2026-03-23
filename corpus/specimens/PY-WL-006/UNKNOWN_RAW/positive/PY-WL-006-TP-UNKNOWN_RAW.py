def process(data):
    try:
        risky()
    except Exception:
        db.record_failure(data)
