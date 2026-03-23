def process(data):
    try:
        risky()
    except Exception:
        audit.emit("pipeline_error", data)
