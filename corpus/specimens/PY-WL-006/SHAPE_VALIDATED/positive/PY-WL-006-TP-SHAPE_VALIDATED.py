def process():
    try:
        risky()
    except Exception:
        audit.emit("failed")
