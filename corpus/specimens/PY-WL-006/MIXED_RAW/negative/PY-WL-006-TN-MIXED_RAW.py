def process():
    try:
        risky()
    except ValueError:
        audit.emit("failed")
