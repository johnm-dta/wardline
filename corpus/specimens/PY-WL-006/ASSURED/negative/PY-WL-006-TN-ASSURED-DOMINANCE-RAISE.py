def process():
    if not ok:
        raise ValueError("bad")
    audit.emit("processed", data)
    return result
