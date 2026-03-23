def process():
    try:
        risky()
    except Exception:
        logger.critical("data corruption")
