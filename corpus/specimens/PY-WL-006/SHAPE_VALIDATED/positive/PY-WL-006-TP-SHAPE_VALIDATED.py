def process():
    try:
        risky()
    except Exception:
        logger.warning("validation failed")
