def process():
    try:
        risky()
    except ValueError:
        logger.error("failed")
