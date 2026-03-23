def safe_parse(text):
    try:
        return parse(text)
    except Exception as e:
        log.error("parse failed: %s", e)
        return None
