def process(data):
    try:
        x = int(data)
    except ValueError:
        log.error("Failed to parse: %s", data)

