def process(data):
    try:
        result = data["key"]
    except ValueError:
        raise
