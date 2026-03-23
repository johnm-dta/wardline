def process(data):
    try:
        x = int(data)
    except (TypeError, ValueError):
        x = 0
