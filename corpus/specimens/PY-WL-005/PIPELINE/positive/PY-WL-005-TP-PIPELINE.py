def process(data):
    for x in data:
        try:
            handle(x)
        except TypeError:
            continue
