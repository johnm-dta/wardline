def process(data):
    method = getattr(data, "get")
    x = method("key", "default")
