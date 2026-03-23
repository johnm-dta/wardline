def outer():
    def inner(data):
        x = data.get("key", "default")
    return inner
