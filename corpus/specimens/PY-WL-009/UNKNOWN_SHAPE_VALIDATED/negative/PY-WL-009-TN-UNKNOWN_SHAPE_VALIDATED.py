def process(data):
    data = ensure_shape(data, required=["status"])
    if data["status"] == "active":
        pass
