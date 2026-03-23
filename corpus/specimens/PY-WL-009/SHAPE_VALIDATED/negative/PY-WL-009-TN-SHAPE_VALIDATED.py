def process(data):
    if "status" not in data:
        raise KeyError("missing status")
    if data["status"] == "active":
        pass
