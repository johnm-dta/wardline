def process(data):
    if not isinstance(data, dict) or "status" not in data:
        return
    if data["status"] == "active":
        pass
