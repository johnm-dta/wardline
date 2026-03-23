def process(data):
    schema_validated = validate_shape(data)
    if data["status"] == "active":
        pass
