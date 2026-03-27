from wardline import schema_default

def validate_and_default(data):
    """Governed schema_default: boundary + optional_field + matching default."""
    return schema_default(data.get("region", "us-east-1"))
