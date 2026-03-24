# schema_version: 0.1
from wardline.decorators import external_boundary, validates_shape, tier1_read


@external_boundary
def fetch_data(url: str) -> dict:
    return {}


@validates_shape
def check_schema(data: dict) -> bool:
    if not isinstance(data, dict):
        raise ValueError("not a dict")
    return True


@tier1_read
def get_config() -> dict:
    return {"key": "value"}
