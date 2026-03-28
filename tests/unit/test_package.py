"""Smoke test: wardline package is importable."""

import wardline


def test_version_exists() -> None:
    assert wardline.__version__ == "0.4.0"
