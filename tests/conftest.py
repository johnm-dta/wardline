"""Shared test configuration for wardline test suite."""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: integration tests (deselected by default)")
    config.addinivalue_line("markers", "network: tests requiring network access (run weekly)")
