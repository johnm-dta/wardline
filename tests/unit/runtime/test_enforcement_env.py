"""Tests for WARDLINE_ENFORCE environment variable — subprocess-based.

Uses subprocess (not importlib.reload) to get a clean import state
for each test, ensuring the module-level ``os.environ.get("WARDLINE_ENFORCE")``
path is exercised exactly as it would be in production.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

_SCRIPT = (
    "from wardline.runtime.enforcement import is_enabled; print(is_enabled())"
)


def _run_with_env(env_override: dict[str, str] | None = None) -> str:
    """Run a subprocess that imports enforcement and prints is_enabled().

    Returns the stripped stdout.
    """
    env = {**os.environ}
    # Remove WARDLINE_ENFORCE from inherited env so tests are isolated
    env.pop("WARDLINE_ENFORCE", None)
    if env_override:
        env.update(env_override)

    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode == 0, (
        f"Subprocess failed (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    return result.stdout.strip()


class TestWardlineEnforceEnv:
    def test_wardline_enforce_env_1(self) -> None:
        """WARDLINE_ENFORCE=1 enables enforcement at import time."""
        assert _run_with_env({"WARDLINE_ENFORCE": "1"}) == "True"

    def test_wardline_enforce_env_0(self) -> None:
        """WARDLINE_ENFORCE=0 does NOT enable (strict '1' match only)."""
        assert _run_with_env({"WARDLINE_ENFORCE": "0"}) == "False"

    def test_wardline_enforce_env_true(self) -> None:
        """WARDLINE_ENFORCE=true does NOT enable (strict '1' match only)."""
        assert _run_with_env({"WARDLINE_ENFORCE": "true"}) == "False"

    def test_wardline_enforce_env_absent(self) -> None:
        """No WARDLINE_ENFORCE in environment — disabled."""
        assert _run_with_env() == "False"
