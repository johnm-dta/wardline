"""Group 8 decorators — Secrets handling.

These decorators mark functions that handle secrets or redact output
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "handles_secrets",
    "redacts_output",
]

handles_secrets = wardline_decorator(
    8,
    "handles_secrets",
    _wardline_handles_secrets=True,
)

redacts_output = wardline_decorator(
    8,
    "redacts_output",
    _wardline_redacts_output=True,
)
