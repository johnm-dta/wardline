"""Group 10 decorators — Data sensitivity.

These decorators mark functions that handle sensitive data categories
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "financial_data",
    "phi_handler",
    "pii_handler",
]

pii_handler = wardline_decorator(
    10,
    "pii_handler",
    _wardline_pii_handler=True,
)

phi_handler = wardline_decorator(
    10,
    "phi_handler",
    _wardline_phi_handler=True,
)

financial_data = wardline_decorator(
    10,
    "financial_data",
    _wardline_financial_data=True,
)
