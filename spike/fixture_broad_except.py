"""Fixture file for PY-WL-004 tracer bullet — broad exception handlers.

This file contains sync and async functions with broad exception handlers
that the spike scanner should detect. It is NOT production code — it exists
solely to be parsed by the tracer bullet.
"""

import asyncio


# --- Should trigger PY-WL-004: bare except ---
def sync_bare_except() -> None:
    try:
        _ = 1 / 0
    except:  # noqa: E722
        print("swallowed")


# --- Should trigger PY-WL-004: except Exception ---
def sync_broad_exception() -> None:
    try:
        data = {"key": "value"}
        _ = data["missing"]
    except Exception:
        print("broad handler")


# --- Should trigger PY-WL-004: except Exception as e ---
async def async_broad_exception() -> None:
    try:
        await asyncio.sleep(0)
    except Exception as e:
        print(f"caught: {e}")


# --- Should NOT trigger: specific exception ---
def sync_specific_except() -> None:
    try:
        _ = int("abc")
    except ValueError:
        print("specific handler — OK")


# --- Should NOT trigger: specific exception (async) ---
async def async_specific_except() -> None:
    try:
        await asyncio.sleep(0)
    except asyncio.CancelledError:
        print("specific handler — OK")
