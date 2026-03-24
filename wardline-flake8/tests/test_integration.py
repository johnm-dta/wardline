"""Integration tests: entry point registration and flake8 runner."""

from __future__ import annotations

import ast
import importlib.metadata
import subprocess
import sys
import textwrap

import pytest


def test_entry_point_registered():
    """WardlineChecker is registered as flake8.extension entry point."""
    eps = importlib.metadata.entry_points()
    # Python 3.12+ returns a SelectableGroups, older returns dict
    if hasattr(eps, "select"):
        flake8_eps = eps.select(group="flake8.extension")
    else:
        flake8_eps = eps.get("flake8.extension", [])
    wl_eps = [ep for ep in flake8_eps if ep.name == "WL"]
    assert len(wl_eps) == 1
    assert wl_eps[0].value == "wardline_flake8:WardlineChecker"


def test_checker_loads_from_entry_point():
    """Entry point resolves to WardlineChecker class."""
    eps = importlib.metadata.entry_points()
    if hasattr(eps, "select"):
        flake8_eps = eps.select(group="flake8.extension")
    else:
        flake8_eps = eps.get("flake8.extension", [])
    wl_eps = [ep for ep in flake8_eps if ep.name == "WL"]
    cls = wl_eps[0].load()
    assert cls.name == "wardline-flake8"
    assert cls.version == "0.1.0"


def test_all_codes_appear_in_checker():
    """All 5 rule codes should fire on an all-patterns fixture."""
    from wardline_flake8.checker import WardlineChecker

    source = textwrap.dedent("""\
        from collections import defaultdict

        d = {}
        d.get("key", "default")
        getattr(d, "key", None)
        "key" in d
        try:
            pass
        except Exception:
            pass
        defaultdict(list)
    """)
    tree = ast.parse(source)
    checker = WardlineChecker(tree)
    messages = [msg for _, _, msg, _ in checker.run()]

    codes_found = set()
    for msg in messages:
        for code in ("WL001", "WL002", "WL003", "WL004", "WL005"):
            if code in msg:
                codes_found.add(code)

    assert codes_found == {"WL001", "WL002", "WL003", "WL004", "WL005"}


def test_advisory_tag_in_all_messages():
    """Every message must contain [advisory]."""
    from wardline_flake8.checker import WardlineChecker

    source = textwrap.dedent("""\
        d = {}
        d.get("key", "default")
        getattr(d, "key", None)
        "key" in d
        try:
            pass
        except Exception:
            pass
        try:
            pass
        except:
            ...
    """)
    tree = ast.parse(source)
    checker = WardlineChecker(tree)
    for _, _, msg, _ in checker.run():
        assert "[advisory]" in msg, f"Missing [advisory] in: {msg}"


def test_flake8_runner_select_wl(tmp_path):
    """Run flake8 --select=WL on a fixture file and verify output."""
    fixture = tmp_path / "sample.py"
    fixture.write_text(textwrap.dedent("""\
        d = {}
        d.get("key", "default")
        try:
            pass
        except:
            pass
    """))
    result = subprocess.run(
        [sys.executable, "-m", "flake8", "--select=WL", str(fixture)],
        capture_output=True,
        text=True,
    )
    assert "WL001" in result.stdout
    assert "WL004" in result.stdout
    assert "WL005" in result.stdout
