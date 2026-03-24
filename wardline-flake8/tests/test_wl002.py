"""Tests for WL002: getattr with fallback default."""

from __future__ import annotations

from conftest import parse_and_check
from wardline_flake8.wl002 import check_wl002


def test_getattr_three_args_fires():
    results = parse_and_check("getattr(obj, 'name', None)", check_wl002)
    assert len(results) == 1
    assert "WL002" in results[0][2]
    assert "[advisory]" in results[0][2]


def test_getattr_two_args_clean():
    results = parse_and_check("getattr(obj, 'name')", check_wl002)
    assert results == []


def test_getattr_keyword_default_fires():
    results = parse_and_check("getattr(obj, 'name', default=0)", check_wl002)
    assert len(results) == 1
    assert "WL002" in results[0][2]


def test_nested_getattr_fires():
    results = parse_and_check(
        "getattr(getattr(obj, 'a', None), 'b', None)", check_wl002
    )
    assert len(results) == 2
