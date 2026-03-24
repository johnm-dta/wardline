"""Tests for WL001: dict.get / setdefault / defaultdict."""

from __future__ import annotations

from conftest import parse_and_check
from wardline_flake8.wl001 import check_wl001


def test_get_with_default_fires():
    results = parse_and_check("d.get('key', 'fallback')", check_wl001)
    assert len(results) == 1
    assert "WL001" in results[0][2]
    assert "[advisory]" in results[0][2]


def test_get_without_default_clean():
    results = parse_and_check("d.get('key')", check_wl001)
    assert results == []


def test_setdefault_with_default_fires():
    results = parse_and_check("d.setdefault('key', [])", check_wl001)
    assert len(results) == 1
    assert "WL001" in results[0][2]


def test_setdefault_without_default_clean():
    results = parse_and_check("d.setdefault('key')", check_wl001)
    assert results == []


def test_defaultdict_with_factory_fires():
    results = parse_and_check("defaultdict(list)", check_wl001)
    assert len(results) == 1
    assert "WL001" in results[0][2]


def test_defaultdict_no_factory_clean():
    results = parse_and_check("defaultdict()", check_wl001)
    assert results == []


def test_nested_get_fires():
    results = parse_and_check("d.get('a', {}).get('b', 0)", check_wl001)
    assert len(results) == 2


def test_non_dict_get_fires_advisory():
    """Non-dict .get() also fires — advisory, no type resolution."""
    results = parse_and_check("cache.get('key', None)", check_wl001)
    assert len(results) == 1
    assert "[advisory]" in results[0][2]
