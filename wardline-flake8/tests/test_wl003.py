"""Tests for WL003: existence checking as structural gate."""

from __future__ import annotations

import ast
import sys

import pytest
from conftest import parse_and_check
from wardline_flake8.wl003 import check_wl003


def test_in_operator_fires():
    results = parse_and_check("'key' in d", check_wl003)
    assert len(results) == 1
    assert "WL003" in results[0][2]
    assert "[advisory]" in results[0][2]


def test_hasattr_fires():
    results = parse_and_check("hasattr(obj, 'attr')", check_wl003)
    assert len(results) == 1
    assert "WL003" in results[0][2]


def test_not_in_fires():
    results = parse_and_check("'key' not in d", check_wl003)
    assert len(results) == 1
    assert "WL003" in results[0][2]


@pytest.mark.skipif(
    not hasattr(ast, "MatchMapping"),
    reason="match/case requires Python 3.10+",
)
def test_match_case_mapping_fires():
    source = """\
    match data:
        case {"key": value}:
            pass
    """
    results = parse_and_check(source, check_wl003)
    assert any("WL003" in r[2] for r in results)


def test_clean_no_existence_checks():
    results = parse_and_check("x = 1 + 2", check_wl003)
    assert results == []
