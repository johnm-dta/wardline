"""Tests for WL004: broad exception handlers."""

from __future__ import annotations

import ast
import sys

import pytest
from conftest import parse_and_check
from wardline_flake8.wl004 import check_wl004


def test_except_exception_fires():
    source = """\
    try:
        pass
    except Exception:
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert len(results) == 1
    assert "WL004" in results[0][2]
    assert "[advisory]" in results[0][2]


def test_except_base_exception_fires():
    source = """\
    try:
        pass
    except BaseException:
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert len(results) == 1
    assert "WL004" in results[0][2]


def test_bare_except_fires():
    source = """\
    try:
        pass
    except:
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert len(results) == 1
    assert "WL004" in results[0][2]


def test_except_valueerror_clean():
    source = """\
    try:
        pass
    except ValueError:
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert results == []


def test_tuple_handler_with_broad_fires():
    source = """\
    try:
        pass
    except (Exception, ValueError):
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert len(results) == 1
    assert "WL004" in results[0][2]


def test_qualified_name_fires():
    source = """\
    try:
        pass
    except builtins.Exception:
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert len(results) == 1
    assert "WL004" in results[0][2]


@pytest.mark.skipif(
    not hasattr(ast, "TryStar"),
    reason="except* requires Python 3.11+",
)
def test_except_star_broad_fires():
    source = """\
    try:
        pass
    except* Exception:
        pass
    """
    results = parse_and_check(source, check_wl004)
    assert len(results) == 1
    assert "WL004" in results[0][2]
