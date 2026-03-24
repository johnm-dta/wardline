"""Tests for WL005: silent exception handlers."""

from __future__ import annotations

from conftest import parse_and_check
from wardline_flake8.wl005 import check_wl005


def test_except_pass_fires():
    source = """\
    try:
        x = 1
    except:
        pass
    """
    results = parse_and_check(source, check_wl005)
    assert len(results) == 1
    assert "WL005" in results[0][2]
    assert "[advisory]" in results[0][2]


def test_except_ellipsis_fires():
    source = """\
    try:
        x = 1
    except:
        ...
    """
    results = parse_and_check(source, check_wl005)
    assert len(results) == 1
    assert "WL005" in results[0][2]


def test_except_continue_fires():
    source = """\
    for i in range(10):
        try:
            x = 1
        except:
            continue
    """
    results = parse_and_check(source, check_wl005)
    assert len(results) == 1
    assert "WL005" in results[0][2]


def test_except_break_fires():
    source = """\
    for i in range(10):
        try:
            x = 1
        except:
            break
    """
    results = parse_and_check(source, check_wl005)
    assert len(results) == 1
    assert "WL005" in results[0][2]


def test_except_log_error_clean():
    source = """\
    try:
        x = 1
    except:
        log.error("failed")
    """
    results = parse_and_check(source, check_wl005)
    assert results == []


def test_mixed_handlers():
    source = """\
    try:
        x = 1
    except ValueError:
        pass
    except TypeError:
        log.error("type error")
    """
    results = parse_and_check(source, check_wl005)
    assert len(results) == 1  # only ValueError:pass fires
