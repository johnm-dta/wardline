"""Tests for delegated rejection path resolution in PY-WL-008.

Covers _has_delegated_rejection isolated tests (cases 1-6 from spec)
and integration tests through visit_function (cases 13-23, 29-30).
"""
from __future__ import annotations

import ast
from types import MappingProxyType

from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_008 import RulePyWl008


def _make_context(
    *,
    rejection_path_index: frozenset[str] = frozenset(),
    import_alias_map: dict[str, str] | None = None,
    module_file_map: dict[str, str] | None = None,
    taint_state: TaintState = TaintState.UNKNOWN_RAW,
    file_path: str = "src/myproject/validators.py",
) -> ScanContext:
    return ScanContext(
        file_path=file_path,
        function_level_taint_map=MappingProxyType({}),
        module_file_map=MappingProxyType(module_file_map or {}),
        rejection_path_index=rejection_path_index,
        import_alias_map=MappingProxyType(import_alias_map) if import_alias_map else None,
    )


def _run_rule(source: str, ctx: ScanContext) -> list[object]:
    """Parse source and run PY-WL-008, returning findings."""
    tree = ast.parse(source)
    rule = RulePyWl008(file_path=ctx.file_path)
    rule.set_context(ctx)
    rule.visit(tree)
    return rule.findings


# ---------------------------------------------------------------------------
# Isolated _has_delegated_rejection tests (spec cases 1-6)
# ---------------------------------------------------------------------------


class TestHasDelegatedRejection:
    """Unit tests for _has_delegated_rejection via visit_function."""

    def test_body_calls_function_in_index(self) -> None:
        """Case 1: Body calls function in index → no finding."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    _check(data)
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"myproject.validators._check"}),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_body_calls_function_not_in_index(self) -> None:
        """Case 2: Body calls function NOT in index → finding fires."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    _log(data)
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"myproject.validators._check"}),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 1

    def test_multiple_calls_one_in_index(self) -> None:
        """Case 3: Multiple calls, one in index → no finding."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    _log(data)
    _check(data)
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"myproject.validators._check"}),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_no_calls(self) -> None:
        """Case 4: No calls at all → finding fires."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"something.else"}),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 1

    def test_empty_index_preserves_behavior(self) -> None:
        """Case 29: Empty rejection_path_index → existing behavior preserved."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    _check(data)
    return data
"""
        ctx = _make_context(rejection_path_index=frozenset())
        findings = _run_rule(source, ctx)
        assert len(findings) == 1  # fires because no direct rejection path

    def test_lambda_in_body_not_matched(self) -> None:
        """Case 6: Lambda in body → not matched as delegation."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    f = lambda x: x
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"myproject.validators.<lambda>"}),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 1  # lambda is not a Call to a function in index


# ---------------------------------------------------------------------------
# Integration tests through visit_function (spec cases 13-23)
# ---------------------------------------------------------------------------


class TestDelegatedRejectionIntegration:
    """Integration tests for full delegation resolution path."""

    def test_boundary_calls_known_validator_dotted(self) -> None:
        """Case 15: Boundary calls known validator (dotted name) → no finding."""
        source = """\
import jsonschema
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    jsonschema.validate(data, {})
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"jsonschema.validate"}),
            import_alias_map={"jsonschema": "jsonschema"},
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_boundary_calls_known_validator_bare(self) -> None:
        """Case 16: Boundary calls known validator (bare import) → no finding."""
        source = """\
from jsonschema import validate
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    validate(data, {})
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"jsonschema.validate"}),
            import_alias_map={"validate": "jsonschema.validate"},
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_boundary_calls_known_validator_aliased(self) -> None:
        """Boundary calls known validator via alias → no finding."""
        source = """\
import jsonschema as js
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    js.validate(data, {})
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"jsonschema.validate"}),
            import_alias_map={"js": "jsonschema"},
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_boundary_calls_unknown_third_party(self) -> None:
        """Case 17: Boundary calls unknown third-party → finding fires."""
        source = """\
import unknown_lib
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    unknown_lib.check(data)
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"jsonschema.validate"}),
            import_alias_map={"unknown_lib": "unknown_lib"},
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 1

    def test_boundary_with_direct_raise(self) -> None:
        """Case 19: Boundary with direct raise → no finding (existing logic)."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    if not data:
        raise ValueError("bad")
    return data
"""
        ctx = _make_context(rejection_path_index=frozenset())
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_wrapper_pattern(self) -> None:
        """Case 20: Wrapper pattern → no finding (index expansion)."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    _validate_with_logging(data)
    return data
"""
        # _validate_with_logging is in the index via expansion
        ctx = _make_context(
            rejection_path_index=frozenset({
                "myproject.validators._validate_with_logging",
            }),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_async_boundary_with_delegation(self) -> None:
        """Case 22: Async boundary with delegated rejection → no finding."""
        source = """\
from wardline.decorators import validates_shape

@validates_shape
async def validate_payload(data):
    _check(data)
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"myproject.validators._check"}),
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 0

    def test_validator_in_index_but_empty_context(self) -> None:
        """Case 30: jsonschema.validate() with empty index → fires."""
        source = """\
import jsonschema
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    jsonschema.validate(data, {})
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset(),
            import_alias_map={"jsonschema": "jsonschema"},
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 1  # empty index means no delegation recognized

    def test_boundary_call_in_dead_branch_does_not_suppress(self) -> None:
        """Dead-branch delegated call does not satisfy rejection-path evidence."""
        source = """\
import jsonschema
from wardline.decorators import validates_shape

@validates_shape
def validate_payload(data):
    if False:
        jsonschema.validate(data, {})
    return data
"""
        ctx = _make_context(
            rejection_path_index=frozenset({"jsonschema.validate"}),
            import_alias_map={"jsonschema": "jsonschema"},
            module_file_map={"myproject.validators": "src/myproject/validators.py"},
        )
        findings = _run_rule(source, ctx)
        assert len(findings) == 1
