"""Tests for SUP-001 supplementary decorator contract enforcement."""

from __future__ import annotations

from pathlib import Path

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext
from wardline.scanner.discovery import discover_annotations
from wardline.scanner.rules.sup_001 import RuleSup001

from .conftest import parse_module_source


def _run_rule(
    source: str,
    *,
    file_path: str = "/project/src/service.py",
) -> RuleSup001:
    tree = parse_module_source(source)
    annotations = discover_annotations(tree, Path(file_path))
    annotation_map = {
        qualname: tuple(found)
        for (ann_path, qualname), found in annotations.items()
        if ann_path == file_path
    }
    taint_map = {
        qualname: TaintState.UNKNOWN_RAW
        for qualname in annotation_map
    }
    rule = RuleSup001(file_path=file_path)
    rule.set_context(
        ScanContext(
            file_path=file_path,
            function_level_taint_map=taint_map,
            annotations_map=annotation_map,
        )
    )
    rule.visit(tree)
    return rule


class TestDeterministic:
    def test_random_call_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.determinism import deterministic
import random

@deterministic
def target():
    return random.randint(1, 10)
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.SUP_001

    def test_time_dependent_suppresses(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.determinism import deterministic, time_dependent
import random

@time_dependent
@deterministic
def target():
    return random.randint(1, 10)
"""
        )

        assert len(rule.findings) == 0


class TestParseAtInit:
    def test_parse_call_outside_init_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.safety import parse_at_init

@parse_at_init
def parse_template():
    return 1

def render_row():
    return parse_template()
"""
        )

        assert len(rule.findings) == 1
        assert "@parse_at_init" in rule.findings[0].message

    def test_parse_call_inside_init_is_silent(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.safety import parse_at_init

@parse_at_init
def parse_template():
    return 1

class Renderer:
    def __init__(self):
        self.template = parse_template()
"""
        )

        assert len(rule.findings) == 0


class TestAtomicAndCompensatable:
    def test_atomic_without_transaction_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.operations import atomic

@atomic
def target():
    repo.save()
    audit.write()
"""
        )

        assert len(rule.findings) == 1
        assert "@atomic" in rule.findings[0].message

    def test_compensatable_missing_rollback_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.operations import compensatable

@compensatable(rollback=rollback_order)
def target(order_id):
    return order_id
"""
        )

        assert len(rule.findings) == 1
        assert "rollback function" in rule.findings[0].message


class TestOrderedAfter:
    def test_reversed_order_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.concurrency import ordered_after

@ordered_after("bootstrap")
def start():
    return 1

def run():
    start()
    bootstrap()
"""
        )

        assert len(rule.findings) == 1
        assert "ordered after" in rule.findings[0].message


class TestIdentityAndPrivilege:
    def test_requires_identity_without_audit_arg_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.access import requires_identity
from wardline.decorators.authority import integral_writer

@integral_writer
def audit_log(actor):
    return actor

@requires_identity
def target(user_id):
    audit_log("system")
"""
        )

        assert len(rule.findings) == 1
        assert "identity parameter" in rule.findings[0].message

    def test_privileged_operation_without_auth_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.access import privileged_operation

@privileged_operation
def target():
    db.save()
    authorize()
"""
        )

        assert len(rule.findings) == 1
        assert "authorization check" in rule.findings[0].message


class TestNotReentrantAndDeprecatedBy:
    def test_not_reentrant_direct_cycle_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.concurrency import not_reentrant

@not_reentrant
def target():
    return target()
"""
        )

        assert len(rule.findings) == 1
        assert "call cycle" in rule.findings[0].message

    def test_not_reentrant_mutual_cycle_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.concurrency import not_reentrant

@not_reentrant
def target():
    return helper()

def helper():
    return target()
"""
        )

        assert len(rule.findings) == 1

    def test_deprecated_by_future_is_warning(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.lifecycle import deprecated_by

@deprecated_by(date="2099-12-31", replacement="new_api")
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity.value == "WARNING"

    def test_deprecated_by_past_is_error(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.lifecycle import deprecated_by

@deprecated_by(date="2000-01-01", replacement="new_api")
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity.value == "ERROR"


class TestFeatureGatedAndTestOnly:
    def test_feature_gated_stale_flag_warns(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.lifecycle import feature_gated

@feature_gated(flag="beta")
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert "stale" in rule.findings[0].message
        assert rule.findings[0].severity.value == "WARNING"

    def test_feature_gated_with_gate_reference_is_silent(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.lifecycle import feature_gated

@feature_gated(flag="beta")
def target():
    return flags.enabled("beta")
"""
        )

        assert len(rule.findings) == 0


class TestSensitivityContracts:
    def test_handles_secrets_print_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.secrets import handles_secrets

@handles_secrets
def target(password):
    print(password)
"""
        )

        assert len(rule.findings) == 1
        assert "Secret-bearing data" in rule.findings[0].message

    def test_handles_secrets_hashed_sink_is_silent(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.secrets import handles_secrets

@handles_secrets
def target(password):
    logger.info(hash_value(password))
"""
        )

        assert len(rule.findings) == 0

    def test_handles_pii_logged_field_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import handles_pii

@handles_pii(fields=["email"])
def target(user):
    logger.info(user["email"])
"""
        )

        assert len(rule.findings) == 1
        assert "PII field" in rule.findings[0].message

    def test_handles_secrets_in_exception_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.secrets import handles_secrets

@handles_secrets
def target(password):
    raise ValueError(f"invalid credential: {password}")
"""
        )

        assert len(rule.findings) == 1
        assert "error message" in rule.findings[0].message

    def test_handles_pii_in_exception_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import handles_pii

@handles_pii(fields=["email"])
def target(user):
    raise ValueError(f"bad value for {user['email']}")
"""
        )

        assert len(rule.findings) == 1
        assert "error message" in rule.findings[0].message

    def test_handles_pii_malformed_fields_string_warns(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import handles_pii

@handles_pii(fields="email")
def target(user):
    logger.info(user["email"])
"""
        )

        assert len(rule.findings) == 1
        assert "statically discoverable field" in rule.findings[0].message

    def test_handles_classified_lower_call_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import handles_classified

@handles_classified(level="PROTECTED")
def publish(record):
    return record

@handles_classified(level="SECRET")
def target(record):
    return publish(record)
"""
        )

        assert len(rule.findings) == 1
        assert "without @declassifies" in rule.findings[0].message

    def test_handles_classified_declassifying_call_is_silent(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import declassifies, handles_classified

@handles_classified(level="PROTECTED")
@declassifies(from_level="SECRET", to_level="PROTECTED")
def publish(record):
    if not record:
        raise ValueError("missing")
    return record

@handles_classified(level="SECRET")
def target(record):
    return publish(record)
"""
        )

        assert len(rule.findings) == 0

    def test_declassifies_without_rejection_path_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import declassifies

@declassifies(from_level="SECRET", to_level="PROTECTED")
def target(record):
    return sanitize(record)
"""
        )

        assert len(rule.findings) == 1
        assert "rejection path" in rule.findings[0].message

    def test_declassifies_non_downgrade_fires(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.sensitivity import declassifies

@declassifies(from_level="PROTECTED", to_level="SECRET")
def target(record):
    if not record:
        raise ValueError("missing")
    return record
"""
        )

        assert len(rule.findings) == 1
        assert "must lower classification" in rule.findings[0].message

    def test_test_only_import_from_production_fires(self) -> None:
        producer_path = "/project/tests/helpers.py"
        producer_source = """\
from wardline.decorators.lifecycle import test_only

@test_only
def only_for_tests():
    return 1
"""
        consumer_path = "/project/src/service.py"
        consumer_source = """\
from tests.helpers import only_for_tests

def use_helper():
    return only_for_tests()
"""
        consumer_tree = parse_module_source(consumer_source)
        producer_tree = parse_module_source(producer_source)
        producer_annotations = discover_annotations(producer_tree, Path(producer_path))
        consumer_annotations = discover_annotations(consumer_tree, Path(consumer_path))
        project_annotations = {
            key: tuple(value)
            for key, value in {**producer_annotations, **consumer_annotations}.items()
        }
        rule = RuleSup001(file_path=consumer_path)
        rule.set_context(
            ScanContext(
                file_path=consumer_path,
                function_level_taint_map={},
                annotations_map={},
                project_annotations_map=project_annotations,
                module_file_map={"tests.helpers": producer_path, "src.service": consumer_path},
                string_literal_counts={},
            )
        )
        rule.visit(consumer_tree)

        assert len(rule.findings) == 1
        assert "@test_only" in rule.findings[0].message

    def test_test_only_import_inside_tests_is_silent(self) -> None:
        producer_path = "/project/tests/helpers.py"
        producer_source = """\
from wardline.decorators.lifecycle import test_only

@test_only
def only_for_tests():
    return 1
"""
        consumer_path = "/project/tests/test_service.py"
        consumer_source = """\
from tests.helpers import only_for_tests

def test_use_helper():
    assert only_for_tests() == 1
"""
        consumer_tree = parse_module_source(consumer_source)
        producer_tree = parse_module_source(producer_source)
        producer_annotations = discover_annotations(producer_tree, Path(producer_path))
        consumer_annotations = discover_annotations(consumer_tree, Path(consumer_path))
        project_annotations = {
            key: tuple(value)
            for key, value in {**producer_annotations, **consumer_annotations}.items()
        }
        rule = RuleSup001(file_path=consumer_path)
        rule.set_context(
            ScanContext(
                file_path=consumer_path,
                function_level_taint_map={},
                annotations_map={},
                project_annotations_map=project_annotations,
                module_file_map={"tests.helpers": producer_path, "tests.test_service": consumer_path},
                string_literal_counts={},
            )
        )
        rule.visit(consumer_tree)

        assert len(rule.findings) == 0
