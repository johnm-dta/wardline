"""Tests for SCN-022: Group 5 field-completeness verification."""

from __future__ import annotations

import ast
import textwrap

from wardline.core.severity import RuleId
from wardline.scanner.rules.scn_022 import RuleScn022


def _run_rule(source: str) -> RuleScn022:
    """Parse module source and run SCN-022."""
    tree = ast.parse(textwrap.dedent(source))
    rule = RuleScn022(file_path="test.py")
    rule.visit(tree)
    return rule


class TestFieldCompleteness:
    def test_all_fields_accessed_silent(self) -> None:
        rule = _run_rule('''
            class DTO:
                name: str
                age: int

            @all_fields_mapped(source="DTO")
            def convert(dto):
                return {"name": dto.name, "age": dto.age}
        ''')
        assert len(rule.findings) == 0

    def test_missing_field_fires(self) -> None:
        rule = _run_rule('''
            class DTO:
                name: str
                age: int
                email: str

            @all_fields_mapped(source="DTO")
            def convert(dto):
                return {"name": dto.name, "age": dto.age}
        ''')
        assert len(rule.findings) == 1
        assert "email" in rule.findings[0].message

    def test_no_source_class_in_file_fires(self) -> None:
        rule = _run_rule('''
            @all_fields_mapped(source="MissingClass")
            def convert(dto):
                return dto.name
        ''')
        assert len(rule.findings) == 1
        assert "MissingClass" in rule.findings[0].message

    def test_bare_all_fields_mapped_silent(self) -> None:
        """@all_fields_mapped without source= cannot be verified — no finding."""
        rule = _run_rule('''
            @all_fields_mapped
            def convert(dto):
                return dto.name
        ''')
        assert len(rule.findings) == 0

    def test_classvar_excluded(self) -> None:
        """ClassVar fields should not be required in mapping."""
        rule = _run_rule('''
            from typing import ClassVar

            class DTO:
                name: str
                _registry: ClassVar[dict] = {}

            @all_fields_mapped(source="DTO")
            def convert(dto):
                return {"name": dto.name}
        ''')
        assert len(rule.findings) == 0

    def test_private_fields_excluded(self) -> None:
        """Fields starting with _ should not be required in mapping."""
        rule = _run_rule('''
            class DTO:
                name: str
                _internal: int

            @all_fields_mapped(source="DTO")
            def convert(dto):
                return {"name": dto.name}
        ''')
        assert len(rule.findings) == 0

    def test_multiple_missing_fields(self) -> None:
        """Multiple unmapped fields produce one finding per field."""
        rule = _run_rule('''
            class DTO:
                name: str
                age: int
                email: str

            @all_fields_mapped(source="DTO")
            def convert(dto):
                return {"name": dto.name}
        ''')
        assert len(rule.findings) == 2
        messages = {f.message for f in rule.findings}
        assert any("age" in m for m in messages)
        assert any("email" in m for m in messages)

    def test_rule_id_is_scn_022(self) -> None:
        rule = _run_rule('''
            class DTO:
                name: str

            @all_fields_mapped(source="DTO")
            def convert(dto):
                pass
        ''')
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.SCN_022
