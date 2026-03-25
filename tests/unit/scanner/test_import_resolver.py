"""Tests for import alias resolution."""
from __future__ import annotations

import ast

from wardline.scanner.import_resolver import build_import_alias_map, resolve_call_fqn


class TestBuildImportAliasMap:
    def test_import_module(self) -> None:
        tree = ast.parse("import jsonschema")
        assert build_import_alias_map(tree) == {"jsonschema": "jsonschema"}

    def test_import_module_as_alias(self) -> None:
        tree = ast.parse("import jsonschema as js")
        assert build_import_alias_map(tree) == {"js": "jsonschema"}

    def test_from_import(self) -> None:
        tree = ast.parse("from jsonschema import validate")
        assert build_import_alias_map(tree) == {"validate": "jsonschema.validate"}

    def test_from_import_as_alias(self) -> None:
        tree = ast.parse("from jsonschema import validate as v")
        assert build_import_alias_map(tree) == {"v": "jsonschema.validate"}

    def test_multiple_imports(self) -> None:
        tree = ast.parse("import os\nimport jsonschema as js\nfrom marshmallow import Schema")
        m = build_import_alias_map(tree)
        assert m["os"] == "os"
        assert m["js"] == "jsonschema"
        assert m["Schema"] == "marshmallow.Schema"

    def test_from_import_multiple_names(self) -> None:
        tree = ast.parse("from jsonschema import validate, Draft7Validator")
        m = build_import_alias_map(tree)
        assert m["validate"] == "jsonschema.validate"
        assert m["Draft7Validator"] == "jsonschema.Draft7Validator"

    def test_star_import_not_in_map(self) -> None:
        tree = ast.parse("from jsonschema import *")
        assert build_import_alias_map(tree) == {}

    def test_nested_import_in_function_ignored(self) -> None:
        tree = ast.parse("def f():\n    import jsonschema")
        assert build_import_alias_map(tree) == {}

    def test_empty_module(self) -> None:
        tree = ast.parse("")
        assert build_import_alias_map(tree) == {}

    def test_subpackage_import(self) -> None:
        tree = ast.parse("from jsonschema.validators import Draft7Validator")
        m = build_import_alias_map(tree)
        assert m["Draft7Validator"] == "jsonschema.validators.Draft7Validator"

    def test_dotted_module_import(self) -> None:
        tree = ast.parse("import jsonschema.validators")
        m = build_import_alias_map(tree)
        assert m["jsonschema"] == "jsonschema"

    def test_dotted_module_import_as_alias(self) -> None:
        tree = ast.parse("import jsonschema.validators as jv")
        m = build_import_alias_map(tree)
        assert m["jv"] == "jsonschema.validators"


class TestResolveCallFqn:
    def test_bare_name_local_definition(self) -> None:
        call = ast.parse("validate(data)", mode="eval").body
        fqn = resolve_call_fqn(call, {}, frozenset({"mymod.validate"}), "mymod")
        assert fqn == "mymod.validate"

    def test_bare_name_import_alias(self) -> None:
        call = ast.parse("validate(data)", mode="eval").body
        fqn = resolve_call_fqn(call, {"validate": "jsonschema.validate"}, frozenset(), "mymod")
        assert fqn == "jsonschema.validate"

    def test_bare_name_local_shadows_import(self) -> None:
        call = ast.parse("validate(data)", mode="eval").body
        fqn = resolve_call_fqn(
            call,
            {"validate": "jsonschema.validate"},
            frozenset({"mymod.validate"}),
            "mymod",
        )
        assert fqn == "mymod.validate"

    def test_attribute_call(self) -> None:
        call = ast.parse("js.validate(data)", mode="eval").body
        fqn = resolve_call_fqn(call, {"js": "jsonschema"}, frozenset(), "mymod")
        assert fqn == "jsonschema.validate"

    def test_unresolvable(self) -> None:
        call = ast.parse("unknown(data)", mode="eval").body
        fqn = resolve_call_fqn(call, {}, frozenset(), "mymod")
        assert fqn is None

    def test_nested_attribute_unresolvable(self) -> None:
        """a.b.c() — only single-level attribute resolution supported."""
        call = ast.parse("a.b.c()", mode="eval").body
        fqn = resolve_call_fqn(call, {"a": "pkg"}, frozenset(), "mymod")
        assert fqn is None
