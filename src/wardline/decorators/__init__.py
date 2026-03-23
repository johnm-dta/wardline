"""wardline.decorators — Decorator library for wardline annotations."""

from wardline.decorators.access import requires_auth, requires_role
from wardline.decorators.audit import audit_critical
from wardline.decorators.authority import (
    audit_writer,
    authoritative_construction,
    external_boundary,
    tier1_read,
    validates_external,
    validates_semantic,
    validates_shape,
)
from wardline.decorators.boundaries import tier_transition, trust_boundary
from wardline.decorators.concurrency import process_safe, thread_safe
from wardline.decorators.determinism import deterministic, nondeterministic
from wardline.decorators.lifecycle import deprecated_boundary, experimental
from wardline.decorators.operations import idempotent, retry_safe
from wardline.decorators.plugin import system_plugin
from wardline.decorators.provenance import int_data
from wardline.decorators.safety import fail_safe, fail_secure, graceful_degradation
from wardline.decorators.schema import all_fields_mapped, output_schema, schema_default
from wardline.decorators.secrets import handles_secrets, redacts_output
from wardline.decorators.sensitivity import financial_data, phi_handler, pii_handler

__all__ = [
    "all_fields_mapped",
    "audit_critical",
    "audit_writer",
    "authoritative_construction",
    "deprecated_boundary",
    "deterministic",
    "experimental",
    "external_boundary",
    "fail_safe",
    "fail_secure",
    "financial_data",
    "graceful_degradation",
    "handles_secrets",
    "idempotent",
    "int_data",
    "nondeterministic",
    "output_schema",
    "phi_handler",
    "pii_handler",
    "process_safe",
    "redacts_output",
    "requires_auth",
    "requires_role",
    "retry_safe",
    "schema_default",
    "system_plugin",
    "thread_safe",
    "tier1_read",
    "tier_transition",
    "trust_boundary",
    "validates_external",
    "validates_semantic",
    "validates_shape",
]
