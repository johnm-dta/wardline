# PY-WL-006 Semantic Equivalents — Audit-Critical Writes in Broad Handlers

**Framework rule:** WL-005
**Pattern:** Audit-critical writes inside broad exception handlers where the audit failure is masked

| ID | Pattern | Detection | Priority | Agent Likelihood |
|----|---------|-----------|----------|-----------------|
| SE-001 | `audit.emit(event, data)` in broad handler | DETECTED | -- | -- |
| SE-002 | `db.record_failure(data)` in broad handler | DETECTED | -- | -- |
| SE-003 | `@integral_writer` decorated function called in broad handler | DETECTED | -- | -- |
| SE-004 | `@integrity_critical` decorated function called in broad handler | DETECTED | -- | -- |
| SE-005 | Receiver name containing "audit" or "ledger" | DETECTED | -- | -- |
| SE-006 | Audit call wrapped in undecorated helper function | NOT DETECTED | MEDIUM | MODERATE |
| SE-007 | Audit via chained method (`structlog.get_logger().bind().msg()`) | NOT DETECTED | LOW | LOW |
| SE-008 | Audit via ORM create (`AuditEntry.objects.create(...)`) | PARTIALLY (receiver heuristic) | MEDIUM | MODERATE |
| SE-009 | Audit via queue publish (`audit_queue.publish(event)`) | DETECTED (receiver heuristic) | -- | -- |
| SE-010 | Audit via file write (`open("audit.log").write()`) | NOT DETECTED | LOW | LOW |

**Evasion notes:**
- SE-006 (helper wrapping) is the primary evasion — one layer of indirection defeats detection entirely
- The `emit` prefix in `_AUDIT_FUNC_NAMES` is overly broad — matches `signal.emit()`, Socket.IO patterns
- Dominance analysis (success-path audit bypass) has guard-clause false positives
