# Conformance Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise conformance evidence from "tooling exists" to "spec requirement satisfied" — per-cell (rule × taint_state) metrics with assessment-grade JSON output, generated conformance status, and a real self-hosting gate.

**Architecture:** Refactor corpus verification from per-rule to per-cell aggregation, add `--json` assessment artefact output, add `corpus publish` command that generates `wardline.conformance.json` with input binding, wire conformance gaps into SARIF from the generated file, and add a self-hosting gate test that reads implemented rules from the scanner's own SARIF.

**Tech Stack:** Python 3.12+, pytest, click, hashlib, JSON, frozen dataclasses

**Spec:** `docs/superpowers/specs/2026-03-27-conformance-evidence-design.md`

---

### Task 1: Replace `_RuleStats` with `_CellStats` keyed by `(rule, taint)`

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:31-43` (dataclass), `211-256` (evaluate), `259-290` (print)
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing tests for per-cell stats**

Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestPerCellStats:
    """Per-cell (rule × taint_state) metric accumulation."""

    def test_cell_stats_keyed_by_rule_and_taint(self) -> None:
        """Stats accumulate per (rule, taint) cell, not per rule."""
        from wardline.cli.corpus_cmds import _CellStats

        stats: dict[tuple[str, str], _CellStats] = {}
        key = ("PY-WL-001", "AUDIT_TRAIL")
        stats[key] = _CellStats()
        stats[key].tp += 1
        assert stats[key].tp == 1
        assert stats[key].sample_size == 1

    def test_cell_stats_different_taints_are_independent(self) -> None:
        """Same rule with different taints accumulate independently."""
        from wardline.cli.corpus_cmds import _CellStats

        stats: dict[tuple[str, str], _CellStats] = {}
        stats[("PY-WL-001", "AUDIT_TRAIL")] = _CellStats(tp=5)
        stats[("PY-WL-001", "EXTERNAL_RAW")] = _CellStats(tp=3, fp=1)
        assert stats[("PY-WL-001", "AUDIT_TRAIL")].tp == 5
        assert stats[("PY-WL-001", "EXTERNAL_RAW")].tp == 3
        assert stats[("PY-WL-001", "EXTERNAL_RAW")].fp == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/scanner/test_corpus_runner.py::TestPerCellStats -v`
Expected: FAIL — `_CellStats` does not exist.

- [ ] **Step 3: Rename `_RuleStats` to `_CellStats`**

In `src/wardline/cli/corpus_cmds.py`, rename the dataclass at line 31:

```python
@dataclass
class _CellStats:
    """Per-cell (rule × taint_state) verdict counters."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    kfn: int = 0

    @property
    def sample_size(self) -> int:
        return self.tp + self.fp + self.tn + self.fn + self.kfn
```

- [ ] **Step 4: Update `_evaluate_specimen()` to key by `(rule_id, taint_state)`**

Change the `stats` parameter type and keying. Replace lines 211-256:

```python
def _evaluate_specimen(
    data: dict[str, object],
    source: str,
    rules: tuple[RuleBase, ...],
    stats: dict[tuple[str, str], _CellStats],
) -> None:
    """Evaluate a specimen's verdict against scanner results."""
    rule_id = str(data.get("rule", "") or data.get("rule_id", ""))
    verdict = str(data.get("verdict", ""))

    if not rule_id or not verdict:
        return

    raw_taint = data.get("taint_state")
    taint_state = str(raw_taint) if raw_taint is not None else "UNKNOWN"

    cell_key = (rule_id, taint_state)
    if cell_key not in stats:
        stats[cell_key] = _CellStats()

    boundaries = _parse_specimen_boundaries(data)
    optional_fields = _parse_specimen_optional_fields(data)
    fired = _run_rules_on_fragment(
        source,
        rules,
        taint_state=str(raw_taint) if raw_taint is not None else None,
        boundaries=boundaries,
        optional_fields=optional_fields,
    )
    rule_fired = rule_id in fired

    if verdict == "true_positive":
        if rule_fired:
            stats[cell_key].tp += 1
        else:
            stats[cell_key].fn += 1
    elif verdict == "true_negative":
        if rule_fired:
            stats[cell_key].fp += 1
        else:
            stats[cell_key].tn += 1
    elif verdict == "known_false_negative":
        if rule_fired:
            click.echo(
                f"notice: {rule_id} fired on KFN specimen — consider promoting to true_positive",
                err=True,
            )
        stats[cell_key].kfn += 1
```

- [ ] **Step 5: Update `_print_stats()` to `_print_cell_stats()`**

Replace the function at lines 259-290 with per-cell output grouped by rule:

```python
def _print_cell_stats(stats: dict[tuple[str, str], _CellStats]) -> None:
    """Print per-cell verdict stats grouped by rule."""
    from wardline.core.matrix import SEVERITY_MATRIX
    from wardline.core.severity import Exceptionability, RuleId, Severity
    from wardline.core.taints import TaintState

    if not stats:
        return

    # Group by rule
    rules_seen: dict[str, list[str]] = {}
    for rule_id, taint_state in sorted(stats):
        rules_seen.setdefault(rule_id, []).append(taint_state)

    cells_measured = 0
    cells_below_floor = 0

    for rule_id in sorted(rules_seen):
        click.echo(f"  {rule_id}:")
        for taint_state in sorted(rules_seen[rule_id]):
            cell_key = (rule_id, taint_state)
            s = stats[cell_key]
            cells_measured += 1

            parts: list[str] = []
            if s.tp:
                parts.append(f"{s.tp}TP")
            if s.tn:
                parts.append(f"{s.tn}TN")
            if s.fn:
                parts.append(f"{s.fn}FN")
            if s.fp:
                parts.append(f"{s.fp}FP")
            if s.kfn:
                parts.append(f"{s.kfn}KFN")

            line = f"    {taint_state}: {', '.join(parts)}"

            # Compute precision/recall
            prec_denom = s.tp + s.fp
            precision = s.tp / prec_denom if prec_denom > 0 else None
            recall_denom = s.tp + s.fn
            recall = s.tp / recall_denom if recall_denom > 0 else None

            if precision is not None or recall is not None:
                metrics: list[str] = []
                if precision is not None:
                    metrics.append(f"P={precision:.0%}")
                if recall is not None:
                    metrics.append(f"R={recall:.0%}")
                line += f" | {' '.join(metrics)}"

            # Floor comparison
            prec_floor, recall_floor = _get_floors(rule_id, taint_state)
            below = False
            if precision is not None and prec_floor is not None and precision < prec_floor:
                line += f" [BELOW precision floor {prec_floor:.0%}]"
                below = True
            if recall is not None and recall_floor is not None and recall < recall_floor:
                line += f" [BELOW recall floor {recall_floor:.0%}]"
                below = True
            if below:
                cells_below_floor += 1

            click.echo(line)

    click.echo(
        f"\n  {cells_measured} cells measured, {cells_below_floor} below floor."
    )
```

- [ ] **Step 6: Add `_get_floors()` helper**

Add before `_print_cell_stats()`:

```python
def _get_floors(
    rule_id: str, taint_state: str
) -> tuple[float | None, float | None]:
    """Return (precision_floor, recall_floor) for a cell.

    Floors from §10 properties 3-4:
    - Precision: 80% (65% for MIXED_RAW)
    - Recall: 90% for UNCONDITIONAL, 70% for STANDARD/RELAXED
    - SUPPRESS cells: no recall floor (no positive specimens expected)
    """
    from wardline.core.matrix import SEVERITY_MATRIX
    from wardline.core.severity import Exceptionability, RuleId, Severity
    from wardline.core.taints import TaintState

    try:
        rid = RuleId(rule_id)
        ts = TaintState(taint_state)
        cell = SEVERITY_MATRIX[(rid, ts)]
    except (ValueError, KeyError):
        return None, None

    if cell.severity == Severity.SUPPRESS:
        # SUPPRESS cells: only check for false positives (precision)
        return 0.80, None

    prec_floor = 0.65 if ts == TaintState.MIXED_RAW else 0.80
    if cell.exceptionability == Exceptionability.UNCONDITIONAL:
        recall_floor = 0.90
    else:
        recall_floor = 0.70

    return prec_floor, recall_floor
```

- [ ] **Step 7: Update the `verify` command to use new stats type**

In the `verify()` function (around line 327), change the stats dict type:

```python
    stats: dict[tuple[str, str], _CellStats] = {}
```

And change the stats printing call from `_print_stats(stats)` to `_print_cell_stats(stats)`.

- [ ] **Step 8: Run tests**

Run: `python -m pytest tests/unit/scanner/test_corpus_runner.py -v`
Expected: All pass (existing tests may need minor fixes for the type change from `dict[str, _RuleStats]` to `dict[tuple[str, str], _CellStats]`). Fix any that reference `_RuleStats` directly.

- [ ] **Step 9: Run full test suite**

Run: `python -m pytest tests/ -x -q`
Expected: All pass.

- [ ] **Step 10: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "refactor(corpus): per-cell (rule × taint) metrics with floor comparison

Replaces per-rule _RuleStats with per-cell _CellStats keyed by
(rule_id, taint_state). Output grouped by rule, precision/recall
per cell, floor comparison from severity matrix."
```

---

### Task 2: Add `--json` assessment artefact output to `corpus verify`

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py` (verify command, add --json flag)
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing tests for JSON output**

Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestCorpusVerifyJson:
    """Assessment-artefact JSON output from corpus verify --json."""

    def test_json_output_has_cells_and_summary(self) -> None:
        """--json produces valid JSON with cells array and summary."""
        import json

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        )
        data = json.loads(result.output)
        assert "cells" in data
        assert "summary" in data
        assert "overall_verdict" in data
        assert isinstance(data["cells"], list)

    def test_json_cell_has_verdict(self) -> None:
        """Each cell has a cell_verdict field."""
        import json

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        )
        data = json.loads(result.output)
        for cell in data["cells"]:
            assert "cell_verdict" in cell
            assert cell["cell_verdict"] in ("PASS", "FAIL", "NO_DATA")

    def test_json_output_deterministic(self) -> None:
        """Two runs produce identical JSON."""
        runner = CliRunner()
        args = ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        r1 = runner.invoke(cli, args)
        r2 = runner.invoke(cli, args)
        assert r1.output == r2.output

    def test_json_overall_verdict(self) -> None:
        """Overall verdict is PASS or FAIL."""
        import json

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(FIXTURE_CORPUS), "--json"]
        )
        data = json.loads(result.output)
        assert data["overall_verdict"] in ("PASS", "FAIL")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/scanner/test_corpus_runner.py::TestCorpusVerifyJson -v`
Expected: FAIL — `--json` flag doesn't exist.

- [ ] **Step 3: Add `--json` flag and `_build_json_report()` function**

Add `--json` option to the `verify` command:

```python
@corpus.command()
@click.option(
    "--corpus-dir",
    type=click.Path(exists=True, file_okay=False),
    default="corpus/",
    help="Directory containing specimen YAML files.",
)
@click.option(
    "--analysis-level",
    type=click.IntRange(1, 3),
    default=1,
    help="Analysis level (1-3). Specimens requiring a higher level are skipped.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output per-cell assessment JSON instead of text.",
)
def verify(corpus_dir: str, analysis_level: int, output_json: bool) -> None:
```

After the stats collection loop, branch on `output_json`:

```python
    if output_json:
        import json as json_mod
        from datetime import UTC, datetime

        report = _build_json_report(stats)
        report["generated_at"] = datetime.now(UTC).isoformat()
        click.echo(json_mod.dumps(report, indent=2, sort_keys=True))
    else:
        click.echo(f"Lite bootstrap: {total} specimens{skip_msg}")
        _print_cell_stats(stats)
```

Add the `_build_json_report()` function:

```python
def _build_json_report(
    stats: dict[tuple[str, str], _CellStats],
) -> dict[str, object]:
    """Build per-cell assessment JSON with verdicts."""
    cells: list[dict[str, object]] = []
    passing = 0
    failing = 0
    no_data = 0
    suppress_count = 0
    below_precision = 0
    below_recall = 0

    for (rule_id, taint_state) in sorted(stats):
        s = stats[(rule_id, taint_state)]
        prec_floor, recall_floor = _get_floors(rule_id, taint_state)

        # Determine if this is a SUPPRESS cell
        is_suppress = prec_floor is not None and recall_floor is None
        # But we need a better check — _get_floors returns (0.80, None) for SUPPRESS
        from wardline.core.matrix import SEVERITY_MATRIX
        from wardline.core.severity import RuleId as _RuleId, Severity as _Sev
        from wardline.core.taints import TaintState as _TS
        try:
            matrix_cell = SEVERITY_MATRIX[(_RuleId(rule_id), _TS(taint_state))]
            is_suppress = matrix_cell.severity == _Sev.SUPPRESS
            exceptionability = str(matrix_cell.exceptionability)
        except (ValueError, KeyError):
            is_suppress = False
            exceptionability = "UNKNOWN"

        if is_suppress:
            suppress_count += 1

        # Compute metrics
        prec_denom = s.tp + s.fp
        precision = round(s.tp / prec_denom, 4) if prec_denom > 0 else None
        recall_denom = s.tp + s.fn
        recall = round(s.tp / recall_denom, 4) if recall_denom > 0 else None

        # Determine cell verdict
        if s.sample_size == 0:
            verdict = "NO_DATA"
            no_data += 1
        elif is_suppress:
            # SUPPRESS cells pass if no false positives
            verdict = "PASS" if s.fp == 0 else "FAIL"
            if verdict == "PASS":
                passing += 1
            else:
                failing += 1
        else:
            below_p = (
                precision is not None
                and prec_floor is not None
                and precision < prec_floor
            )
            below_r = (
                recall is not None
                and recall_floor is not None
                and recall < recall_floor
            )
            if below_p:
                below_precision += 1
            if below_r:
                below_recall += 1
            verdict = "FAIL" if below_p or below_r else "PASS"
            if verdict == "PASS":
                passing += 1
            else:
                failing += 1

        cells.append({
            "rule": rule_id,
            "taint_state": taint_state,
            "exceptionability": exceptionability,
            "suppress": is_suppress,
            "tp": s.tp,
            "tn": s.tn,
            "fp": s.fp,
            "fn": s.fn,
            "kfn": s.kfn,
            "precision": precision,
            "recall": recall,
            "precision_floor": prec_floor,
            "recall_floor": recall_floor,
            "cell_verdict": verdict,
        })

    overall = "PASS" if failing == 0 and no_data == 0 else "FAIL"

    return {
        "format_version": "1.0",
        "overall_verdict": overall,
        "cells": cells,
        "summary": {
            "total_cells": len(cells),
            "measured_cells": passing + failing,
            "suppress_cells": suppress_count,
            "passing_cells": passing,
            "failing_cells": failing,
            "no_data_cells": no_data,
            "cells_below_precision_floor": below_precision,
            "cells_below_recall_floor": below_recall,
        },
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/scanner/test_corpus_runner.py::TestCorpusVerifyJson -v`
Expected: All 4 pass.

- [ ] **Step 5: Run full test suite**

Run: `python -m pytest tests/ -x -q`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "feat(corpus): add --json assessment artefact output with per-cell verdicts"
```

---

### Task 3: Add `corpus publish` command

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py` (add `publish` subcommand)
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestCorpusPublish:
    """Tests for corpus publish command — generates wardline.conformance.json."""

    def test_publish_creates_conformance_json(self, tmp_path: Path) -> None:
        """corpus publish creates wardline.conformance.json."""
        import json

        # Create a minimal self-hosting SARIF file
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "results": [],
                "properties": {
                    "wardline.implementedRules": ["PY-WL-001"],
                    "wardline.inputHash": "sha256:abc",
                    "wardline.manifestHash": "sha256:def",
                },
                "tool": {"driver": {"version": "0.1.0"}},
            }],
        }
        sarif_path = tmp_path / "self-hosting.sarif.json"
        sarif_path.write_text(json.dumps(sarif))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "corpus", "publish",
                "--corpus-dir", str(FIXTURE_CORPUS),
                "--sarif", str(sarif_path),
                "--output", str(tmp_path / "wardline.conformance.json"),
            ],
        )
        assert result.exit_code == 0, f"Failed: {result.output}"
        conf = json.loads((tmp_path / "wardline.conformance.json").read_text())
        assert "corpus_verdict" in conf
        assert "self_hosting_verdict" in conf
        assert "inputs" in conf
        assert "gaps" in conf

    def test_publish_inputs_binding(self, tmp_path: Path) -> None:
        """Published conformance file includes input identity hashes."""
        import json

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "results": [],
                "properties": {
                    "wardline.implementedRules": ["PY-WL-001"],
                    "wardline.inputHash": "sha256:abc123",
                    "wardline.manifestHash": "sha256:manifest456",
                },
                "tool": {"driver": {"version": "0.1.0"}},
            }],
        }
        sarif_path = tmp_path / "self-hosting.sarif.json"
        sarif_path.write_text(json.dumps(sarif))

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "corpus", "publish",
                "--corpus-dir", str(FIXTURE_CORPUS),
                "--sarif", str(sarif_path),
                "--output", str(tmp_path / "wardline.conformance.json"),
            ],
        )
        conf = json.loads((tmp_path / "wardline.conformance.json").read_text())
        inputs = conf["inputs"]
        assert inputs["tool_version"] == "0.1.0"
        assert inputs["self_hosting_input_hash"] == "sha256:abc123"
        assert inputs["manifest_hash"] == "sha256:manifest456"
        assert "corpus_hash" in inputs
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/scanner/test_corpus_runner.py::TestCorpusPublish -v`
Expected: FAIL — `corpus publish` command doesn't exist.

- [ ] **Step 3: Implement `corpus publish` command**

Add to `src/wardline/cli/corpus_cmds.py`:

```python
@corpus.command()
@click.option(
    "--corpus-dir",
    type=click.Path(exists=True, file_okay=False),
    default="corpus/",
    help="Corpus specimen directory.",
)
@click.option(
    "--sarif",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Self-hosting SARIF output file from a previous scan.",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False),
    default="wardline.conformance.json",
    help="Output path for conformance status file.",
)
@click.option(
    "--analysis-level",
    type=click.IntRange(1, 3),
    default=1,
    help="Analysis level (1-3).",
)
def publish(
    corpus_dir: str,
    sarif: str,
    output: str,
    analysis_level: int,
) -> None:
    """Generate wardline.conformance.json from corpus verify + self-hosting SARIF."""
    import json as json_mod
    from datetime import UTC, datetime

    # --- Run corpus verify internally ---
    corpus_path = Path(corpus_dir)
    specimens = sorted(
        list(corpus_path.glob("**/*.yaml"))
        + list(corpus_path.glob("**/*.yml"))
    )

    WardlineSafeLoader = make_wardline_loader()
    rules = make_rules()
    stats: dict[tuple[str, str], _CellStats] = {}
    errors = 0

    for specimen_path in specimens:
        try:
            with open(specimen_path, encoding="utf-8") as f:
                data = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506
        except (OSError, yaml.YAMLError):
            errors += 1
            continue
        if not isinstance(data, dict):
            errors += 1
            continue

        required_level = int(data.get("analysis_level_required", 1))
        if required_level > analysis_level:
            continue

        source = data.get("fragment", "") or data.get("source", "")
        if not source:
            errors += 1
            continue

        actual_hash = hashlib.sha256(str(source).encode("utf-8")).hexdigest()
        if actual_hash != data.get("sha256", ""):
            errors += 1
            continue

        try:
            ast.parse(str(source))
        except SyntaxError:
            errors += 1
            continue

        try:
            _evaluate_specimen(data, str(source), rules, stats)
        except ValueError:
            errors += 1
            continue

    corpus_report = _build_json_report(stats)

    # --- Read self-hosting SARIF ---
    sarif_data = json_mod.loads(Path(sarif).read_text(encoding="utf-8"))
    run = sarif_data["runs"][0]
    run_props = run.get("properties", {})
    implemented_rules = set(run_props.get("wardline.implementedRules", []))

    # Count unexcepted findings for implemented rules
    unexcepted = 0
    for result in run.get("results", []):
        rule_id = result.get("ruleId", "")
        if rule_id not in implemented_rules:
            continue
        props = result.get("properties", {})
        if "wardline.exceptionId" in props:
            continue
        unexcepted += 1

    self_hosting_verdict = "PASS" if unexcepted == 0 else "FAIL"

    # --- Compute corpus hash (full artefact set) ---
    corpus_hash = _compute_corpus_hash(corpus_path)

    # --- Build gaps list ---
    gaps: list[str] = []
    if corpus_report["overall_verdict"] == "FAIL":
        failing = corpus_report["summary"]["failing_cells"]
        gaps.append(f"{failing} corpus cell(s) below floor")
    if self_hosting_verdict == "FAIL":
        gaps.append(f"{unexcepted} unexcepted self-hosting finding(s)")
    # Known deferred gap
    gaps.append("adversarial corpus below full floor (deferred)")

    # --- Assemble conformance status ---
    tool_version = run.get("tool", {}).get("driver", {}).get("version", "unknown")

    conformance = {
        "format_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "inputs": {
            "tool_version": tool_version,
            "commit_ref": run_props.get("wardline.commitRef", "unknown"),
            "manifest_hash": run_props.get("wardline.manifestHash", "unknown"),
            "corpus_hash": corpus_hash,
            "self_hosting_input_hash": run_props.get("wardline.inputHash", "unknown"),
        },
        "corpus_verdict": corpus_report["overall_verdict"],
        "self_hosting_verdict": self_hosting_verdict,
        "gaps": gaps,
        "corpus_cells_failing": [
            c for c in corpus_report["cells"]
            if c["cell_verdict"] == "FAIL"
        ],
        "self_hosting_unexcepted_findings": unexcepted,
    }

    Path(output).write_text(
        json_mod.dumps(conformance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    click.echo(
        f"Conformance status written to {output} "
        f"(corpus={corpus_report['overall_verdict']}, "
        f"self-hosting={self_hosting_verdict}, "
        f"{len(gaps)} gap(s))"
    )
```

- [ ] **Step 4: Add `_compute_corpus_hash()` helper**

Add before the `publish` command:

```python
def _compute_corpus_hash(corpus_path: Path) -> str:
    """Hash-of-hashes over the full corpus artefact set.

    Covers specimen YAML files, corpus_manifest.json, and schema files.
    Uses the same §10.1 construction as inputHash.
    """
    all_files = sorted(
        list(corpus_path.glob("**/*.yaml"))
        + list(corpus_path.glob("**/*.yml"))
        + list(corpus_path.glob("**/*.json"))
    )

    records: list[str] = []
    for fp in all_files:
        resolved = fp.resolve()
        try:
            rel = resolved.relative_to(corpus_path.resolve())
        except ValueError:
            rel = resolved
        normalized = rel.as_posix()
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        records.append(f"{normalized}\x00{digest}")

    records.sort()
    combined = "".join(r + "\n" for r in records)
    return "sha256:" + hashlib.sha256(combined.encode("utf-8")).hexdigest()
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/unit/scanner/test_corpus_runner.py::TestCorpusPublish -v`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "feat(corpus): add 'corpus publish' command generating wardline.conformance.json"
```

---

### Task 4: Wire `conformanceGaps` from generated file into SARIF

**Files:**
- Modify: `src/wardline/scanner/sarif.py:227-228` (add field), `283` (replace hardcoded `[]`)
- Modify: `src/wardline/cli/scan.py` (read conformance file, pass to SarifReport)
- Modify: `.github/CODEOWNERS`
- Test: `tests/unit/scanner/test_sarif.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/scanner/test_sarif.py` inside `TestSarifPropertyBags`:

```python
    def test_conformance_gaps_from_field(self) -> None:
        """conformanceGaps populated from field, not hardcoded."""
        report = SarifReport(
            findings=[],
            conformance_gaps=("gap A", "gap B"),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.conformanceGaps"] == ["gap A", "gap B"]

    def test_conformance_gaps_default_empty(self) -> None:
        """No gaps declared = empty list."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.conformanceGaps"] == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/scanner/test_sarif.py::TestSarifPropertyBags::test_conformance_gaps_from_field -v`
Expected: FAIL — `SarifReport` has no `conformance_gaps` field.

- [ ] **Step 3: Add `conformance_gaps` field to `SarifReport`**

In `src/wardline/scanner/sarif.py`, add after `coverage_ratio`:

```python
    coverage_ratio: float | None = None
    conformance_gaps: tuple[str, ...] = ()
```

Replace the hardcoded line in `to_dict()`:

```python
                "wardline.conformanceGaps": [],
```

with:

```python
                "wardline.conformanceGaps": list(self.conformance_gaps),
```

- [ ] **Step 4: Add conformance file reading in `scan.py`**

Add a helper function in `src/wardline/cli/scan.py` (after the existing helpers):

```python
def _read_conformance_gaps(manifest_path: Path) -> tuple[str, ...]:
    """Read conformance gaps from wardline.conformance.json.

    Returns gap strings from the generated conformance status file.
    If the file is absent or stale, returns a gap describing that.
    """
    import json

    conf_path = manifest_path.parent / "wardline.conformance.json"
    if not conf_path.exists():
        return ("conformance status not generated — run 'wardline corpus publish'",)

    try:
        data = json.loads(conf_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ("conformance status file unreadable",)

    # Staleness check: compare input identities
    import wardline as _pkg
    inputs = data.get("inputs", {})

    stale_reasons: list[str] = []
    if inputs.get("tool_version") != _pkg.__version__:
        stale_reasons.append("tool_version")
    if inputs.get("manifest_hash") != _compute_manifest_hash(manifest_path):
        stale_reasons.append("manifest_hash")

    if stale_reasons:
        return (
            f"conformance status stale — {', '.join(stale_reasons)} changed",
            *tuple(data.get("gaps", [])),
        )

    return tuple(data.get("gaps", []))
```

Then in the SARIF construction section, before building `SarifReport`, add:

```python
    conformance_gaps = _read_conformance_gaps(manifest_path)
```

And pass it to the `SarifReport` constructor:

```python
        conformance_gaps=conformance_gaps,
```

- [ ] **Step 5: Add `wardline.conformance.json` to `.github/CODEOWNERS`**

```
# Conformance status (generated by corpus publish)
wardline.conformance.json          @wardline/maintainers
```

- [ ] **Step 6: Run tests**

Run: `python -m pytest tests/unit/scanner/test_sarif.py -v`
Expected: All pass.

Run: `python -m pytest tests/ -x -q`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/scanner/sarif.py src/wardline/cli/scan.py .github/CODEOWNERS tests/unit/scanner/test_sarif.py
git commit -m "feat(sarif): wire conformanceGaps from generated wardline.conformance.json

Replaces hardcoded [] with generated evidence. Checks tool_version
and manifest_hash staleness. Reports absent file as a gap."
```

---

### Task 5: Self-hosting gate test

**Files:**
- Modify: `tests/integration/test_self_hosting_scan.py`

- [ ] **Step 1: Add the self-hosting gate test**

Add to `tests/integration/test_self_hosting_scan.py` inside `TestSelfHostingScan`:

```python
    def test_self_hosting_passes_own_rules(self) -> None:
        """Scanner passes the rules it implements on its own source (§10 property 2).

        Reads implementedRules from the SARIF output and asserts zero
        unexcepted findings for those rules. This is the real self-hosting
        gate — not stability checking, but compliance checking.
        """
        import json

        exit_code, output = _run_scan()

        sarif = json.loads(_extract_sarif_json(output))
        run = sarif["runs"][0]
        props = run["properties"]

        # Get implemented rules from the scanner's own declaration
        implemented = set(props["wardline.implementedRules"])

        # Find unexcepted findings for implemented rules
        unexcepted: list[dict[str, object]] = []
        for result in run["results"]:
            rule_id = result.get("ruleId", "")
            if rule_id not in implemented:
                continue
            result_props = result.get("properties", {})
            if "wardline.exceptionId" in result_props:
                continue
            unexcepted.append(result)

        assert len(unexcepted) == 0, (
            f"Self-hosting gate: {len(unexcepted)} unexcepted finding(s) "
            f"for implemented rules. The scanner's own source must pass "
            f"all rules it implements, or have active exceptions.\n"
            + "\n".join(
                f"  {r['ruleId']} at {r['locations'][0]['physicalLocation']['artifactLocation']['uri']}"
                f":{r['locations'][0]['physicalLocation']['region']['startLine']}"
                for r in unexcepted[:10]
            )
        )
```

- [ ] **Step 2: Run the test**

Run: `python -m pytest tests/integration/test_self_hosting_scan.py::TestSelfHostingScan::test_self_hosting_passes_own_rules -v -m integration`
Expected: This may PASS (if all findings have exceptions) or FAIL (if the codebase has unexcepted findings). If it fails, the failures are real self-hosting violations that need either code fixes or exceptions.

- [ ] **Step 3: Handle failures if any**

If the test fails, add exception entries for the specific findings via `wardline exception add` or fix the underlying code. This is expected — the purpose of the gate is to surface these.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_self_hosting_scan.py
git commit -m "feat(self-hosting): add real compliance gate — zero unexcepted findings for implemented rules"
```

---

### Task 6: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `python -m pytest tests/ -x -q`
Expected: All pass.

- [ ] **Step 2: Run corpus verify with JSON output**

```bash
wardline corpus verify --json 2>/dev/null | python -c "
import json, sys
d = json.load(sys.stdin)
print(f\"Overall: {d['overall_verdict']}\")
s = d['summary']
print(f\"Cells: {s['measured_cells']} measured, {s['passing_cells']} pass, {s['failing_cells']} fail\")
print(f\"Below floor: {s['cells_below_precision_floor']} precision, {s['cells_below_recall_floor']} recall\")
"
```

Expected: Per-cell metrics with verdicts.

- [ ] **Step 3: Run corpus publish**

```bash
wardline scan src/wardline --manifest wardline.yaml --allow-registry-mismatch -o /tmp/self-hosting.sarif.json 2>/dev/null
wardline corpus publish --sarif /tmp/self-hosting.sarif.json --output wardline.conformance.json
```

Expected: `wardline.conformance.json` created with corpus and self-hosting verdicts.

- [ ] **Step 4: Verify SARIF conformance gaps**

```bash
wardline scan src/wardline --manifest wardline.yaml --allow-registry-mismatch 2>/dev/null | python -c "
import json, sys
d = json.load(sys.stdin)
gaps = d['runs'][0]['properties']['wardline.conformanceGaps']
print(f'Conformance gaps ({len(gaps)}):')
for g in gaps:
    print(f'  - {g}')
"
```

Expected: Gaps populated from generated file (not hardcoded `[]`).
