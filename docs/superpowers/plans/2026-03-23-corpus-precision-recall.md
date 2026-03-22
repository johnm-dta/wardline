# Corpus Precision/Recall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `wardline corpus verify` to run scanner rules on specimen fragments and compute per-rule precision/recall, with `known_false_negative` excluded from recall.

**Architecture:** The current `corpus_cmds.py` does structural verification (hash + parse). We add a `_evaluate_specimen()` function that runs all rules on the parsed AST and compares fired rules against the specimen's `verdict` and `rule_id`. Results are accumulated in a `_CorpusStats` dataclass that tracks TP/FP/TN/FN/KFN per rule. After all specimens, precision/recall is computed and printed for rules with sample >= 5.

**Tech Stack:** Python 3.12, Click CLI, wardline scanner rules, ast module

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/wardline/cli/corpus_cmds.py` | Modify | Add rule execution, verdict evaluation, precision/recall output |
| `tests/unit/scanner/test_corpus_runner.py` | Modify | Add tests for verdict evaluation + precision/recall |
| `tests/fixtures/corpus/bare_except_tp.yaml` | Modify | Rename `source` to `fragment`, add `rule` field |
| `tests/fixtures/corpus/clean_code_tn.yaml` | Create | True negative fixture specimen |
| `tests/fixtures/corpus/known_fn.yaml` | Create | Known false negative fixture specimen |

## Key Design Decisions

1. **Field name**: Rename internal usage from `source` to `fragment` to match the corpus-specimen schema. Support both for backward compatibility during transition.
2. **Rule execution**: Instantiate rules via `_make_rules()` (same as scan command), run each rule's `visit()` on the parsed AST, collect findings.
3. **Verdict evaluation**: Compare expected rule_id + verdict against whether the rule actually fired.
4. **Precision/recall**: Only print for rules with >= 5 specimens. `known_false_negative` specimens are excluded from recall denominator.

## Terminology

- **TP**: true_positive specimen where expected rule fired
- **FP**: true_negative specimen where a rule fired unexpectedly
- **TN**: true_negative specimen where no rule fired (correct silence)
- **FN**: true_positive specimen where expected rule did NOT fire
- **KFN**: known_false_negative specimen (documented scanner limitation, excluded from recall)

---

### Task 1: Fix field name and add `rule` field to existing fixture

**Files:**
- Modify: `tests/fixtures/corpus/bare_except_tp.yaml`
- Modify: `src/wardline/cli/corpus_cmds.py:58` (field name)

- [ ] **Step 1: Update fixture to use `fragment` and `rule`**

```yaml
# tests/fixtures/corpus/bare_except_tp.yaml
rule: "PY-WL-004"
verdict: "true_positive"
sha256: "<recompute>"
fragment: |
  def target():
      try:
          pass
      except Exception:
          pass
```

Recompute the sha256:
```bash
uv run python -c "
import hashlib
fragment = 'def target():\n    try:\n        pass\n    except Exception:\n        pass\n'
print(hashlib.sha256(fragment.encode()).hexdigest())
"
```

- [ ] **Step 2: Update `corpus_cmds.py` to read `fragment` with `source` fallback**

In `corpus_cmds.py:58`, change:
```python
source = data.get("source", "")
```
to:
```python
source = data.get("fragment", "") or data.get("source", "")
```

And update the error message at line 63:
```python
f"error: {specimen_path.name} has no 'fragment' field",
```

- [ ] **Step 3: Update tests that reference `source` field**

In `tests/unit/scanner/test_corpus_runner.py`, update `TestHashVerification` and `TestSpecimenLoading` test methods: keep using `source:` in YAML strings (backward compat path is tested), but add one test using `fragment:`.

- [ ] **Step 4: Run tests to verify backward compatibility**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py tests/integration/test_corpus_verify.py -m 'not network' -x -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/corpus/bare_except_tp.yaml src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "fix: rename source→fragment in corpus specimens with backward compat"
```

---

### Task 2: Add verdict evaluation logic

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py`
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing tests for verdict evaluation**

Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestVerdictEvaluation:
    """Test specimen verdict evaluation against scanner results."""

    def test_true_positive_rule_fires(self, tmp_path: Path) -> None:
        """TP specimen where expected rule fires → pass."""
        source = "def f():\n    try:\n        pass\n    except Exception:\n        pass\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "1 TP" in result.output or "Lite bootstrap:" in result.output

    def test_true_negative_no_rule_fires(self, tmp_path: Path) -> None:
        """TN specimen where no rule fires → pass."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_negative"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0

    def test_known_false_negative_tracked(self, tmp_path: Path) -> None:
        """KFN specimen is tracked separately, not counted as FN."""
        source = "x = 1\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "kfn.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "known_false_negative"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  x = 1\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "1 KFN" in result.output or "known_false_negative" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestVerdictEvaluation -x -q`
Expected: FAIL

- [ ] **Step 3: Implement verdict evaluation in corpus_cmds.py**

Add to `corpus_cmds.py` — a `_evaluate_specimen()` function and a `_CorpusStats` tracker:

```python
from dataclasses import dataclass, field
from wardline.scanner.rules.base import RuleBase
from wardline.core.severity import RuleId

@dataclass
class _RuleStats:
    """Per-rule verdict counters."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    kfn: int = 0

def _make_rules() -> tuple[RuleBase, ...]:
    """Instantiate all available rule classes."""
    from wardline.scanner.rules.py_wl_001 import RulePyWl001
    from wardline.scanner.rules.py_wl_002 import RulePyWl002
    from wardline.scanner.rules.py_wl_003 import RulePyWl003
    from wardline.scanner.rules.py_wl_004 import RulePyWl004
    from wardline.scanner.rules.py_wl_005 import RulePyWl005
    return (RulePyWl001(), RulePyWl002(), RulePyWl003(), RulePyWl004(), RulePyWl005())

def _run_rules_on_fragment(
    source: str, rules: tuple[RuleBase, ...],
) -> set[str]:
    """Run all rules on a source fragment, return set of fired rule IDs."""
    tree = ast.parse(source)
    fired: set[str] = set()
    for rule in rules:
        if hasattr(rule, "_file_path"):
            rule._file_path = "<specimen>"
        if hasattr(rule, "findings"):
            rule.findings.clear()
        rule.visit(tree)
        if hasattr(rule, "findings") and rule.findings:
            fired.add(str(rule.RULE_ID))
    return fired

def _evaluate_specimen(
    data: dict,
    rules: tuple[RuleBase, ...],
    stats: dict[str, _RuleStats],
) -> str | None:
    """Evaluate a specimen's verdict against scanner results.

    Returns an error message if evaluation finds a mismatch, None if OK.
    """
    rule_id = data.get("rule", data.get("rule_id", ""))
    verdict = data.get("verdict", "")
    source = data.get("fragment", "") or data.get("source", "")

    if not rule_id or not verdict:
        return None  # Skip evaluation for specimens without rule/verdict

    if rule_id not in stats:
        stats[rule_id] = _RuleStats()

    fired = _run_rules_on_fragment(source, rules)
    rule_fired = rule_id in fired

    if verdict == "true_positive":
        if rule_fired:
            stats[rule_id].tp += 1
        else:
            stats[rule_id].fn += 1
    elif verdict == "true_negative":
        if rule_fired:
            stats[rule_id].fp += 1
        else:
            stats[rule_id].tn += 1
    elif verdict == "known_false_negative":
        stats[rule_id].kfn += 1

    return None
```

Then update the `verify()` function to call `_evaluate_specimen()` after hash/parse checks, and print stats.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py -x -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "feat: add verdict evaluation to corpus verify"
```

---

### Task 3: Add precision/recall output

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py`
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing test for precision/recall output**

```python
class TestPrecisionRecall:
    """Test precision/recall calculation and output."""

    def test_precision_recall_printed_when_sample_ge_5(
        self, tmp_path: Path
    ) -> None:
        """Precision/recall printed for rules with >= 5 specimens."""
        # Create 5 TP specimens for PY-WL-004
        for i in range(5):
            source = f"def f{i}():\n    try:\n        pass\n    except Exception:\n        pass\n"
            sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
            specimen = tmp_path / f"tp_{i}.yaml"
            specimen.write_text(
                f'rule: "PY-WL-004"\n'
                f'verdict: "true_positive"\n'
                f'sha256: "{sha}"\n'
                f"fragment: |\n"
                f"  def f{i}():\n"
                f"      try:\n"
                f"          pass\n"
                f"      except Exception:\n"
                f"          pass\n"
            )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "PY-WL-004" in result.output
        assert "precision" in result.output.lower() or "P:" in result.output

    def test_precision_recall_skipped_when_sample_lt_5(
        self, tmp_path: Path
    ) -> None:
        """Precision/recall NOT printed for rules with < 5 specimens."""
        source = "def f():\n    try:\n        pass\n    except Exception:\n        pass\n"
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        # Should NOT show precision/recall for < 5 specimens
        assert "precision" not in result.output.lower()

    def test_kfn_excluded_from_recall(self, tmp_path: Path) -> None:
        """known_false_negative specimens excluded from recall denominator."""
        specimens_data = []
        # 3 TP specimens
        for i in range(3):
            source = f"def f{i}():\n    try:\n        pass\n    except Exception:\n        pass\n"
            specimens_data.append(("true_positive", source))
        # 2 KFN specimens (bring total to 5 but recall denom stays 3)
        for i in range(2):
            source = f"x{i} = 1\n"
            specimens_data.append(("known_false_negative", source))

        for idx, (verdict, source) in enumerate(specimens_data):
            sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
            specimen = tmp_path / f"spec_{idx}.yaml"
            specimen.write_text(
                f'rule: "PY-WL-004"\n'
                f'verdict: "{verdict}"\n'
                f'sha256: "{sha}"\n'
                f"fragment: |\n"
                + "".join(f"  {line}\n" for line in source.splitlines())
            )

        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "2 KFN" in result.output or "KFN: 2" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestPrecisionRecall -x -q`
Expected: FAIL

- [ ] **Step 3: Add precision/recall output to verify command**

After the specimen loop in `verify()`, add stats output:

```python
# Print per-rule stats
for rule_id in sorted(stats):
    s = stats[rule_id]
    sample = s.tp + s.fp + s.tn + s.fn + s.kfn
    parts = []
    if s.tp: parts.append(f"{s.tp} TP")
    if s.tn: parts.append(f"{s.tn} TN")
    if s.fn: parts.append(f"{s.fn} FN")
    if s.fp: parts.append(f"{s.fp} FP")
    if s.kfn: parts.append(f"{s.kfn} KFN")

    line = f"  {rule_id}: {', '.join(parts)}"

    if sample >= 5:
        # Precision = TP / (TP + FP), Recall = TP / (TP + FN)
        # KFN excluded from recall denominator
        precision = s.tp / (s.tp + s.fp) if (s.tp + s.fp) > 0 else 0.0
        recall_denom = s.tp + s.fn  # KFN excluded
        recall = s.tp / recall_denom if recall_denom > 0 else 0.0
        line += f" | precision={precision:.1%} recall={recall:.1%}"

    click.echo(line)
```

- [ ] **Step 4: Run all tests**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py tests/integration/test_corpus_verify.py -m 'not network' -x -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "feat: add per-rule precision/recall to corpus verify"
```

---

### Task 4: Add fixture specimens and run full verification

**Files:**
- Create: `tests/fixtures/corpus/clean_code_tn.yaml`
- Create: `tests/fixtures/corpus/known_fn.yaml`
- Test: integration tests

- [ ] **Step 1: Create TN fixture specimen**

```yaml
# tests/fixtures/corpus/clean_code_tn.yaml
rule: "PY-WL-004"
verdict: "true_negative"
sha256: "<compute>"
fragment: |
  def clean():
      return 42
```

Compute hash:
```bash
uv run python -c "import hashlib; print(hashlib.sha256('def clean():\n    return 42\n'.encode()).hexdigest())"
```

- [ ] **Step 2: Create KFN fixture specimen**

```yaml
# tests/fixtures/corpus/known_fn.yaml
rule: "PY-WL-004"
verdict: "known_false_negative"
sha256: "<compute>"
fragment: |
  x = 1
```

- [ ] **Step 3: Run integration tests**

Run: `uv run pytest tests/integration/test_corpus_verify.py -m integration -x -q`
Expected: all pass, output shows KFN tracking

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest tests/unit/ -q && uv run pytest tests/integration/ -m integration -q && uv run mypy src/ && uv run ruff check src/ tests/`

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/corpus/ src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "feat: complete T-5.4 corpus verify with precision/recall + KFN"
```
