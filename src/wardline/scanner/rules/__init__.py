"""Rule registry — shared rule instantiation factory."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wardline.scanner.rules.base import RuleBase


def make_rules() -> tuple[RuleBase, ...]:
    """Instantiate all available rule classes.

    Uses lazy imports to avoid circular-import issues at module level.
    """
    from wardline.scanner.rules.py_wl_001 import RulePyWl001
    from wardline.scanner.rules.py_wl_002 import RulePyWl002
    from wardline.scanner.rules.py_wl_003 import RulePyWl003
    from wardline.scanner.rules.py_wl_004 import RulePyWl004
    from wardline.scanner.rules.py_wl_005 import RulePyWl005
    from wardline.scanner.rules.py_wl_006 import RulePyWl006
    from wardline.scanner.rules.py_wl_007 import RulePyWl007
    from wardline.scanner.rules.py_wl_008 import RulePyWl008
    from wardline.scanner.rules.py_wl_009 import RulePyWl009
    from wardline.scanner.rules.scn_021 import RuleScn021
    from wardline.scanner.rules.sup_001 import RuleSup001

    return (
        RulePyWl001(),
        RulePyWl002(),
        RulePyWl003(),
        RulePyWl004(),
        RulePyWl005(),
        RulePyWl006(),
        RulePyWl007(),
        RulePyWl008(),
        RulePyWl009(),
        RuleScn021(),
        RuleSup001(),
    )
