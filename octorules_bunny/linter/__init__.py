"""Bunny Shield WAF linter — registers all Bunny-specific lint rules and plugins."""

import threading

_registered = False
_register_lock = threading.Lock()


def register_bunny_linter() -> None:
    """Register the Bunny Shield WAF lint plugin and rule definitions.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _registered
    with _register_lock:
        if _registered:
            return

        from octorules.linter.plugin import LintPlugin, register_linter
        from octorules.linter.rules.registry import register_rules

        from octorules_bunny.linter._plugin import BN_RULE_IDS, bunny_lint
        from octorules_bunny.linter._rules import BN_RULE_METAS

        register_linter(LintPlugin(name="bunny", lint_fn=bunny_lint, rule_ids=BN_RULE_IDS))
        register_rules(BN_RULE_METAS)

        _registered = True
