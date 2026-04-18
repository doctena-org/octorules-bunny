"""Bunny Shield WAF linter — registers all Bunny-specific lint rules and plugins."""

from octorules.registration import idempotent_registration


@idempotent_registration
def register_bunny_linter() -> None:
    """Register the Bunny Shield WAF lint plugin and rule definitions."""
    from octorules.linter.plugin import LintPlugin, register_linter
    from octorules.linter.rules.registry import register_rules

    from octorules_bunny.linter._plugin import BN_RULE_IDS, bunny_lint
    from octorules_bunny.linter._rules import BN_RULE_METAS

    register_linter(LintPlugin(name="bunny", lint_fn=bunny_lint, rule_ids=BN_RULE_IDS))
    register_rules(BN_RULE_METAS)
