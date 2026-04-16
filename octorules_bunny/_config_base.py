"""Shared base for config extension hooks (shield config + pull zone security).

Both ``_shield_config.py`` and ``_pullzone_security.py`` use identical
dataclass shapes, diff logic, and formatter methods.  This module
provides the common parts; the two extension modules wire up their
specific normalization and hook registrations.
"""

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model for config diffs
# ---------------------------------------------------------------------------
@dataclass
class ConfigChange:
    """A single field change in a config section."""

    section: str
    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class ConfigPlan:
    """Plan for a set of field-level config changes."""

    changes: list[ConfigChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------
def diff_flat_dicts(section: str, current: dict, desired: dict) -> list[ConfigChange]:
    """Compare two flat dicts and return field-level changes."""
    changes: list[ConfigChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(ConfigChange(section=section, field=key, current=cur, desired=des))
    return changes


# ---------------------------------------------------------------------------
# Formatter (parameterised by provider_id / label prefix)
# ---------------------------------------------------------------------------
class ConfigFormatter:
    """Formats config diffs for plan output.

    Parameterised by *provider_id* (e.g. ``"bunny_shield_config"``)
    which is used for report-mode output.
    """

    def __init__(self, provider_id: str) -> None:
        self._provider_id = provider_id

    # -- active change iterator (skips no-ops) --
    @staticmethod
    def _iter_changes(plans: list):
        for plan in plans:
            if not isinstance(plan, ConfigPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if change.has_changes:
                    yield plan, change

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for _, change in self._iter_changes(plans):
            label = f"{change.section}.{change.field}"
            line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
            lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, ConfigPlan) or not plan.has_changes:
                continue
            changes = [
                {
                    "section": c.section,
                    "field": c.field,
                    "current": c.current,
                    "desired": c.desired,
                }
                for c in plan.changes
                if c.has_changes
            ]
            if changes:
                result.append({"changes": changes})
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for _, change in self._iter_changes(plans):
            label = _md_escape(f"{change.section}.{change.field}")
            cur = _md_escape(repr(change.current))
            des = _md_escape(repr(change.desired))
            lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, ConfigPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"{change.section}.{change.field}")
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = sum(
            1
            for _, change in self._iter_changes(plans)
            if change  # always True, but keeps the generator expression valid
        )
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": self._provider_id.removeprefix("bunny_"),
                    "provider_id": self._provider_id,
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift
