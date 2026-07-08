"""Shared base for config extension hooks (shield config + pull zone security).

Both ``_shield_config.py`` and ``_pullzone_security.py`` diff flat
``{field: value}`` dicts per section.  The data model and all plan-output
formatting come from octorules' public settings framework; the section
path is carried inside ``field`` (e.g. ``"waf.enabled"``) so the core
formatter renders bunny's ``section.field`` labels unchanged, while
``section`` / ``leaf`` stay available to the apply paths.
"""

from octorules.extensions import SettingsChange, SettingsFormatter, SettingsPlan

ConfigPlan = SettingsPlan


class ConfigChange(SettingsChange):
    """A single field change in a config section.

    Constructed as ``ConfigChange(section, field, current, desired)``;
    stored with the section joined into ``field`` so the inherited
    formatter renders the ``section.field`` label directly.
    """

    def __init__(self, section: str, field: str, current: object, desired: object) -> None:
        super().__init__(field=f"{section}.{field}", current=current, desired=desired)
        self.section = section
        self.leaf = field


def diff_flat_dicts(section: str, current: dict, desired: dict) -> list[ConfigChange]:
    """Compare two flat dicts and return field-level changes."""
    changes: list[ConfigChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(ConfigChange(section=section, field=key, current=cur, desired=des))
    return changes


def section_desired(plan: SettingsPlan, section: str) -> dict:
    """Collect a section's changed leaf fields -> desired values.

    Apply paths need the bare leaf names for the provider payload
    builders, one payload per section.
    """
    return {c.leaf: c.desired for c in plan.changes if c.has_changes and c.section == section}


class ConfigFormatter(SettingsFormatter):
    """Formats config diffs for plan output.

    Change fields already carry the section path (``waf.enabled``), so the
    label prefix is empty.
    """

    def __init__(self) -> None:
        super().__init__(
            plan_type=ConfigPlan,
            prefix="",
        )
