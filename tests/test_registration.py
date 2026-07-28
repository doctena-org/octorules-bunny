"""Tests that extension registration wires up correctly."""

from octorules.extensions import _format_extensions

import octorules_bunny  # noqa: F401 — triggers __init__.py registration


def _plan_keys() -> set[str]:
    """Plan keys the provider exposes.

    Apply is reached through ``provider.extensions`` rather than a registry,
    so this asserts on what core actually walks.
    """
    from octorules_bunny.provider import BunnyShieldProvider

    inst = object.__new__(BunnyShieldProvider)
    return {e.plan_key() for e in BunnyShieldProvider.extensions.fget(inst)}


# --- pull zone security ---


def test_pullzone_security_format_registered():
    assert "bunny.pullzone_security" in _format_extensions


def test_pullzone_security_apply_registered():
    assert "bunny.pullzone_security" in _plan_keys()
