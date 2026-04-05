"""Tests that extension registration wires up correctly."""

from octorules.extensions import _apply_extensions, _format_extensions

import octorules_bunny  # noqa: F401 — triggers __init__.py registration

# --- pull zone security ---


def test_pullzone_security_format_registered():
    assert "bunny_pullzone_security" in _format_extensions


def test_pullzone_security_apply_registered():
    assert "bunny_pullzone_security" in _apply_extensions
