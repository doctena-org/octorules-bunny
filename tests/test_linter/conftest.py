"""Shared fixtures for the Bunny Shield linter test suite.

Assertion helpers (``assert_lint``, ``assert_no_lint``) live in
``octorules.testing.lint``; this conftest only ensures Bunny rules are
registered before tests run.
"""

from octorules_bunny.linter import register_bunny_linter

# Ensure Bunny linter rules are registered before any test in this directory runs.
register_bunny_linter()
