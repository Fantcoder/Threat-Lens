"""Global pytest fixtures and test configuration for ThreatLens."""

from __future__ import annotations

import pathlib

import pytest


@pytest.fixture
def fixtures_dir() -> pathlib.Path:
    """Return the absolute path to the test fixtures directory."""
    return pathlib.Path(__file__).parent / "fixtures"
