"""Fixtures."""

from __future__ import annotations

import json
from typing import Any

import pytest
from helpers import VECTORS


@pytest.fixture(scope="session")
def vectors() -> dict[str, Any]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))
