"""Locks the model-visible text of every agent, tool and the retriever to recorded base values."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tests.model_input_lock.scenarios import GROUPS

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="expected values are rendered on Python >= 3.13",
)

EXPECTED = json.loads((Path(__file__).parent / "expected.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("group", sorted(GROUPS))
def test_model_visible_text_matches_the_recorded_base_values(group, tmp_path):
    actual = GROUPS[group](tmp_path)
    expected = EXPECTED[group]
    assert sorted(actual) == sorted(expected)
    for name in expected:
        assert actual[name] == expected[name], f"{group}/{name} changed"
