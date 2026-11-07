"""Outcome types shared by the runner and component modules."""

from __future__ import annotations


class InfraError(Exception):
    """Raised by run_item when a model, judge or dependency fails; the unit is recorded as error."""


class NotScored:
    """Returned by run_item when the unit has no valid output to score."""

    def __init__(self, reason: str):
        self.reason = reason


class ModelSettingMismatch(RuntimeError):
    pass
