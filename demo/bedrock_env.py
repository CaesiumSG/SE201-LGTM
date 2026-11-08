"""Bedrock credentials and the shared spend ledger, read without ever printing the key."""

from __future__ import annotations

import json
import os
from pathlib import Path


def ledger_total(path: Path = Path.home() / ".lgtm" / "bedrock-spend.jsonl") -> float:
    total = 0.0
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                total += float(json.loads(line).get("usd") or 0)
            except (ValueError, json.JSONDecodeError, AttributeError):
                continue
    return total


def read_bedrock_key(env_files: list[Path]) -> str | None:
    if os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
        return os.environ["AWS_BEARER_TOKEN_BEDROCK"]
    for path in env_files:
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("AWS_BEDROCK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'") or None
    return None
