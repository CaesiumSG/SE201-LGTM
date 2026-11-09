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


def load_env_files(env_files: list[Path]) -> list[Path]:
    """Copy ``KEY=value`` lines from .env files into the environment (values already set win). Returns the files read."""
    read = []
    for path in env_files:
        if not path.is_file():
            continue
        read.append(path)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.removeprefix("export ").strip(), value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value
    return read


def read_bedrock_key(env_files: list[Path]) -> str | None:
    if os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
        return os.environ["AWS_BEARER_TOKEN_BEDROCK"]
    for path in env_files:
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("AWS_BEDROCK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'") or None
    return None
