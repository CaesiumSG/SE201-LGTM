from __future__ import annotations

import re
import subprocess
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


def resolve_refs(repo: str | Path, base_ref: str, pr_ref: str) -> Mapping[str, str]:
    result = {}
    for label, ref in (("base", base_ref), ("pr", pr_ref)):
        if not ref or "\x00" in ref or ref.startswith("-"):
            raise ValueError(f"cannot resolve {label} ref {ref!r} to a commit")
        try:
            sha = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", f"{ref}^{{commit}}"],
                check=True, capture_output=True, text=True, timeout=60,
            ).stdout.strip().lower()
        except (OSError, subprocess.SubprocessError):
            sha = ""
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError(f"cannot resolve {label} ref {ref!r} to a commit")
        result[label] = sha
    return MappingProxyType(result)
