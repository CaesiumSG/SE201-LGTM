"""Run the next unrun batch of 6 real-world cases in lgtm mode and write its bundle.

Usage: python benchmark/real_world/batch.py <results root>

Batches 1-4 walk cases.json in order (6 cases each, two passes). Results land
under <results root>/batch-<n>/; the llm-only control of each case lives once
under <results root>/control/.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from lgtm.config import LGTMConfig  # noqa: E402

_spec = importlib.util.spec_from_file_location("lgtm_bench_evaluate", REPO_ROOT / "benchmark" / "evaluate.py")
evaluate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = evaluate
_spec.loader.exec_module(evaluate)
is_done, load_result = evaluate.is_done, evaluate.load_result

BATCH_SIZE = 6
BATCHES = 4


def _evaluate(*args: str) -> None:
    subprocess.run([sys.executable, str(HERE / "evaluate_real.py"), *args], check=False)


def _cite(path: Path) -> str:
    if path.is_relative_to(REPO_ROOT):
        return path.relative_to(REPO_ROOT).as_posix()
    return path.as_posix()


def _control_ok(path: Path) -> bool:
    data = load_result(path)
    return data is not None and not evaluate.result_is_error(data)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: batch.py <results root>", file=sys.stderr)
        return 2
    root = Path(args[0]).resolve()

    n = next((i for i in range(1, BATCHES + 1) if not (root / f"batch-{i}" / "bundle.json").is_file()), None)
    if n is None:
        print("No batch remains: all four batches are finished.")
        return 0

    endpoint = LGTMConfig().ollama_base_url
    try:
        urllib.request.urlopen(endpoint, timeout=10)
    except OSError as exc:
        print(f"Reviewer endpoint {endpoint} is unreachable ({exc}); no batch started.", file=sys.stderr)
        return 1

    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))["cases"]
    ids = [c["id"] for c in cases]
    start = ((n - 1) % 2) * BATCH_SIZE
    batch_ids = ids[start:start + BATCH_SIZE]
    out = root / f"batch-{n}"
    control = root / "control" / "llm-only"

    lacking = [i for i in batch_ids if not _control_ok(control / f"{i}.json")]
    if lacking:
        _evaluate("--modes", "llm-only", "--output", str(root / "control"), "--cases", *lacking)
    _evaluate("--modes", "lgtm", "--output", str(out), "--cases", *batch_ids, "--resume")

    lgtm_dir = out / "lgtm"
    unfinished = [i for i in batch_ids
                  if not is_done(lgtm_dir / f"{i}.json") or not _control_ok(control / f"{i}.json")]
    if unfinished:
        print(f"Batch {n} unfinished, no bundle written: {', '.join(unfinished)}", file=sys.stderr)
        return 1

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    rows = []
    for i in batch_ids:
        rows.append({
            "id": i,
            "lgtm_correct": (load_result(lgtm_dir / f"{i}.json") or {}).get("correct"),
            "control_correct": (load_result(control / f"{i}.json") or {}).get("correct"),
            "lgtm_result": _cite(lgtm_dir / f"{i}.json"),
        })
    bundle = {
        "batch": n,
        "pass": 1 if n <= 2 else 2,
        "commit": commit,
        "cases": rows,
        "totals": {"lgtm": sum(r["lgtm_correct"] is True for r in rows),
                   "control": sum(r["control_correct"] is True for r in rows)},
    }
    path = out / "bundle.json"
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
