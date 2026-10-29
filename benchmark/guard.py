"""Held-out guard: run the synthetic eval split in lgtm mode and report the cases
that flipped from correct to wrong against the previous complete guard run.

Usage: python benchmark/guard.py <results root>

Results land under <results root>/guard/: run/ holds the latest evaluator
output, reference.json the last complete run, flips.json the report.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
GPU_MODEL = "qwen3.8-27b"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: guard.py <results root>", file=sys.stderr)
        return 2
    guard_dir = Path(args[0]).resolve() / "guard"
    run_dir = guard_dir / "run"
    reference_path = guard_dir / "reference.json"

    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))["cases"]
    eval_cases = {c["id"]: c["category"] for c in labels if c.get("split", "eval") == "eval"}

    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    subprocess.run(
        [sys.executable, str(REPO_ROOT / "benchmark" / "evaluate.py"), "--mode", "lgtm",
         "--split", "eval", "--gpu-model", GPU_MODEL, "--output", str(run_dir)],
        check=False, cwd=REPO_ROOT)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True,
                            capture_output=True, check=False).stdout.strip()

    correct: dict[str, bool] = {}
    for cid in eval_cases:
        try:
            value = json.loads((run_dir / f"{cid}.json").read_text(encoding="utf-8")).get("correct")
        except (OSError, ValueError):
            continue
        if isinstance(value, bool):
            correct[cid] = value
    unscored = [cid for cid in eval_cases if cid not in correct]

    reference = None
    if reference_path.is_file():
        reference = json.loads(reference_path.read_text(encoding="utf-8"))["correct"]
    flips = [{"id": cid, "category": eval_cases[cid], "direction": "correct_to_wrong"}
             for cid in eval_cases if reference and reference.get(cid) is True and correct.get(cid) is False]

    report = {"commit": commit, "reference": reference is None, "flips": flips, "unscored": unscored}
    (guard_dir / "flips.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not unscored:
        reference_path.write_text(json.dumps({"commit": commit, "correct": correct}), encoding="utf-8")

    print(f"Guard {'reference run' if reference is None else 'run'} on {commit}: "
          f"{len(flips)} flipped, {len(unscored)} unscored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
