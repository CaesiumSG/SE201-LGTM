#!/usr/bin/env python3
"""Live hunt: review recently merged PRs of active projects, with no answer key.

``cases.json`` lists merged PRs (May-Nov 2026) in Python web apps that add
endpoints, permission checks or query code. Unlike the benchmarks there is no
expected verdict: every PR LGTM flags is a lead to verify by hand.

Results go to ``benchmark/results/live_hunt/`` (gitignored) and stay there. A
confirmed vulnerability is reported privately to the maintainers (their
SECURITY.md or GitHub private vulnerability reporting) and is not published,
in this repository or anywhere else, until they have fixed it.

Usage:
    python benchmark/live_hunt/run_live_hunt.py --gpu-model qwen3.8-27b
    python benchmark/live_hunt/run_live_hunt.py --gpu-model qwen3.8-27b \\
        --bedrock-model global.anthropic.claude-sonnet-4-6 --output benchmark/results/live_hunt_sonnet
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent

_spec = importlib.util.spec_from_file_location("lgtm_field_trial", BENCH / "field_trial" / "run_field_trial.py")
ft = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ft
_spec.loader.exec_module(ft)


def load_cases(path: Path = HERE / "cases.json") -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cases", nargs="+", default=None)
    parser.add_argument("--cache", type=Path, default=HERE / ".cache")
    parser.add_argument("--output", type=Path, default=BENCH / "results" / "live_hunt")
    parser.add_argument("--gpu-model", choices=sorted(ft.GPU_MODELS), default=None)
    parser.add_argument("--bedrock-model", default=None)
    parser.add_argument("--bedrock-budget", type=float, default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    ft.setup_logging(args.verbose)

    cases = load_cases()
    if args.cases:
        cases = [c for c in cases if c["id"] in set(args.cases)]
    config = ft.LGTMConfig()
    if args.gpu_model:
        ft.apply_gpu_model(config, args.gpu_model)
    if args.bedrock_model:
        config.llm_backend = "bedrock"
        config.bedrock_model = args.bedrock_model
        config.ollama_model = f"bedrock:{args.bedrock_model}"
        config.bedrock_run_label = f"live_hunt:{args.output.name}"
        if args.bedrock_budget is not None:
            config.bedrock_budget_usd = args.bedrock_budget
    cache = args.cache.resolve()
    out_dir = args.output / "lgtm"
    out_dir.mkdir(parents=True, exist_ok=True)
    flagged = []
    for i, case in enumerate(cases, 1):
        path = out_dir / f"{case['id']}.json"
        if args.resume and path.is_file() and not json.loads(path.read_text(encoding="utf-8")).get("crashed"):
            record = json.loads(path.read_text(encoding="utf-8"))
        else:
            print(f"[{i}/{len(cases)}] {case['id']}", flush=True)
            try:
                record = ft.run_case(case, "lgtm", cache, config)
            except Exception as exc:  # noqa: BLE001 - a fetch failure is still a row
                record = {"id": case["id"], "repo": case["repo"], "crashed": True,
                          "error": f"{type(exc).__name__}: {exc}", "findings": []}
            record = ft.scrub(record, [str(cache)])
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            print(f"  -> {len(record.get('vulnerable_findings') or [])} flagged of "
                  f"{record.get('n_findings', 0)} findings, {record.get('latency_seconds')} s"
                  f"{' ERROR ' + str(record.get('error')) if record.get('crashed') else ''}", flush=True)
        if "BedrockBudgetExceeded" in str(record.get("error") or ""):
            print(f"stopped: {record['error']}", flush=True)
            break
        if record.get("vulnerable_findings"):
            flagged.append(case["id"])
    print(f"flagged {len(flagged)} of {len(cases)} PRs: {', '.join(flagged) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
