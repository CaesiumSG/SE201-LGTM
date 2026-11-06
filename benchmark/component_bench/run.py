"""Run component benchmarks: python benchmark/component_bench/run.py [--components ...] [--resume]."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.component_bench import metrics as cost  # noqa: E402
from benchmark.component_bench import schema  # noqa: E402
from benchmark.component_bench.outcomes import InfraError, ModelSettingMismatch, NotScored  # noqa: E402,F401
from benchmark.component_bench.registry import REGISTRY  # noqa: E402

HERE = Path(__file__).resolve().parent
CLONE_CACHE = ROOT / "benchmark" / "real_world" / ".cache"
FETCH_COMMAND = "python -m benchmark.component_bench.fetch_real_prs"


def _module(entry):
    if isinstance(entry.module, str):
        return importlib.import_module(f"benchmark.component_bench.{entry.module}")
    return entry.module


def _items(name, entry, labels_dir):
    """Returns (items, label counts)."""
    if entry.source == "cases":
        return [{"case_id": c["id"], "label_id": None, "case": c} for c in schema.load_cases()], "n/a"
    doc = json.loads((Path(labels_dir) / f"{name}.json").read_text(encoding="utf-8"))
    schema.validate_labels(doc, set(entry.applicable) if entry.applicable else None)
    counts = {"draft": 0, "approved": 0}
    for item in doc["items"]:
        counts[item["review_state"]] += 1
    return doc["items"], counts


def _preflight(case) -> str | None:
    """Reason a development case cannot run at its pinned revisions, or None."""
    if not case or case.get("split") != "real_prs":
        return None
    project = case["repo_url"].rstrip("/").rsplit("/", 1)[-1]
    repo = CLONE_CACHE / project
    if not (repo / ".git").is_dir():
        return f"clone {repo} is missing; run `{FETCH_COMMAND}`"
    problems = []
    for role in ("base", "pr"):
        name = f"rw/{case['id']}/{role}"
        found = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "-q", f"refs/heads/{name}"],
            capture_output=True, text=True,
        )
        if found.returncode != 0:
            problems.append(f"branch {name} is missing")
        elif found.stdout.strip() != case[f"{role}_ref"]:
            problems.append(f"branch {name} is not at {case[f'{role}_ref']}")
    if problems:
        return f"{'; '.join(problems)} in {repo}; run `{FETCH_COMMAND}`"
    return None


def _run_unit(mod, item, config, llm, judge, clock, results_dir, labels_dir=None, case=None):
    m = cost.Metrics()
    ctx = SimpleNamespace(
        config=config,
        results_dir=results_dir,
        labels_dir=labels_dir,
        metrics=m,
        llm=cost.RecordingLLM(llm, m) if llm is not None else None,
        judge=cost.recording_judge(judge, m) if judge is not None else None,
    )
    unit = {"case_id": item["case_id"], "label_id": item.get("label_id")}
    start = clock()
    reason = _preflight(case)
    if reason:
        unit.update(status="error", reason=reason, scores=None, wall_time_s=clock() - start)
        unit.update(input_tokens=0, output_tokens=0, tools={})
        return unit
    try:
        output = mod.run_item(item, ctx)
        unit["wall_time_s"] = clock() - start
        if isinstance(output, NotScored):
            unit.update(status="not_scored", reason=output.reason, scores=None)
        else:
            unit.update(status="scored", scores=mod.score(item, output))
            if isinstance(output, dict) and "label_ids" in output:
                unit["label_ids"] = output["label_ids"]
            if isinstance(output, dict) and "detail" in output:
                unit["detail"] = output["detail"]
    except InfraError as exc:
        unit.update(status="error", reason=str(exc), scores=None, wall_time_s=clock() - start)
    unit.update(
        input_tokens=cost.total(m.input), output_tokens=cost.total(m.output), tools=m.tools
    )
    return unit


def _summarize(units, labels, entry, results_dir, labels_dir=None):
    scored = [u for u in units if u["status"] == "scored"]
    metrics: dict[str, list[float]] = {}
    for u in scored:
        for key, value in (u["scores"] or {}).items():
            if value is not None:
                metrics.setdefault(key, []).append(value)
    tools: dict = {}
    for u in units:
        for agent, stats in (u.get("tools") or {}).items():
            for tool, n in stats.items():
                t = tools.setdefault(agent, {}).setdefault(tool, {"calls": 0, "invalid": 0})
                t["calls"] += n["calls"]
                t["invalid"] += n["invalid"]
    section = {
        "scores": {k: sum(v) / len(v) for k, v in metrics.items()},
        "units_scored": len(scored),
        "units_errored": sum(u["status"] == "error" for u in units),
        "units_not_scored": sum(u["status"] == "not_scored" for u in units),
        "labels": labels,
        "wall_time_s": sum(u["wall_time_s"] for u in units),
        "tools": tools,
    }
    for key in ("input_tokens", "output_tokens"):
        total = cost.total(u[key] for u in units)
        section[key] = cost.NOT_RECORDED if total is None else total
    if entry.aggregate:
        extra = {"labels_dir": labels_dir} if "labels_dir" in inspect.signature(entry.aggregate).parameters else {}
        section["aggregate"] = entry.aggregate(units, results_dir, **extra)
    return section


def _check_model_setting(results_dir: Path, setting) -> None:
    for path in results_dir.glob("*.json"):
        if path.name == "summary.json":
            continue
        previous = json.loads(path.read_text(encoding="utf-8")).get("model_setting")
        if previous != setting:
            raise ModelSettingMismatch(
                f"{path} was written under model setting {previous!r}, not {setting!r}"
            )


def run_benchmark(
    results_dir,
    labels_dir=HERE / "labels",
    registry=None,
    components=None,
    resume=False,
    llm=None,
    judge=None,
    clock=None,
    config=None,
    model_setting=None,
) -> dict:
    registry = REGISTRY if registry is None else registry
    clock = clock or time.perf_counter
    names = list(registry) if not components else list(components)
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise ValueError(f"unknown components: {', '.join(unknown)}")
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    _check_model_setting(results_dir, model_setting)
    summary = {"components": {}}
    cases = {c["id"]: c for c in schema.load_cases()}
    for name in names:
        entry = registry[name]
        mod = _module(entry)
        items, labels = _items(name, entry, labels_dir)
        path = results_dir / f"{name}.json"
        recorded = {}
        if resume and path.exists():
            for u in json.loads(path.read_text(encoding="utf-8"))["units"]:
                if u["status"] != "error":
                    recorded[(u["case_id"], u["label_id"])] = u
        for i in items:
            key = (i["case_id"], i.get("label_id"))
            if key not in recorded:
                recorded[key] = _run_unit(
                    mod, i, config, llm, judge, clock, results_dir, labels_dir, cases.get(i["case_id"])
                )
            doc = {"model_setting": model_setting, "labels": labels, "units": list(recorded.values())}
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        units = [recorded[(i["case_id"], i.get("label_id"))] for i in items]
        summary["components"][name] = _summarize(units, labels, entry, results_dir, labels_dir)
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv=None) -> int:
    from lgtm.agents.base import build_llm
    from lgtm.config import GPU_MODELS, LGTMConfig, apply_gpu_model
    from lgtm.validation.judge import http_judge

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--components", nargs="+", choices=sorted(REGISTRY), help="default: all")
    p.add_argument("--resume", action="store_true", help="skip completed units, rerun errored")
    p.add_argument("--results-dir", default=str(HERE / "results"))
    p.add_argument("--labels-dir", default=str(HERE / "labels"))
    p.add_argument("--gpu-model", choices=sorted(GPU_MODELS), default="qwen3.8-27b")
    args = p.parse_args(argv)

    config = LGTMConfig()
    apply_gpu_model(config, args.gpu_model)
    setting = f"{config.ollama_model}@{config.ollama_base_url}+{config.judge_model}@{config.judge_endpoint}"
    try:
        summary = run_benchmark(
            args.results_dir, args.labels_dir, components=args.components, resume=args.resume,
            llm=build_llm(config), judge=http_judge(config), config=config, model_setting=setting,
        )
    except ModelSettingMismatch as exc:
        print(exc, file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
