"""Aggregate the final evaluation runs into RESULTS.md and results.json.

Usage: python benchmark/final_eval/aggregate.py [--root benchmark/runs/final-2026-11]

Reads every run folder under the root, the run manifest (for Bedrock cost and
wall time) and the real-PR case files, and writes:

- <root>/results.json: every number below, machine-readable;
- <root>/RESULTS.md: the tables used in the final presentation.

Definitions (as in docs/real-prs-eval.md):
- caught: the vulnerable diff produced at least one vulnerable finding (TP);
- on target: a vulnerable finding is in a file the advisory names;
- exact: on target and the finding's CWE matches the advisory's category
  (CWE-89 for SQL injection, an access-control CWE for authorization);
- false alarm: the fix diff produced a vulnerable finding (FP).
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
AUTHZ_CWES = {"CWE-862", "CWE-863", "CWE-639", "CWE-284", "CWE-285", "CWE-200", "CWE-269", "CWE-732", "CWE-266"}
WEAK = {"piccolo-savepoint-name-sqli", "openedx-support-manage-course-team-authz", "django-orderby-dotted-column-sqli"}

# Variant folder -> (label, manifest run id)
HELDOUT_VARIANTS = {
    "qwen27b-t0-r1": ("Qwen3.8 27B, T=0, run 1", "heldout-qwen27b-t0-r1"),
    "qwen27b-t0-r2": ("Qwen3.8 27B, T=0, run 2", "heldout-qwen27b-t0-r2"),
    "qwen27b-t0-r3": ("Qwen3.8 27B, T=0, run 3", "heldout-qwen27b-t0-r3"),
    "qwen27b-t0.5": ("Qwen3.8 27B, T=0.5", "heldout-qwen27b-t0.5"),
    "qwen27b-t1.0": ("Qwen3.8 27B, T=1.0", "heldout-qwen27b-t1.0"),
    "gptoss20b-t0": ("gpt-oss 20B (local), T=0", "heldout-gptoss20b-t0"),
    "haiku45": ("Claude Haiku 4.5 (Bedrock)", "heldout-haiku45"),
    "sonnet46": ("Claude Sonnet 4.6 (Bedrock)", "heldout-sonnet46"),
}


def load_cases(name: str) -> dict[str, dict]:
    data = json.loads((REPO / "benchmark" / "real_prs" / name).read_text())
    return {c["id"]: c for c in data["cases"]}


def load_manifest(root: Path) -> dict[str, dict]:
    """Last ok entry per run id (a restarted run keeps its final entry), plus summed cost/time over all attempts."""
    path = HERE / "manifest.jsonl"
    out: dict[str, dict] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        r = json.loads(line)
        e = out.setdefault(r["run_id"], {"attempts": 0, "bedrock_usd": 0.0, "entries": []})
        e["attempts"] += 1
        e["bedrock_usd"] += r.get("bedrock_usd_run") or 0.0
        e["entries"].append(r)
        if r.get("status") == "ok":
            e["final"] = r
    return out


def exact(rec: dict, case: dict) -> bool:
    ok = {"CWE-89"} if case["category"] == "sqli" else AUTHZ_CWES
    files = set(case["vulnerable_files"])
    return any(f.get("cwe_id") in ok and f.get("file") in files for f in rec.get("vulnerable_findings") or [])


def score_real_prs(mode_dir: Path, cases: dict[str, dict]) -> dict | None:
    if not mode_dir.is_dir():
        return None
    per, lat, errors, agent_errors, unparsed = {}, [], 0, 0, 0
    for adv, case in cases.items():
        v_path, f_path = mode_dir / f"{adv}-vulnerable.json", mode_dir / f"{adv}-fixed.json"
        if not (v_path.is_file() and f_path.is_file()):
            per[adv] = None
            continue
        v, f = json.loads(v_path.read_text()), json.loads(f_path.read_text())
        for r in (v, f):
            if r.get("outcome") == "ERROR":
                errors += 1
            elif r.get("latency_seconds") is not None:
                lat.append(r["latency_seconds"])
            agent_errors += len(r.get("agent_errors") or [])
        if v.get("outcome") == "ERROR" or f.get("outcome") == "ERROR":
            per[adv] = {"error": True}
            continue
        caught = v["outcome"] == "TP"
        per[adv] = {
            "category": case["category"],
            "caught": caught,
            "on_target": caught and bool(v.get("on_target")),
            "exact": caught and exact(v, case),
            "false_alarm": f["outcome"] == "FP",
            "findings_vulnerable": v.get("n_findings"),
            "findings_fixed": f.get("n_findings"),
        }
    done = {a: x for a, x in per.items() if x and not x.get("error")}

    def tally(keep) -> dict:
        xs = [x for a, x in done.items() if keep(a, x)]
        return {
            "n": len(xs),
            "caught": sum(x["caught"] for x in xs),
            "on_target": sum(x["on_target"] for x in xs),
            "exact": sum(x["exact"] for x in xs),
            "false_alarms": sum(x["false_alarm"] for x in xs),
        }

    return {
        "advisories_expected": len(cases),
        "advisories_scored": len(done),
        "missing": sorted(a for a, x in per.items() if x is None),
        "errored": sorted(a for a, x in per.items() if x and x.get("error")),
        "diff_errors": errors,
        "agent_errors": agent_errors,
        "median_seconds_per_diff": round(statistics.median(lat), 1) if lat else None,
        "all": tally(lambda a, x: True),
        "sqli": tally(lambda a, x: x["category"] == "sqli"),
        "authz": tally(lambda a, x: x["category"] == "authz"),
        "without_weak": tally(lambda a, x: a not in WEAK),
        "per_advisory": per,
    }


def cell(x: dict | None) -> str:
    if x is None:
        return "–"
    if x.get("error"):
        return "error"
    s = "exact" if x["exact"] else "on file" if x["on_target"] else "caught" if x["caught"] else "miss"
    return s + (" +FP" if x["false_alarm"] else "")


def heldout_table(rows: list[tuple[str, dict]], manifest_cost: dict[str, float] | None = None) -> list[str]:
    out = ["| Variant | Caught | Exact | SQLi exact | Authz exact | False alarms on fixes | Median s/diff | Errors | Bedrock USD |",
           "|---|---|---|---|---|---|---|---|---|"]
    for label, s in rows:
        a = s["all"]
        n = s["advisories_scored"]
        cost = "" if not manifest_cost or label not in manifest_cost else f"{manifest_cost[label]:.2f}"
        out.append(f"| {label} | {a['caught']}/{n} | {a['exact']}/{n} | {s['sqli']['exact']}/{s['sqli']['n']} | "
                   f"{s['authz']['exact']}/{s['authz']['n']} | {a['false_alarms']}/{n} | {s['median_seconds_per_diff']} | "
                   f"{s['diff_errors']} | {cost} |")
    return out


def summary_json(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.is_file() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=REPO / "benchmark" / "runs" / "final-2026-11")
    args = ap.parse_args()
    root = args.root
    manifest = load_manifest(root)
    heldout_cases, dev_cases = load_cases("heldout.json"), load_cases("cases.json")
    results: dict = {"root": str(root.relative_to(REPO)), "manifest": {k: {kk: vv for kk, vv in v.items() if kk != "entries"} for k, v in manifest.items()}}
    md = ["# Final evaluation results", "",
          "Generated by `benchmark/final_eval/aggregate.py` from the run folders in this directory and "
          "`benchmark/final_eval/manifest.jsonl`. Every run used the integrated pipeline; the commit of each run "
          "is in the manifest.", ""]

    # Held-out real PRs
    held: dict[str, dict] = {}
    for folder, (label, run_id) in HELDOUT_VARIANTS.items():
        for mode in ("lgtm", "llm-only", "sast-only"):
            s = score_real_prs(root / "heldout" / folder / mode, heldout_cases)
            if s:
                held[f"{folder}/{mode}"] = s
                s["label"] = f"{label} — {mode}"
                s["bedrock_usd_run_total"] = round(manifest.get(run_id, {}).get("bedrock_usd", 0.0), 4)
    results["heldout"] = held

    if held:
        md += ["## Held-out real PRs (17 published advisories)", ""]
        # Model comparison: lgtm and plain LLM per model
        model_rows = [(f"{HELDOUT_VARIANTS[f][0]} — {m}", held[f"{f}/{m}"])
                      for f in ("qwen27b-t0-r1", "gptoss20b-t0", "haiku45", "sonnet46")
                      for m in ("lgtm", "llm-only") if f"{f}/{m}" in held]
        if "qwen27b-t0-r1/sast-only" in held:
            model_rows.append(("Semgrep only (no model)", held["qwen27b-t0-r1/sast-only"]))
        cost = {lbl: held_s["bedrock_usd_run_total"] for lbl, held_s in model_rows}
        md += ["### Model comparison", "", *heldout_table(model_rows, cost), "",
               "Bedrock USD is the cost of the whole run id (lgtm and plain LLM together) from the spend ledger.", ""]

        # Repeatability
        reps = {m: [held[f"qwen27b-t0-r{i}/{m}"] for i in (1, 2, 3) if f"qwen27b-t0-r{i}/{m}" in held] for m in ("lgtm", "llm-only")}
        rep_out = {}
        md += ["### Repeatability (Qwen3.8 27B, temperature 0, three runs)", "",
               "| Mode | Runs | Caught (each run) | Exact (each run) | False alarms (each run) | Advisories caught in every run | Caught in some runs only |",
               "|---|---|---|---|---|---|---|"]
        for m, rs in reps.items():
            if not rs:
                continue
            advs = sorted(heldout_cases)
            always = [a for a in advs if all((r["per_advisory"].get(a) or {}).get("caught") for r in rs)]
            some = [a for a in advs if a not in always and any((r["per_advisory"].get(a) or {}).get("caught") for r in rs)]
            rep_out[m] = {"caught": [r["all"]["caught"] for r in rs], "exact": [r["all"]["exact"] for r in rs],
                          "false_alarms": [r["all"]["false_alarms"] for r in rs], "always": always, "sometimes": some}
            md.append(f"| {m} | {len(rs)} | {', '.join(str(x) for x in rep_out[m]['caught'])} | "
                      f"{', '.join(str(x) for x in rep_out[m]['exact'])} | {', '.join(str(x) for x in rep_out[m]['false_alarms'])} | "
                      f"{len(always)} | {', '.join(some) or 'none'} |")
        results["repeatability"] = rep_out
        md.append("")

        # Temperature
        t_rows = []
        for i in (1, 2, 3):
            if f"qwen27b-t0-r{i}/lgtm" in held:
                t_rows.append((f"T=0, run {i}", held[f"qwen27b-t0-r{i}/lgtm"]))
        for t in ("0.5", "1.0"):
            if f"qwen27b-t{t}/lgtm" in held:
                t_rows.append((f"T={t}", held[f"qwen27b-t{t}/lgtm"]))
        if t_rows:
            md += ["### Temperature (Qwen3.8 27B, lgtm)", "", *heldout_table(t_rows), ""]

        # Per advisory
        cols = [(k, held[k]) for k in held]
        md += ["### Per advisory", "", "| Advisory | Category | " + " | ".join(s["label"] for _, s in cols) + " |",
               "|---|---|" + "---|" * len(cols)]
        for adv in sorted(heldout_cases, key=lambda a: (heldout_cases[a]["category"], a)):
            weak = " (weak)" if adv in WEAK else ""
            md.append(f"| `{adv}`{weak} | {heldout_cases[adv]['category']} | " +
                      " | ".join(cell(s["per_advisory"].get(adv)) for _, s in cols) + " |")
        md.append("")

    # Development real PRs
    dev = {m: score_real_prs(root / "real_prs_dev" / "qwen27b-t0" / m, dev_cases) for m in ("lgtm", "llm-only", "sast-only")}
    dev = {m: s for m, s in dev.items() if s}
    results["real_prs_dev"] = dev
    if dev:
        md += ["## Development real PRs (13 advisories, used to build the SQLi reviewer)", "",
               *heldout_table([(f"Qwen3.8 27B — {m}" if m != "sast-only" else "Semgrep only", s) for m, s in dev.items()]), ""]

    # Shoply, injection, field trial: copy their own summaries
    for name, sub in (("shoply", ("lgtm", "llm-only")), ("injection", ("lgtm", "llm-only")), ("field_trial", ("lgtm", "llm-only"))):
        got = {}
        for m in sub:
            for cand in (root / name / m / "summary.json", root / name / f"{m}.json", root / name / m / "results.json"):
                s = summary_json(cand)
                if s is not None:
                    got[m] = {"file": str(cand.relative_to(REPO)), "summary": s.get("summary", s)}
                    break
        if got:
            results[name] = got
    md += ["## Shoply, prompt injection, field trial", "",
           "Their own summary files are copied into `results.json` under `shoply`, `injection` and `field_trial`; "
           "the tables for them are written by hand in `docs/final-eval.md` from those files.", ""]

    # Costs and wall time
    md += ["## Runs, cost and wall time", "", "| Run id | Attempts | Status | Start (UTC) | End (UTC) | Bedrock USD |", "|---|---|---|---|---|---|"]
    total = 0.0
    for run_id, e in manifest.items():
        last = e.get("final") or e["entries"][-1]
        total += e["bedrock_usd"]
        md.append(f"| {run_id} | {e['attempts']} | {last['status']} | {e['entries'][0]['start']} | {last['end']} | {e['bedrock_usd']:.2f} |")
    md += ["", f"Bedrock spend in these runs: USD {total:.2f}.", ""]
    results["bedrock_usd_total"] = round(total, 4)

    (root / "results.json").write_text(json.dumps(results, indent=2))
    (root / "RESULTS.md").write_text("\n".join(md))
    print(f"wrote {root / 'RESULTS.md'} and results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
