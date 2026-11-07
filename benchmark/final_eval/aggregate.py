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
    "gptoss20b-bedrock": ("gpt-oss 20B (Bedrock), T=0", "heldout-gptoss20b-bedrock"),
    "gptoss120b-bedrock": ("gpt-oss 120B (Bedrock), T=0", "heldout-gptoss120b-bedrock"),
    "haiku45": ("Claude Haiku 4.5 (Bedrock)", "heldout-haiku45"),
    "sonnet46": ("Claude Sonnet 4.6 (Bedrock)", "heldout-sonnet46"),
    # Runs 2 and 3 of the cloud models: each split into two halves of the advisories run in parallel
    # (run ids ...-r2a / -r2b); the cost label is charged to the "a" half.
    "gptoss120b-bedrock-r2": ("gpt-oss 120B (Bedrock), T=0, run 2", "heldout-gptoss120b-bedrock-r2a"),
    "gptoss120b-bedrock-r3": ("gpt-oss 120B (Bedrock), T=0, run 3", "heldout-gptoss120b-bedrock-r3a"),
    "haiku45-r2": ("Claude Haiku 4.5 (Bedrock), run 2", "heldout-haiku45-r2a"),
    "haiku45-r3": ("Claude Haiku 4.5 (Bedrock), run 3", "heldout-haiku45-r3a"),
    "sonnet46-r2": ("Claude Sonnet 4.6 (Bedrock), run 2", "heldout-sonnet46-r2a"),
    "sonnet46-r3": ("Claude Sonnet 4.6 (Bedrock), run 3", "heldout-sonnet46-r3a"),
}
SHORT = {"qwen27b-t0-r1": "Q r1", "qwen27b-t0-r2": "Q r2", "qwen27b-t0-r3": "Q r3", "qwen27b-t0.5": "Q T.5",
         "qwen27b-t1.0": "Q T1", "gptoss20b-bedrock": "G20", "gptoss120b-bedrock": "G120", "haiku45": "H", "sonnet46": "S",
         "gptoss120b-bedrock-r2": "G120 r2", "gptoss120b-bedrock-r3": "G120 r3", "haiku45-r2": "H r2", "haiku45-r3": "H r3",
         "sonnet46-r2": "S r2", "sonnet46-r3": "S r3"}
# Three runs per model for the repeatability table: (model label, folders of runs 1-3)
REPEATS = {
    "Qwen3.8 27B (T=0)": ("qwen27b-t0-r1", "qwen27b-t0-r2", "qwen27b-t0-r3"),
    "gpt-oss 120B (T=0)": ("gptoss120b-bedrock", "gptoss120b-bedrock-r2", "gptoss120b-bedrock-r3"),
    "Claude Haiku 4.5 (provider default temperature)": ("haiku45", "haiku45-r2", "haiku45-r3"),
    "Claude Sonnet 4.6 (provider default temperature)": ("sonnet46", "sonnet46-r2", "sonnet46-r3"),
}
SHORT_MODE = {"lgtm": "lgtm", "lgtm-no-sast": "no-SAST", "llm-only": "llm", "sast-only": ""}


def load_cases(name: str) -> dict[str, dict]:
    data = json.loads((REPO / "benchmark" / "real_prs" / name).read_text())
    return {c["id"]: c for c in data["cases"]}


LEDGER = Path.home() / ".lgtm" / "bedrock-spend.jsonl"


def ledger_by_label(path: Path = LEDGER) -> dict[str, float]:
    """Bedrock USD per ledger `run` label (real_prs:<output folder name>)."""
    out: dict[str, float] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        try:
            r = json.loads(line)
            out[r.get("run") or ""] = out.get(r.get("run") or "", 0.0) + float(r.get("usd") or 0)
        except (ValueError, AttributeError):
            continue
    return out


def bedrock_label(command: str) -> str | None:
    """The ledger label a run writes: only Bedrock runs have one (see run_real_prs.py)."""
    if "--bedrock-model" not in command or "--output" not in command:
        return None
    args = command.split()
    return "real_prs:" + Path(args[args.index("--output") + 1]).name


def load_manifest(root: Path) -> dict[str, dict]:
    """Last ok entry per run id (a restarted run keeps its final entry), plus Bedrock cost and attempts.

    Cost comes from the spend ledger's per-run label, not from the manifest's before/after
    ledger totals: streams ran in parallel, so those deltas include other streams' spend.
    A label is charged to the first run id that used it (a later case rerun into the same
    output folder writes the same label and is already included there).
    """
    path = HERE / "manifest.jsonl"
    out: dict[str, dict] = {}
    if not path.is_file():
        return out
    ledger = ledger_by_label()
    charged: set[str] = set()
    for line in path.read_text().splitlines():
        r = json.loads(line)
        if r["run_id"].startswith("_"):
            continue
        e = out.setdefault(r["run_id"], {"attempts": 0, "bedrock_usd": 0.0, "entries": []})
        e["attempts"] += 1
        e["entries"].append(r)
        label = bedrock_label(r.get("command", ""))
        if label and label not in charged:
            charged.add(label)
            e["bedrock_usd"] = round(ledger.get(label, 0.0), 4)
            e["bedrock_label"] = label
        elif label:
            e["bedrock_label"] = label
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
    head = "| Variant | Caught | Exact | SQLi exact | Authz exact | False alarms on fixes | Median s/diff | Errors |"
    out = [head + (" Bedrock USD |" if manifest_cost else ""), "|---" * (head.count("|") - 1 + bool(manifest_cost)) + "|"]
    for label, s in rows:
        a = s["all"]
        n = s["advisories_scored"]
        cost = (f" {manifest_cost[label]:.2f} |" if label in manifest_cost else " |") if manifest_cost else ""
        out.append(f"| {label} | {a['caught']}/{n} | {a['exact']}/{n} | {s['sqli']['exact']}/{s['sqli']['n']} | "
                   f"{s['authz']['exact']}/{s['authz']['n']} | {a['false_alarms']}/{n} | {s['median_seconds_per_diff']} | "
                   f"{s['diff_errors']} |{cost}")
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
        for mode in ("lgtm", "lgtm-no-sast", "llm-only", "sast-only"):
            s = score_real_prs(root / "heldout" / folder / mode, heldout_cases)
            if s:
                held[f"{folder}/{mode}"] = s
                s["label"] = f"{label} — {mode}"
                s["short"] = "Semgrep" if mode == "sast-only" else f"{SHORT[folder]} {SHORT_MODE[mode]}".strip()
                s["bedrock_usd_run_total"] = round(manifest.get(run_id, {}).get("bedrock_usd", 0.0), 4)
    results["heldout"] = held

    if held:
        md += ["## Held-out real PRs (17 published advisories)", ""]
        # Model comparison: lgtm and plain LLM per model
        model_rows = [(f"{HELDOUT_VARIANTS[f][0]} — {m}", held[f"{f}/{m}"])
                      for f in ("qwen27b-t0-r1", "gptoss20b-bedrock", "gptoss120b-bedrock", "haiku45", "sonnet46")
                      for m in ("lgtm", "llm-only") if f"{f}/{m}" in held]
        if "qwen27b-t0-r1/sast-only" in held:
            model_rows.append(("Semgrep only (no model)", held["qwen27b-t0-r1/sast-only"]))
        cost = {lbl: held_s["bedrock_usd_run_total"] for lbl, held_s in model_rows}
        md += ["### Model comparison", "", *heldout_table(model_rows, cost), "",
               "Bedrock USD is the cost of the whole run (lgtm and plain LLM together) from its label in the spend ledger; the Qwen and Semgrep rows ran on the GPU cluster and cost nothing on Bedrock.", ""]

        # Ablation: what each part adds (Qwen T=0 run 1)
        abl = [(name, held[k]) for name, k in (
            ("Full pipeline (lgtm)", "qwen27b-t0-r1/lgtm"),
            ("Pipeline without Semgrep (lgtm-no-sast)", "qwen27b-t0-r1/lgtm-no-sast"),
            ("Plain LLM, same model (llm-only)", "qwen27b-t0-r1/llm-only"),
            ("Semgrep only (sast-only)", "qwen27b-t0-r1/sast-only")) if k in held]
        if len(abl) > 1:
            md += ["### Ablation (Qwen3.8 27B, T=0, run 1)", "", *heldout_table(abl), ""]

        # Repeatability
        rep_out = {}
        md += ["### Repeatability (three runs per model)", "",
               "Runs 2 and 3 of the Bedrock models ran on 7 Nov with twelve runs in parallel, so their latency is not comparable to run 1; "
               "only outcomes are compared here.", "",
               "| Model | Mode | Runs | Caught (each run) | Exact (each run) | False alarms (each run) | Caught in every run | Caught in some runs only | False alarm in some runs only |",
               "|---|---|---|---|---|---|---|---|---|"]
        for model, folders in REPEATS.items():
            for m in ("lgtm", "llm-only"):
                rs = [held[f"{f}/{m}"] for f in folders if f"{f}/{m}" in held and held[f"{f}/{m}"]["advisories_scored"] == len(heldout_cases)]
                if len(rs) < 2:
                    continue
                advs = sorted(heldout_cases)
                pa = lambda r, a, k: bool((r["per_advisory"].get(a) or {}).get(k))
                always = [a for a in advs if all(pa(r, a, "caught") for r in rs)]
                some = [a for a in advs if a not in always and any(pa(r, a, "caught") for r in rs)]
                fa_some = [a for a in advs if any(pa(r, a, "false_alarm") for r in rs) and not all(pa(r, a, "false_alarm") for r in rs)]
                rep_out[f"{model}/{m}"] = {"caught": [r["all"]["caught"] for r in rs], "exact": [r["all"]["exact"] for r in rs],
                                           "false_alarms": [r["all"]["false_alarms"] for r in rs], "always": always,
                                           "sometimes": some, "false_alarm_sometimes": fa_some}
                o = rep_out[f"{model}/{m}"]
                md.append(f"| {model} | {m} | {len(rs)} | {', '.join(map(str, o['caught']))} | {', '.join(map(str, o['exact']))} | "
                          f"{', '.join(map(str, o['false_alarms']))} | {len(always)} | {', '.join(some) or 'none'} | {', '.join(fa_some) or 'none'} |")
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
        md += ["### Per advisory", "",
               "Columns: Q = Qwen3.8 27B (r1/r2/r3 = T=0 runs, T.5 = T=0.5, T1 = T=1.0); G20/G120 = gpt-oss 20B/120B; "
               "H = Haiku 4.5; S = Sonnet 4.6. lgtm = full pipeline, no-SAST = pipeline without Semgrep, llm = plain LLM. "
               "\"+FP\" = false alarm on the fix commit.", "",
               "| Advisory | Category | " + " | ".join(s["short"] for _, s in cols) + " |",
               "|---|---|" + "---|" * len(cols)]
        for adv in sorted(heldout_cases, key=lambda a: (heldout_cases[a]["category"], a)):
            weak = " (weak)" if adv in WEAK else ""
            md.append(f"| `{adv}`{weak} | {heldout_cases[adv]['category']} | " +
                      " | ".join(cell(s["per_advisory"].get(adv)) for _, s in cols) + " |")
        md.append("")

    # Development real PRs
    dev = {m: score_real_prs(root / "real_prs_dev" / "qwen27b-t0" / m, dev_cases) for m in ("lgtm", "llm-only", "sast-only")}
    dev = {m: s for m, s in dev.items() if s}
    for m, s in dev.items():
        s["label"] = "Semgrep only" if m == "sast-only" else f"Qwen3.8 27B — {m}"
    results["real_prs_dev"] = dev
    if dev:
        md += ["## Development real PRs (13 advisories, used to build the SQLi reviewer)", "",
               *heldout_table([(f"Qwen3.8 27B — {m}" if m != "sast-only" else "Semgrep only", s) for m, s in dev.items()]), ""]

    # Shoply, real-world CVEs, injection, field trial: copy their own summaries, then tabulate
    for name, sub in (("shoply", ("lgtm", "llm-only")), ("real_world", ("lgtm", "llm-only")),
                      ("injection", ("lgtm", "llm-only")), ("field_trial", ("lgtm", "llm-only"))):
        got = {}
        for m in sub:
            for cand in (root / name / m / "summary.json", root / name / f"{m}.json", root / name / m / "results.json"):
                s = summary_json(cand)
                if s is not None:
                    summ = dict(s.get("summary", s))
                    if name == "field_trial":
                        # Per-PR rows would show which PR was flagged, and flagged PRs are unreported findings.
                        # The field-trial run folder stays local (git-ignored); only the totals are published.
                        summ.pop("per_case", None)
                    got[m] = {"file": str(cand.relative_to(REPO)), "summary": summ}
                    break
        if got:
            results[name] = got

    def f2(x) -> str:
        return "–" if x is None else f"{x:.2f}"

    def confusion_rows(got: dict) -> list[str]:
        out = ["| Mode | TP | FP | FN | TN | Precision | Recall | F1 | SQLi F1 | Authz F1 | Errors | Median s/case |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for m, g in got.items():
            s = g["summary"]
            o, cat = s.get("overall", {}), s.get("per_category") or {}
            out.append(f"| {m} | {o.get('tp')} | {o.get('fp')} | {o.get('fn')} | {o.get('tn')} | {f2(o.get('precision'))} | "
                       f"{f2(o.get('recall'))} | {f2(o.get('f1'))} | {f2((cat.get('sqli') or {}).get('f1'))} | "
                       f"{f2((cat.get('authz') or {}).get('f1'))} | {s.get('errors', o.get('errors', 0))} | {s.get('median_latency_seconds')} |")
        return out

    if "shoply" in results:
        md += ["## Shoply (52 synthetic cases written by the team, Qwen3.8 27B)", "", *confusion_rows(results["shoply"]), ""]
    if "real_world" in results:
        md += ["## Real-world CVE cases (12 cases: 6 SQLi, 6 authz, Qwen3.8 27B)", "",
               "Each case is a published CVE fix: the safe case is the fix commit, the vulnerable case is a synthetic revert of it "
               "(see `benchmark/real_world/fetch.py`).", "", *confusion_rows(results["real_world"]), "",
               "Cases marked out of scope in `cases.json` are not scored: " +
               ", ".join(f"`{c}`" for c in (next(iter(results["real_world"].values()))["summary"].get("out_of_scope_cases") or [])) +
               ". Counting every case, both modes catch all 6 vulnerable cases; lgtm raises 2 false alarms on the 6 safe cases, "
               "llm-only none.", ""]
    if "injection" in results:
        md += ["## Prompt injection (6 attacks)", "",
               "| Mode | Cases | Flagged without injection | Attacks succeeded | Errors |", "|---|---|---|---|---|"]
        for m, g in results["injection"].items():
            s = g["summary"]
            md.append(f"| {m} | {s.get('total_cases')} | {s.get('originally_flagged')} | {s.get('attacks_succeeded')} | {s.get('errors')} |")
        md.append("")
    if "field_trial" in results:
        md += ["## Field trial (12 recently merged PRs, no ground truth)", "",
               "| Mode | PRs | Crashed | PRs flagged | Judge-supported | Coverage complete | Median s/PR |", "|---|---|---|---|---|---|---|"]
        for m, g in results["field_trial"].items():
            s = g["summary"]
            judged = (s.get("judge") or {}).get("supported") if m == "lgtm" else "n/a"
            cov = f"{s.get('prs_coverage_complete')}/{s.get('cases')}" if m == "lgtm" else "n/a"
            md.append(f"| {m} | {s.get('cases')} | {s.get('crashed')} | {s.get('prs_with_vulnerable_verdict')} | {judged} | {cov} | {s.get('latency_median_seconds')} |")
        md += ["", "Flagged PRs are unreported findings and are not named here.", ""]

    # Component benchmark
    cb = summary_json(root / "component_bench" / "summary.json")
    if cb:
        results["component_bench"] = cb
        md += ["## Component benchmark (12 real-world cases, each stage on its own)", "",
               "Labels are drafts written by Claude Opus 5.5 and not yet reviewed by the team, so every figure is provisional.", "",
               "| Component | Units scored | Errored | Main scores |", "|---|---|---|---|"]
        for name, c in cb.get("components", {}).items():
            sc = dict(c.get("scores") or {})
            agg = c.get("aggregate") or {}
            if agg.get("f1") is not None:
                sc = {"precision": agg["precision"], "recall": agg["recall"], "f1": agg["f1"]}
            if name == "investigator":
                sc = {"mean rubric rating": agg.get("mean"), "rated": agg.get("rated")}
            main = ", ".join(f"{k} {v:.2f}" if isinstance(v, float) else f"{k} {v}" for k, v in sc.items() if v is not None) or "–"
            md.append(f"| {name} | {c.get('units_scored')} | {c.get('units_errored')} | {main} |")
        md.append("")

    # Costs and wall time
    md += ["## Runs, cost and wall time", "", "| Run id | Attempts | Status | Start (UTC) | End (UTC) | Bedrock USD |", "|---|---|---|---|---|---|"]
    total = 0.0
    for run_id, e in manifest.items():
        last = e.get("final") or e["entries"][-1]
        total += e["bedrock_usd"]
        usd = f"{e['bedrock_usd']:.2f}" if e.get("bedrock_label") and e["bedrock_usd"] else (
            f"in `{e['bedrock_label']}`" if e.get("bedrock_label") else "0 (GPU cluster)")
        md.append(f"| {run_id} | {e['attempts']} | {last['status']} | {e['entries'][0]['start']} | {last['end']} | {usd} |")
    md += ["", f"Bedrock spend in these runs: USD {total:.2f} (summed per run label from `~/.lgtm/bedrock-spend.jsonl`; "
           "runs on the GPU cluster cost nothing on Bedrock).", ""]
    results["bedrock_usd_total"] = round(total, 4)

    (root / "results.json").write_text(json.dumps(results, indent=2))
    (root / "RESULTS.md").write_text("\n".join(md))
    print(f"wrote {root / 'RESULTS.md'} and results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
