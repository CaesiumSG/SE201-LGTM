#!/usr/bin/env python3
"""Run one real-PR case through the LGTM pipeline and stream progress as JSON lines.

Started by ``demo/server.py`` as a subprocess, one per live review. Every line
on stdout that starts with ``@@EVT `` is a JSON event the server relays to the
browser; everything else (library logging) goes to stderr. The finished
record (same shape as ``benchmark/results/real_prs/<mode>/<id>.json``) is
written to ``--out``.

The pipeline itself is not changed: progress comes from wrapping a few of its
functions (fetch, index, Semgrep, triage, validation, judge), from the
``lgtm`` log messages that name each agent, and from ``AgentToolbox._serve``,
which sees every tool call an agent makes.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

_spec = importlib.util.spec_from_file_location("lgtm_real_prs", REPO_ROOT / "benchmark" / "real_prs" / "run_real_prs.py")
rpr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rpr
_spec.loader.exec_module(rpr)
ft = rpr.ft

import lgtm.pipeline as pipeline_mod  # noqa: E402
from lgtm.agents.sast_triage import SASTTriageAgent  # noqa: E402
from lgtm.agents.tools import AgentToolbox  # noqa: E402

STAGES = ["fetch", "index", "context", "sast", "triage", "investigator", "review", "validate", "judge", "report"]
TOOL_KINDS = {
    "read_file": "code", "grep_repo": "code",
    "search_policy": "rag",
    "investigate_base_code": "graph", "investigate_pr_code": "graph",
}
STARTED = time.monotonic()
_out = sys.stdout
sys.stdout = sys.stderr  # stray prints from libraries must not corrupt the event stream


JUDGE_LABEL = "Kev judge"


def emit(event_type: str, /, **fields) -> None:
    """Write one event; progress reporting must never break the review, so it cannot raise."""
    try:
        fields = {**fields, "type": event_type, "t": round(time.monotonic() - STARTED, 1)}
        _out.write("@@EVT " + json.dumps(fields, default=str) + "\n")
        _out.flush()
    except Exception:  # noqa: BLE001
        pass


class Progress:
    """Stage bookkeeping: starting a stage closes the open one and skips any it jumped over."""

    def __init__(self) -> None:
        self.current: str | None = None
        self.agent = {"agent": "", "section": ""}
        self.counts: dict[str, int] = {}

    def stage(self, name: str, detail: str = "") -> None:
        if name == self.current:
            return
        idx = STAGES.index(name)
        prev = STAGES.index(self.current) if self.current else -1
        if self.current:
            emit("stage", stage=self.current, status="done", detail=self._done_detail(self.current))
        for skipped in STAGES[prev + 1:idx]:
            emit("stage", stage=skipped, status="skipped", detail=SKIP_REASONS.get(skipped, ""))
        self.current = name
        emit("stage", stage=name, status="start", detail=detail)

    def finish(self) -> None:
        if self.current:
            emit("stage", stage=self.current, status="done", detail=self._done_detail(self.current))
        self.current = None

    def bump(self, key: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1

    def _done_detail(self, stage: str) -> str:
        return {
            "triage": f"{self.counts.get('triage', 0)} Semgrep finding(s) triaged",
            "review": f"{self.counts.get('sections', 0)} section(s) reviewed",
        }.get(stage, "")


SKIP_REASONS = {
    "index": "not needed in this mode",
    "sast": "not run in this mode",
    "triage": "no Semgrep findings in the diff",
    "investigator": "no Python hunks",
    "review": "no sections planned",
    "judge": "not run in this mode",
}
P = Progress()


def wrap(owner, name: str, before=None, after=None):
    original = getattr(owner, name)

    def wrapper(*args, **kwargs):
        if before:
            _safely(before, *args, **kwargs)
        result = original(*args, **kwargs)
        if after:
            _safely(after, result, *args, **kwargs)
        return result

    setattr(owner, name, wrapper)


def _safely(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception:  # noqa: BLE001 - a progress hook must not change the review
        traceback.print_exc()


def _trim(args: dict) -> dict:
    return {k: (v[:160] if isinstance(v, str) else v) for k, v in (args or {}).items()}


def install_hooks() -> None:
    wrap(ft, "ensure_case", before=lambda case, cache: P.stage("fetch", f"{case['repo']} @ {case['merge_commit'][:10]}"))
    wrap(ft, "ensure_index",
         before=lambda *a, **k: P.stage("index", "indexing repository docs for policy retrieval"),
         after=lambda r, *a, **k: emit("info", stage="index", detail=(
             "index reused" if r.get("index_reused") else f"{r.get('index_chunks', 0)} chunks indexed")))
    wrap(pipeline_mod.ReviewPipeline, "run", before=lambda *a, **k: P.stage("context", "reading the diff, building code graphs"))
    wrap(pipeline_mod.ReviewPipeline, "_run_sast",
         before=lambda *a, **k: P.stage("sast", "Semgrep on the changed files"),
         after=lambda r, *a, **k: emit("info", stage="sast", detail=f"{len(r[0])} finding(s) in the diff, {r[1]} total"))

    def triage_before(self, sf, *a, **k):
        P.stage("triage")
        P.bump("triage")
        P.agent = {"agent": "sast_triage", "section": f"{sf.rule_id.split('.')[-1]} @ {sf.path}:{sf.start_line}"}
        emit("agent", **P.agent, status="start")

    wrap(SASTTriageAgent, "triage", before=triage_before)

    original_serve = AgentToolbox._serve

    def serve(self, name, args, impl, charges=True):
        result = original_serve(self, name, args, impl, charges)
        _safely(lambda: emit("tool", **P.agent, tool=name, kind=TOOL_KINDS.get(name, "other"),
                             args=_trim(args), chars=len(result) if isinstance(result, str) else 0))
        return result

    AgentToolbox._serve = serve

    original_validate = pipeline_mod.EvidenceValidator.validate_all

    def validate_all(self, findings):
        _safely(P.stage, "validate", f"checking {len(findings)} candidate(s) against the cited code")
        return original_validate(self, findings)

    pipeline_mod.EvidenceValidator.validate_all = validate_all

    original_judge = pipeline_mod.judge_candidates

    def judge_candidates(findings, *a, **k):
        _safely(P.stage, "judge", f"{JUDGE_LABEL} on {len(findings)} candidate(s)")
        out = original_judge(findings, *a, **k)
        for f in out:
            _safely(emit, "verdict", finding_id=f.finding_id, file=f.file, line=f.line, cwe=f.cwe_id,
                 category=f.category, supported=f.supported, kev_verdict=f.kev_verdict,
                 kev_severity=f.kev_severity, judged=f.judged)
        return out

    pipeline_mod.judge_candidates = judge_candidates


class StageLogHandler(logging.Handler):
    """Agents announce themselves in the log; turn those lines into agent events."""

    def emit(self, record: logging.LogRecord) -> None:  # noqa: A003 - logging API
        try:
            self._handle(record)
        except Exception:  # noqa: BLE001 - never let progress reporting fail a log call
            pass

    def _handle(self, record: logging.LogRecord) -> None:
        msg = record.getMessage()
        if record.name.startswith("lgtm"):
            if msg.startswith("Investigator:"):
                P.stage("investigator", msg.split(":", 1)[1].strip())
                P.agent = {"agent": "investigator", "section": "investigator"}
                emit("agent", **P.agent, status="start")
            elif msg.startswith(("Authz section review:", "Sqli section review:")):
                P.stage("review")
                kind, section = msg.split(" section review:", 1)
                agent = "sqli_reviewer" if kind == "Sqli" else "authz_reviewer"
                if agent == "authz_reviewer":
                    P.bump("sections")
                P.agent = {"agent": agent, "section": section.strip()}
                emit("agent", **P.agent, status="start")
            if record.levelno >= logging.INFO:
                emit("log", level=record.levelname.lower(), msg=_scrub(msg)[:300])


SCRUB: list[str] = []


def _scrub(text: str) -> str:
    for needle in SCRUB:
        text = text.replace(needle, "<cache>")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--row-id", help="a benchmark row, e.g. taiga-epic-order-sqli-vulnerable")
    which.add_argument("--case-json", type=Path,
                       help="any PR: {id, repo, pr, title, base_commit, merge_commit}; no answer key, so not scored")
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", default="lgtm", choices=["lgtm", "llm-only", "sast-only"])
    parser.add_argument("--backend", default="gpu", choices=["gpu", "bedrock"])
    parser.add_argument("--bedrock-model", default="global.anthropic.claude-sonnet-4-6")
    parser.add_argument("--bedrock-budget", type=float, default=None)
    parser.add_argument("--judge-endpoint", default=None, help="evidence judge URL (default: config, Kev on 127.0.0.1:8008)")
    parser.add_argument("--judge-name", default="Kev judge")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    for noisy in ("httpx", "chromadb", "urllib3", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger().addHandler(StageLogHandler())
    cache = args.cache.resolve()
    SCRUB.extend([str(cache), str(Path.home())])

    if args.case_json:
        row = json.loads(args.case_json.read_text(encoding="utf-8"))
    else:
        rows = {}
        for cases_file in (rpr.CASES_FILE, rpr.HERE / "heldout.json"):
            for case in rpr.load_cases(cases_file):
                for row in rpr.expand(case):
                    rows[row["id"]] = row
        row = rows.get(args.row_id)
        if row is None:
            emit("error", msg=f"unknown case {args.row_id}")
            return 2

    config = ft.LGTMConfig()
    ft.apply_gpu_model(config, "qwen3.8-27b")
    if args.backend == "bedrock":
        config.llm_backend = "bedrock"
        config.bedrock_model = args.bedrock_model
        config.ollama_model = f"bedrock:{args.bedrock_model}"
        config.bedrock_run_label = f"demo:{row['id']}"
        if args.bedrock_budget is not None:
            config.bedrock_budget_usd = args.bedrock_budget
    global JUDGE_LABEL
    JUDGE_LABEL = args.judge_name
    if args.judge_endpoint:
        config.judge_endpoint = args.judge_endpoint
    emit("meta", row=row, mode=args.mode, model=config.ollama_model, backend=args.backend)
    install_hooks()

    try:
        record = ft.run_case(row, args.mode, cache, config)
    except Exception as exc:  # noqa: BLE001 - reported to the browser, not raised
        traceback.print_exc()
        record = {"id": row["id"], "repo": row["repo"], "mode": args.mode, "crashed": True,
                  "error": f"{type(exc).__name__}: {exc}", "findings": []}
    P.stage("report", "scoring against the advisory and writing the result")
    if not args.case_json:
        record.update(rpr.score(row, record))
    record["title"] = record.get("title") or row["title"]
    record["backend"] = args.backend
    record["judge"] = args.judge_name
    record = ft.scrub(record, SCRUB)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    P.finish()
    emit("done", outcome=record.get("outcome"), predicted=record.get("predicted"),
         n_findings=record.get("n_findings", 0), latency_seconds=record.get("latency_seconds"),
         error=_scrub(record.get("error") or ""))
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    sys.exit(main())
