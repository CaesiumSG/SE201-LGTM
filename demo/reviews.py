"""The review engine behind the LGTM GitHub App.

A pull-request event (webhook, polling fallback or a re-run) becomes a queued
run. One worker thread takes runs in order and, for each:

1. creates an in-progress check run on the PR's head commit,
2. fetches base and head into a local clone cache (installation token, never on a command line),
3. runs the real pipeline in lgtm mode in a subprocess (``live_runner.py``),
   recording every progress event for the dashboard,
4. completes the check run with a summary and line annotations,
5. posts a pull-request review with inline comments on the flagged lines,
6. stores the run, its findings and its log.

Everything posted to github.com goes through ``github_app.safe_markdown``.
"""

from __future__ import annotations

import datetime
import json
import os
import queue
import re
import statistics
import subprocess
import threading
import time
import traceback
import urllib.request
import uuid
from pathlib import Path

import github_app as gh
import brief
import results
import suggest
from store import DATA_DIR, SEVERITY_RANK, Store, now

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
CLONES = DATA_DIR / "clones"
RUN_FILES = DATA_DIR / "runs"
CHECK_NAME = "LGTM security review"

CWE_NAMES = {
    "CWE-89": "SQL injection", "CWE-639": "Insecure direct object reference",
    "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization",
    "CWE-285": "Improper authorization", "CWE-284": "Improper access control",
    "CWE-22": "Path traversal", "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting",
}
SEVERITY_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡"}
STAGE_LABELS = {
    "fetch": "Fetch the pull request", "index": "Index repository docs", "context": "Read the diff and build code graphs",
    "sast": "Semgrep on changed files", "triage": "Triage Semgrep hits", "investigator": "Investigator agent",
    "review": "Section reviewers (authorization, SQL injection)", "validate": "Check cited evidence",
    "judge": "Evidence judge", "report": "Write the report",
}


# Evidence judges: (endpoint, short name, long name). Kev is the evaluated judge; Claude is a labelled stand-in.
JUDGES = {
    "kev": ("http://127.0.0.1:8008", "Kev judge", "Kev-4B"),
    "claude": ("http://127.0.0.1:8009", "Claude judge", "Claude (stand-in)"),
}


def cwe_name(cwe: str | None) -> str:
    return CWE_NAMES.get(cwe or "", cwe or "Security issue")


def finding_title(f: dict) -> str:
    return f"{cwe_name(f.get('cwe'))} ({f['cwe']})" if f.get("cwe") else cwe_name(None)


def iso(ts: float | None = None) -> str:
    return datetime.datetime.fromtimestamp(ts or time.time(), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(clone: Path, *args: str, env: dict | None = None, timeout: int = 600) -> str:
    proc = subprocess.run(["git", "-C", str(clone), *args], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env={**os.environ, **(env or {})})
    if proc.returncode != 0:
        raise RuntimeError(gh.redact(f"git {args[0]} failed: {proc.stderr.strip()[:400]}"))
    return proc.stdout


class LiveRun:
    """In-memory event list for a run in progress, so the dashboard can stream it."""

    def __init__(self, run_id: str):
        self.id = run_id
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self.finished = False
        self.proc: subprocess.Popen | None = None
        self.cancelled = False


class Engine:
    def __init__(self, store: Store, python: str, base_url: str, bedrock_key: str | None, bedrock_budget: float):
        self.store, self.python, self.base_url = store, python, base_url
        self.bedrock_key, self.bedrock_budget = bedrock_key, bedrock_budget
        self.queue: queue.Queue[str] = queue.Queue()
        self.live: dict[str, LiveRun] = {}
        self.current: str | None = None
        self.lock = threading.RLock()
        self.relay_state = {"connected": False, "since": None, "last_event": None, "error": None}
        self.poll_state = {"last": None, "error": None, "seen_prs": 0}
        CLONES.mkdir(parents=True, exist_ok=True)
        RUN_FILES.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ setup
    def start(self, port: int) -> None:
        self.port = port
        # Runs left "running" by a previous server process cannot finish now.
        for r in self.store.q("SELECT id FROM runs WHERE status IN ('running') AND source='github'"):
            self.store.update("runs", r["id"], status="failed", error="the server restarted during this review",
                              finished_at=now())
        for r in self.store.q("SELECT id FROM runs WHERE status='queued' AND source='github' ORDER BY created_at"):
            self.queue.put(r["id"])
        threading.Thread(target=self._worker, name="review-worker", daemon=True).start()
        threading.Thread(target=self._poller, name="pr-poller", daemon=True).start()
        threading.Thread(target=self._relay, name="webhook-relay", daemon=True).start()

    # --------------------------------------------------------- installations
    def sync_installations(self) -> None:
        if not gh.load_app():
            return
        seen = set()
        for inst in gh.as_app("GET", "/app/installations?per_page=100"):
            seen.add(inst["id"])
            acct = inst.get("account") or {}
            self.store.upsert("installations", {
                "id": inst["id"], "account": acct.get("login"), "account_type": acct.get("type"),
                "avatar": acct.get("avatar_url"), "repo_selection": inst.get("repository_selection"),
                "suspended": 1 if inst.get("suspended_at") else 0, "created_at": inst.get("created_at"),
                "removed": 0})
            repos = gh.paged(lambda m, p: gh.as_installation(inst["id"], m, p), "/installation/repositories",
                             "repositories")
            ids = []
            for repo in repos:
                ids.append(repo["id"])
                existing = self.store.one("SELECT enabled, added_at FROM repos WHERE id=?", (repo["id"],))
                self.store.upsert("repos", {
                    "id": repo["id"], "installation_id": inst["id"], "full_name": repo["full_name"],
                    "private": 1 if repo.get("private") else 0, "default_branch": repo.get("default_branch"),
                    "description": repo.get("description") or "", "language": repo.get("language") or "",
                    "enabled": existing["enabled"] if existing else 1, "removed": 0,
                    "added_at": existing["added_at"] if existing else now()})
            marks = ",".join("?" * len(ids)) or "NULL"
            self.store.x(f"UPDATE repos SET removed=1 WHERE installation_id=? AND id NOT IN ({marks})",
                         [inst["id"], *ids])
        marks = ",".join("?" * len(seen)) or "NULL"
        self.store.x(f"UPDATE installations SET removed=1 WHERE id NOT IN ({marks})", list(seen))
        self.store.x(f"UPDATE repos SET removed=1 WHERE installation_id NOT IN ({marks})", list(seen))

    # --------------------------------------------------------------- webhooks
    def handle_event(self, event: str, payload: dict, via: str) -> str:
        action = payload.get("action", "")
        repo = (payload.get("repository") or {}).get("full_name", "")
        if event in ("installation", "installation_repositories"):
            self.sync_installations()
            return f"installations synced ({action})"
        if event == "pull_request" and action in ("opened", "synchronize", "reopened", "ready_for_review"):
            inst = (payload.get("installation") or {}).get("id")
            run_id = self.enqueue(inst, payload["repository"], payload["pull_request"], f"webhook:{action}")
            return f"queued {run_id}" if run_id else "already reviewed"
        if event == "pull_request" and action == "closed":
            pr = payload["pull_request"]
            self.store.x("UPDATE runs SET merged=? WHERE repo=? AND pr_number=? AND source='github'",
                         (1 if pr.get("merged") else 0, repo, pr["number"]))
            return "merge state recorded"
        if event == "check_run" and action == "rerequested":
            ext = (payload.get("check_run") or {}).get("external_id")
            old = self.store.run(ext) if ext else None
            if old:
                new = self.rerun(old["id"], trigger="github:re-run")
                return f"re-run queued {new}"
        return "ignored"

    # --------------------------------------------------------------- queueing
    def enqueue(self, installation_id: int, repo: dict, pr: dict, trigger: str, force: bool = False) -> str | None:
        full = repo["full_name"]
        settings = self.store.settings()
        row = self.store.one("SELECT enabled FROM repos WHERE full_name=?", (full,))
        if row is not None and not row["enabled"]:
            return None
        if not force and (not settings["auto_review"] and trigger.startswith(("webhook", "poll"))):
            return None
        with self.lock:
            if not force and self.store.pending_for(full, pr["number"], pr["head"]["sha"]):
                return None
            run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
            user = pr.get("user") or {}
            self.store.upsert("runs", {
                "id": run_id, "source": "github", "repo": full, "repo_id": repo.get("id"),
                "installation_id": installation_id, "pr_number": pr["number"], "pr_title": pr.get("title", ""),
                "pr_url": pr.get("html_url"), "author": user.get("login"), "author_avatar": user.get("avatar_url"),
                "head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"], "head_ref": pr["head"].get("ref"),
                "base_ref": pr["base"].get("ref"), "trigger": trigger, "status": "queued",
                "created_at": now(), "backend": settings["backend"], "merged": 1 if pr.get("merged_at") else 0})
        try:
            check = gh.as_installation(installation_id, "POST", f"/repos/{full}/check-runs", {
                "name": CHECK_NAME, "head_sha": pr["head"]["sha"], "status": "queued", "external_id": run_id,
                "details_url": f"{self.base_url}/#/runs/{run_id}",
                "output": {"title": "Queued", "summary": "LGTM will review this pull request shortly."}})
            self.store.update("runs", run_id, check_run_id=check["id"], check_url=check.get("html_url"))
        except Exception as exc:  # noqa: BLE001 - the review still runs; the check is cosmetic until it completes
            self._log_note(run_id, f"could not create the check run: {gh.redact(str(exc))}")
        self.queue.put(run_id)
        return run_id

    def rerun(self, run_id: str, trigger: str = "manual") -> str | None:
        old = self.store.run(run_id)
        if not old or old["source"] != "github":
            return None
        pr = gh.as_installation(old["installation_id"], "GET", f"/repos/{old['repo']}/pulls/{old['pr_number']}")
        repo = gh.as_installation(old["installation_id"], "GET", f"/repos/{old['repo']}")
        return self.enqueue(old["installation_id"], repo, pr, trigger, force=True)

    def cancel(self, run_id: str) -> bool:
        run = self.store.run(run_id)
        if not run or run["status"] not in ("queued", "running"):
            return False
        live = self.live.get(run_id)
        if live:
            live.cancelled = True
            if live.proc and live.proc.poll() is None:
                live.proc.terminate()
        if run["status"] == "queued":
            self.store.update("runs", run_id, status="cancelled", finished_at=now())
            self._complete_check(run, "cancelled", "Review cancelled", "The review was cancelled from the LGTM dashboard.")
        return True

    # ----------------------------------------------------------------- worker
    def _worker(self) -> None:
        while True:
            run_id = self.queue.get()
            run = self.store.run(run_id)
            if not run or run["status"] != "queued":
                continue
            self.current = run_id
            try:
                self._review(run)
            except Exception as exc:  # noqa: BLE001 - one bad run must not stop the queue
                traceback.print_exc()
                msg = gh.redact(f"{type(exc).__name__}: {exc}")
                self.store.update("runs", run_id, status="failed", error=msg, finished_at=now())
                self._emit(run_id, {"type": "error", "msg": msg})
                try:   # GitHub is often why the review failed; telling it so must not stop the worker as well
                    self._complete_check(self.store.run(run_id), "neutral", "LGTM could not finish this review", msg)
                except Exception as exc2:  # noqa: BLE001
                    self._log_note(run_id, gh.redact(f"marking the check run as failed did not work either: {exc2}"))
            finally:
                live = self.live.get(run_id)
                if live:
                    with live.cond:
                        live.finished = True
                        live.cond.notify_all()
                self.current = None

    def _emit(self, run_id: str, event: dict) -> None:
        live = self.live.setdefault(run_id, LiveRun(run_id))
        with live.cond:
            event["seq"] = len(live.events)
            live.events.append(event)
            live.cond.notify_all()
        self.store.add_event(run_id, event["seq"], event)

    def _log_note(self, run_id: str, msg: str) -> None:
        with open(RUN_FILES / f"{run_id}.log", "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} lgtm-app: {msg}\n")

    def _review(self, run: dict) -> None:
        run_id, full, inst = run["id"], run["repo"], run["installation_id"]
        live = self.live.setdefault(run_id, LiveRun(run_id))
        started = time.time()
        settings = self.store.settings()
        backend = settings["backend"] if settings["backend"] in ("gpu", "bedrock") else "gpu"
        if backend == "bedrock" and not self.bedrock_key:
            backend = "gpu"
        judge = settings.get("judge") if settings.get("judge") in JUDGES else "kev"
        self.store.update("runs", run_id, status="running", started_at=now(), stage="fetch", backend=backend, judge=judge)
        self._emit(run_id, {"type": "accepted", "run_id": run_id, "repo": full, "pr": run["pr_number"],
                            "title": run["pr_title"], "backend": backend})
        self._check_progress(run, "fetch", started)

        # 1. fetch base and head
        owner, name = full.split("/")
        cache = CLONES / owner
        clone = cache / name
        if not (clone / ".git").is_dir():
            clone.mkdir(parents=True, exist_ok=True)
            git(clone, "init", "-q")
            git(clone, "remote", "add", "origin", f"https://github.com/{full}.git")
            git(clone, "config", "core.autocrlf", "false")
        env = gh.git_auth_env(inst)
        n = run["pr_number"]
        git(clone, "fetch", "--quiet", "--force", "origin",
            f"+refs/pull/{n}/head:refs/lgtm/pr-{n}/head", f"+refs/heads/{run['base_ref']}:refs/lgtm/pr-{n}/base", env=env)
        for sha in (run["head_sha"], run["base_sha"]):
            if subprocess.run(["git", "-C", str(clone), "cat-file", "-e", f"{sha}^{{commit}}"],
                              capture_output=True).returncode != 0:
                git(clone, "fetch", "--quiet", "origin", sha, env=env)
        merge_base = git(clone, "merge-base", run["head_sha"], run["base_sha"]).strip()
        self.store.update("runs", run_id, base_sha=merge_base)
        applied = self._applied_verified_fixes(run, clone, env)
        if applied:   # this commit only applies LGTM's own, already verified fixes: no second review
            return self._finish_fast(run, applied, started)
        case = {"id": f"{name}-pr{n}", "repo": full, "pr": n, "title": run["pr_title"],
                "base_commit": merge_base, "merge_commit": run["head_sha"]}
        case_file = RUN_FILES / f"{run_id}.case.json"
        case_file.write_text(json.dumps(case), encoding="utf-8")
        out = RUN_FILES / f"{run_id}.json"

        # 2. the pipeline, in a subprocess
        cmd = [self.python, "-u", str(HERE / "live_runner.py"), "--case-json", str(case_file),
               "--cache", str(cache), "--out", str(out), "--backend", backend,
               "--judge-endpoint", JUDGES[judge][0], "--judge-name", JUDGES[judge][1]]
        penv = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "PYTHONUNBUFFERED": "1"}
        penv.pop("AWS_BEARER_TOKEN_BEDROCK", None)
        if backend == "bedrock":
            cmd += ["--bedrock-budget", f"{self.bedrock_budget:.2f}"]
            penv["AWS_BEARER_TOKEN_BEDROCK"] = self.bedrock_key
        with open(RUN_FILES / f"{run_id}.log", "a", encoding="utf-8") as log:
            proc = subprocess.Popen(cmd, cwd=REPO_ROOT, env=penv, stdout=subprocess.PIPE, stderr=log,
                                    text=True, bufsize=1)
            live.proc = proc
            last_stage = None
            for line in proc.stdout:
                if not line.startswith("@@EVT "):
                    continue
                try:
                    event = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "meta":
                    self.store.update("runs", run_id, model=event.get("model"))
                    event.pop("row", None)
                if event.get("type") == "stage" and event.get("status") == "start":
                    last_stage = event["stage"]
                    self.store.update("runs", run_id, stage=last_stage)
                    self._check_progress(run, last_stage, started)
                self._emit(run_id, event)
            code = proc.wait()
        if live.cancelled:
            self.store.update("runs", run_id, status="cancelled", finished_at=now(),
                              latency=round(time.time() - started, 1))
            self._emit(run_id, {"type": "error", "msg": "review cancelled"})
            self._complete_check(self.store.run(run_id), "cancelled", "Review cancelled",
                                 "The review was cancelled from the LGTM dashboard.")
            return
        if code != 0 or not out.is_file():
            raise RuntimeError(f"the review process exited with code {code}")

        # 3. report back to GitHub
        record = json.loads(out.read_text(encoding="utf-8"))
        record["started_at"] = run["created_at"]
        out.write_text(json.dumps(record, indent=2), encoding="utf-8")
        findings = results.normalise_findings(record, "lgtm")
        verdict = results.verdict_of(record, findings)
        flagged = [f for f in findings if f["flagged"]]
        sev_max = max((f["severity"] for f in flagged), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)
        block = SEVERITY_RANK.get(settings["block_on"], 3)
        blocking = [f for f in flagged if SEVERITY_RANK.get(f["severity"], 0) >= block]
        if verdict == "error":
            conclusion = "error"
        elif blocking:
            conclusion = "blocked"
        elif flagged:
            conclusion = "findings"
        else:
            conclusion = "passed"
        latency = round(time.time() - started, 1)
        self.store.update("runs", run_id, status="completed", finished_at=now(), latency=latency,
                          verdict=verdict, conclusion=conclusion, n_flagged=len(flagged),
                          n_candidates=len(findings), severity_max=sev_max, stage="done",
                          error=record.get("error"))
        run = self.store.run(run_id)
        self._store_findings(run, findings)
        try:
            self._post_results(run, record, findings, blocking)
        except Exception as exc:  # noqa: BLE001 - the run is stored either way
            msg = gh.redact(f"posting to GitHub failed: {exc}")
            self._log_note(run_id, msg)
            self._emit(run_id, {"type": "log", "level": "warning", "msg": msg})
        self._emit(run_id, {"type": "done", "verdict": verdict, "conclusion": conclusion, "n_flagged": len(flagged),
                            "latency_seconds": latency, "check_url": run.get("check_url"),
                            "review_url": self.store.run(run_id).get("review_url")})

    # ------------------------------------------------- verified suggestions and the fast path
    def _record_suggestion(self, run: dict, f: dict, fix: dict) -> None:
        self.store.x("INSERT INTO suggestions (repo, pr_number, head_sha, run_id, finding_key, path, start_line, end_line, "
                     "replacement, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (run["repo"], run["pr_number"], run["head_sha"], run["id"], f"{run['id']}:{f['id']}", f["file"],
                      fix["start_line"], fix["end_line"], fix["replacement"], now()))

    def _applied_verified_fixes(self, run: dict, clone: Path, env: dict) -> dict | None:
        """If this commit is exactly the previous review's verified suggestions applied (some or all of them), and they
        cover every finding that review reported, return what was applied. Anything else gets a full review."""
        prev = self.store.one("SELECT * FROM runs WHERE repo=? AND pr_number=? AND source='github' AND status='completed' "
                              "AND head_sha<>? ORDER BY created_at DESC LIMIT 1", (run["repo"], run["pr_number"], run["head_sha"]))
        if not prev or not prev.get("n_flagged"):
            return None
        flagged = self.store.q("SELECT * FROM findings WHERE run_id=? AND flagged=1", (prev["id"],))
        sugg = self.store.q("SELECT * FROM suggestions WHERE run_id=?", (prev["id"],))
        if not flagged or not sugg or {f["id"] for f in flagged} - {s["finding_key"] for s in sugg}:
            return None
        if subprocess.run(["git", "-C", str(clone), "cat-file", "-e", f"{prev['head_sha']}^{{commit}}"], capture_output=True).returncode:
            git(clone, "fetch", "--quiet", "origin", prev["head_sha"], env=env)
        changed = [p for p in git(clone, "diff", "--name-only", prev["head_sha"], run["head_sha"]).splitlines() if p]
        spans: dict[str, list] = {}
        for s in sugg:
            key = (s["start_line"], s["end_line"], s["replacement"])
            if key not in spans.setdefault(s["path"], []):
                spans[s["path"]].append(key)
        if not changed or any(p not in spans for p in changed):
            return None
        applied = []
        for path in changed:
            old = git(clone, "show", f"{prev['head_sha']}:{path}").split("\n")
            new = git(clone, "show", f"{run['head_sha']}:{path}").split("\n")
            opts = sorted(spans[path], key=lambda t: -t[0])   # apply bottom-up so line numbers stay valid
            hit = None
            for mask in range(1, 2 ** len(opts)):
                lines = old
                for i, (a, b, rep) in enumerate(opts):
                    if mask >> i & 1:
                        lines = suggest.apply_span(lines, a, b, rep)
                if lines == new:
                    hit = [o for i, o in enumerate(opts) if mask >> i & 1]
                    break
            if hit is None:
                return None
            applied += [(path, a, b) for a, b, _ in hit]
        covered = {s["finding_key"] for s in sugg if (s["path"], s["start_line"], s["end_line"]) in applied}
        if {f["id"] for f in flagged} - covered:
            return None   # some finding's fix was not applied: that needs a real review
        return {"prev": prev, "findings": flagged, "applied": applied}

    def _finish_fast(self, run: dict, applied: dict, started: float) -> None:
        run_id = run["id"]
        prev, flagged = applied["prev"], applied["findings"]
        judge_name = JUDGES.get(prev.get("judge") or "kev", JUDGES["kev"])[1]
        latency = round(time.time() - started, 1)
        self._emit(run_id, {"type": "stage", "stage": "fetch", "status": "done", "detail": "this commit applies LGTM's verified fix"})
        self.store.update("runs", run_id, status="completed", finished_at=now(), latency=latency, verdict="safe",
                          conclusion="passed", n_flagged=0, n_candidates=0, severity_max=None, stage="done",
                          judge=prev.get("judge"), trigger=(run.get("trigger") or "") + ":verified-fix")
        for f in self.store.q("SELECT id, file, cwe FROM findings WHERE repo=? AND pr_number=? AND source='github' AND status IN ('open', 'confirmed')",
                              (run["repo"], run["pr_number"])):
            if any((f["file"], f["cwe"]) == (g["file"], g["cwe"]) for g in flagged):
                self.store.update("findings", f["id"], status="fixed", updated_at=now(),
                                  note=f"Fixed by LGTM's verified suggestion, applied in {run['head_sha'][:7]}.")
        items = "\n".join(f"- {finding_title(dict(g))} at `{g['file']}:{g['line']}`" for g in flagged)
        link = f"{self.base_url}/#/runs/{prev['id']}"
        summary = (f"This commit applies exactly the fix LGTM suggested on the previous review, and nothing else. The {judge_name} "
                   f"checked that fix before it was offered, so LGTM did not review it a second time.\n\nFixed:\n{items}\n\n"
                   f"[The review that found it]({link})")
        self._complete_check(self.store.run(run_id), "success", "Applied LGTM's verified fix", summary)
        try:
            body = (f"**The fix LGTM suggested is in, so this pull request is clear.** ✅\n\n{items}\n\n"
                    f"<sub>The {judge_name} checked the fix before it was offered; this commit applies only that change.</sub>")
            review = gh.as_installation(run["installation_id"], "POST", f"/repos/{run['repo']}/pulls/{run['pr_number']}/reviews",
                                        {"commit_id": run["head_sha"], "event": "COMMENT", "body": self._md(body)})
            self.store.update("runs", run_id, review_id=review.get("id"), review_url=review.get("html_url"))
            self._dismiss_stale(self.store.run(run_id), review.get("id"))
        except Exception as exc:  # noqa: BLE001 - the check already says it
            self._log_note(run_id, gh.redact(f"posting the verified-fix review failed: {exc}"))
        self._emit(run_id, {"type": "done", "verdict": "safe", "conclusion": "passed", "n_flagged": 0, "latency_seconds": latency,
                            "check_url": self.store.run(run_id).get("check_url"), "review_url": self.store.run(run_id).get("review_url")})

    def _store_findings(self, run: dict, findings: list[dict]) -> None:
        # A newer review of the same PR supersedes the older ones: what it no longer reports is fixed.
        still = {(f["file"], f["cwe"]) for f in findings if f["flagged"]}
        for old in self.store.q("SELECT id, file, cwe FROM findings WHERE repo=? AND pr_number=? AND run_id<>? "
                                "AND source='github' AND status IN ('open', 'confirmed')", (run["repo"], run["pr_number"], run["id"])):
            if (old["file"], old["cwe"]) not in still:
                self.store.update("findings", old["id"], status="fixed", updated_at=now(),
                                  note=f"Not reported by the review of {run['head_sha'][:7]}.")
        for f in findings:
            self.store.upsert("findings", {
                "id": f"{run['id']}:{f['id']}", "run_id": run["id"], "source": run["source"], "repo": run["repo"],
                "pr_number": run["pr_number"], "pr_title": run["pr_title"], "file": f["file"], "line": f["line"],
                "cwe": f["cwe"], "category": f["category"], "severity": f["severity"], "agent": f["agent"],
                "flagged": 1 if f["flagged"] else 0, "kev_verdict": f["kev_verdict"], "title": finding_title(f),
                "explanation": f["explanation"][:2000], "status": "open" if f["flagged"] else "filtered",
                "created_at": run["finished_at"] or now(), "updated_at": now()})

    # ------------------------------------------------------- GitHub reporting
    def _owner(self) -> str:
        return (gh.load_app() or {}).get("owner") or "cyberjj999"

    def _md(self, text: str) -> str:
        return gh.safe_markdown(text or "", self._owner())

    def _check_progress(self, run: dict, stage: str, started: float) -> None:
        if not run.get("check_run_id"):
            run = self.store.run(run["id"]) or run
            if not run.get("check_run_id"):
                return
        order = list(STAGE_LABELS)
        idx = order.index(stage) if stage in order else 0
        lines = []
        for i, key in enumerate(order):
            mark = "✅" if i < idx else ("⏳" if i == idx else "⬜")
            lines.append(f"{mark} {STAGE_LABELS[key]}")
        body = {"status": "in_progress", "started_at": iso(started),
                "output": {"title": f"Reviewing: {STAGE_LABELS.get(stage, stage)}",
                           "summary": "\n".join(lines) + f"\n\n[Watch it live in LGTM]({self.base_url}/#/runs/{run['id']})"}}
        try:
            gh.as_installation(run["installation_id"], "PATCH", f"/repos/{run['repo']}/check-runs/{run['check_run_id']}", body)
        except Exception as exc:  # noqa: BLE001
            self._log_note(run["id"], gh.redact(f"check-run progress update failed: {exc}"))

    def _complete_check(self, run: dict | None, conclusion: str, title: str, summary: str,
                        text: str = "", annotations: list | None = None) -> None:
        if not run or not run.get("check_run_id"):
            return
        output = {"title": title[:250], "summary": self._md(summary)[:60000]}
        if text:
            output["text"] = self._md(text)[:60000]
        anns = annotations or []
        output["annotations"] = anns[:50]
        path = f"/repos/{run['repo']}/check-runs/{run['check_run_id']}"
        gh.as_installation(run["installation_id"], "PATCH", path, {
            "status": "completed", "conclusion": conclusion, "completed_at": iso(), "output": output})
        for i in range(50, len(anns), 50):  # GitHub takes 50 annotations per request
            gh.as_installation(run["installation_id"], "PATCH", path,
                               {"output": {"title": output["title"], "summary": output["summary"],
                                           "annotations": anns[i:i + 50]}})

    def _post_results(self, run: dict, record: dict, findings: list[dict], blocking: list[dict]) -> None:
        flagged = [f for f in findings if f["flagged"]]
        filtered = len(findings) - len(flagged)
        settings = self.store.settings()
        link = f"{self.base_url}/#/runs/{run['id']}"
        mins = f"{int(run['latency'] // 60)}m {int(run['latency'] % 60)}s" if run["latency"] else "-"
        model = (run.get("model") or "").replace("bedrock:", "")
        if run["verdict"] == "error":
            self._complete_check(run, "neutral", "LGTM could not finish this review",
                                 f"The pipeline reported an error: `{record.get('error')}`.\n\n[Run details]({link})")
            return

        # Check run
        if flagged:
            title = (f"{len(flagged)} security finding{'s' if len(flagged) != 1 else ''}: "
                     + ", ".join(sorted({cwe_name(f['cwe']) for f in flagged})))
        else:
            title = "No security findings"
        rows = ["| Severity | Issue | Location | Judge |", "|---|---|---|---|"]
        for f in flagged:
            rows.append(f"| {SEVERITY_ICON.get(f['severity'], '⚪')} {f['severity'].title()} | {finding_title(f)} | "
                        f"`{f['file']}:{f['line']}` | {'confirmed' if f['kev_verdict'] == 'real' else (f['kev_verdict'] or 'not judged')} |")
        policy = (f"**Merge blocked by policy:** {len(blocking)} finding(s) at or above **{settings['block_on']}** severity."
                  if blocking else "Nothing at or above the blocking severity "
                  f"(**{settings['block_on']}**).")
        summary = "\n".join([
            policy, "",
            *(rows if flagged else ["LGTM reviewed every changed Python file for SQL injection and broken authorization "
                                    "and found nothing it could back with evidence."]),
            "",
            f"{len(findings)} candidate finding(s) raised by the agents; {filtered} filtered out by evidence checks "
            f"and the {JUDGES.get(run.get('judge') or 'kev', JUDGES['kev'])[1]}. Semgrep: {record.get('semgrep_findings_in_diff', 0) if isinstance(record.get('semgrep_findings_in_diff'), int) else len(record.get('semgrep_findings_in_diff') or [])} hit(s) in the diff.",
            "",
            f"Reviewed in {mins} by {model or 'the reviewer model'} with the {JUDGES.get(run.get('judge') or 'kev', JUDGES['kev'])[2]} judge. [Open the full trace in LGTM]({link})",
        ])
        annotations = []
        for f in flagged:
            if not f["file"] or not f["line"]:
                continue
            annotations.append({
                "path": f["file"], "start_line": int(f["line"]), "end_line": int(f["line"]),
                "annotation_level": "failure" if f in blocking else "warning",
                "title": f"{f['severity'].title()}: {finding_title(f)}"[:255],
                "message": self._md(f["explanation"])[:4000] or finding_title(f),
                **({"raw_details": self._md(f["suggested_fix"])[:4000]} if f.get("suggested_fix") else {}),
            })
        conclusion = "failure" if blocking else ("neutral" if flagged else "success")
        self._complete_check(run, conclusion, title, summary, annotations=annotations)

        # Pull-request review
        if not settings["inline_comments"]:
            return
        valid = self._commentable_lines(run)
        comments, loose, taken, posted = [], [], set(), []
        self._briefs = brief.briefs(self.store, self.bedrock_key, self.bedrock_budget,
                                    {f"{run['id']}:{f['id']}": f for f in flagged})
        for f in flagged:
            f["brief"] = self._briefs.get(f"{run['id']}:{f['id']}")
        judge_url, judge_name = JUDGES.get(run.get("judge") or "kev", JUDGES["kev"])[:2]
        for f in flagged:
            line = self._snap(valid.get(f["file"] or "", set()), f["line"])
            fix = None
            covering = next((p for p in posted if p["path"] == f["file"] and p["start_line"] - 2 <= int(f["line"] or 0) <= p["end_line"] + 2), None)
            if covering:   # the fix already suggested for these lines covers this finding too
                self._record_suggestion(run, f, covering)
            elif line and f.get("file") in self._added:
                try:   # a one-click fix, when it can be expressed on lines this pull request added
                    fix = suggest.suggest(self.bedrock_key, self.bedrock_budget, f["file"], self._added[f["file"]], f)
                    if fix:   # offered only if the same judge agrees the bug is gone from the fixed code
                        ok, why = suggest.verify(judge_url, f, f["file"], self._added[f["file"]], fix)
                        self._log_note(run["id"], f"suggestion for {f['file']}:{f['line']}: {why}")
                        fix = fix if ok else None
                except Exception as exc:  # noqa: BLE001 - the prose fix still goes out
                    self._log_note(run["id"], gh.redact(f"no committable suggestion for {f['file']}:{f['line']}: {exc}"))
                    fix = None
                if fix and any((f["file"], n) in taken for n in range(fix["start_line"], fix["end_line"] + 1)):
                    fix = None   # an earlier comment already suggests a change to these lines
            body = self._comment_body(f, link, judge_name, fix, covering)
            if fix:
                fix = {**fix, "path": f["file"]}
                posted.append(fix)
                self._record_suggestion(run, f, fix)
                taken.update((f["file"], n) for n in range(fix["start_line"], fix["end_line"] + 1))
                c = {"path": f["file"], "line": fix["end_line"], "side": "RIGHT", "body": body}
                if fix["start_line"] != fix["end_line"]:
                    c.update(start_line=fix["start_line"], start_side="RIGHT")
                comments.append(c)
            elif line:
                comments.append({"path": f["file"], "line": line, "side": "RIGHT", "body": body})
            else:
                loose.append(f"**`{f['file']}:{f['line']}`**\n\n{body}")
        if flagged:
            head = (f"**LGTM found {len(flagged)} security issue{'s' if len(flagged) != 1 else ''} in this pull request.**"
                    + (" The merge is blocked by your LGTM policy until they are fixed or dismissed." if blocking else ""))
        else:
            head = "**LGTM found no security issues in this pull request.** ✅"
        body = "\n\n".join([head, *loose, f"<sub>[Review details and agent trace]({link}) · {mins} · "
                                         f"{len(findings)} candidates, {filtered} filtered</sub>"])
        event = "REQUEST_CHANGES" if blocking and settings["request_changes"] else "COMMENT"
        payload = {"commit_id": run["head_sha"], "event": event, "body": self._md(body), "comments": comments}
        try:
            review = gh.as_installation(run["installation_id"], "POST",
                                        f"/repos/{run['repo']}/pulls/{run['pr_number']}/reviews", payload)
        except gh.GitHubError as exc:
            if exc.status != 422 or not comments:
                raise
            # A line GitHub will not take: put every comment in the review body instead.
            extra = [f"**`{c['path']}:{c['line']}`**\n\n{c['body']}" for c in comments]
            payload = {**payload, "comments": [], "body": self._md("\n\n".join([head, *extra, *loose]))}
            review = gh.as_installation(run["installation_id"], "POST",
                                        f"/repos/{run['repo']}/pulls/{run['pr_number']}/reviews", payload)
        self.store.update("runs", run["id"], review_id=review.get("id"), review_url=review.get("html_url"))
        if event != "REQUEST_CHANGES":
            self._dismiss_stale(run, review.get("id"))

    def _dismiss_stale(self, run: dict, keep_id) -> None:
        """A newer review no longer blocks: lift LGTM's own earlier "Changes requested"."""
        slug = (gh.load_app() or {}).get("slug", "")
        path = f"/repos/{run['repo']}/pulls/{run['pr_number']}/reviews"
        for rv in gh.paged(lambda m, p: gh.as_installation(run["installation_id"], m, p), path, None):
            if (rv.get("state") == "CHANGES_REQUESTED" and rv.get("id") != keep_id
                    and (rv.get("user") or {}).get("login") == f"{slug}[bot]"):
                try:
                    gh.as_installation(run["installation_id"], "PUT", f"{path}/{rv['id']}/dismissals", {
                        "message": f"Superseded by LGTM's review of {run['head_sha'][:7]}, which found nothing blocking.",
                        "event": "DISMISS"})
                except gh.GitHubError as exc:
                    self._log_note(run["id"], gh.redact(f"could not dismiss review {rv['id']}: {exc}"))

    def _comment_body(self, f: dict, link: str, judge_name: str = "Kev judge", fix: dict | None = None,
                      covering: dict | None = None) -> str:
        judge = {"real": f"confirmed by the {judge_name}", "uncertain": f"the {judge_name} was unsure"}.get(
            f["kev_verdict"] or "", "not judged")
        parts = [f"{SEVERITY_ICON.get(f['severity'], '⚪')} **{f['severity'].title()} · {finding_title(f)}** · {judge}", ""]
        if f.get("brief"):   # readable first; the agent's full reasoning stays one click away
            parts += [self._md(brief.markdown(f["brief"])), "", "<details><summary>Full reasoning</summary>", "",
                      self._md(f["explanation"]), "", "</details>"]
        else:
            parts += [self._md(f["explanation"])]
        ev = [e for e in f["evidence"] if e.get("content")][:3]
        if ev:
            parts += ["", f"<details><summary>Evidence the agents cited ({len(ev)})</summary>", ""]
            for e in ev:
                where = f"{e.get('file') or ''}{(':' + str(e['lines'])) if e.get('lines') else ''}"
                parts += [f"`{where}` ({e.get('type') or 'code'})", "", "```python", e["content"].strip()[:1200], "```", ""]
            parts += ["</details>"]
        if fix:
            parts += ["", f"**Suggested fix**, checked by the {judge_name} before it was offered. Commit it with the button below.", "",
                      "```suggestion", fix["replacement"], "```"]
        elif covering:
            parts += ["", f"**Fix:** the suggestion on lines {covering['start_line']}–{covering['end_line']} fixes this too."]
        elif f.get("suggested_fix") and brief.fix_markdown(f.get("brief"), f["file"]):
            parts += ["", self._md(brief.fix_markdown(f["brief"], f["file"])), "", "<details><summary>The fix in full</summary>", "",
                      self._md(f["suggested_fix"]), "", "</details>"]
        elif f.get("suggested_fix"):
            parts += ["", "**Suggested fix**", "", self._md(f["suggested_fix"])]
        parts += ["", f"<sub>{f['agent'] or 'reviewer'} · {f['tool_calls']} tool calls · [trace]({link})</sub>"]
        return "\n".join(parts)

    def _commentable_lines(self, run: dict) -> dict[str, set[int]]:
        files = gh.paged(lambda m, p: gh.as_installation(run["installation_id"], m, p),
                         f"/repos/{run['repo']}/pulls/{run['pr_number']}/files", None)
        out: dict[str, set[int]] = {}
        self._added = {fd["filename"]: suggest.added_lines(fd.get("patch") or "") for fd in files}
        for fd in files:
            parsed = results.parse_diff(f"diff --git a/{fd['filename']} b/{fd['filename']}\n" + (fd.get("patch") or ""))
            lines = set()
            for p in parsed:
                for h in p["hunks"]:
                    lines.update(l["new"] for l in h["lines"] if l["new"] is not None)
            out[fd["filename"]] = lines
        return out

    @staticmethod
    def _snap(lines: set[int], line) -> int | None:
        if not line or not lines:
            return None
        line = int(line)
        if line in lines:
            return line
        near = sorted(lines, key=lambda x: abs(x - line))
        return near[0] if abs(near[0] - line) <= 3 else None

    # ----------------------------------------------------------------- poller
    def _poller(self) -> None:
        time.sleep(3)
        while True:
            try:
                if gh.load_app():
                    self.sync_installations()
                    self.poll_once()
                    self.poll_state.update(last=now(), error=None)
            except Exception as exc:  # noqa: BLE001
                self.poll_state.update(last=now(), error=gh.redact(str(exc))[:300])
            time.sleep(max(10, int(self.store.settings().get("poll_seconds") or 30)))

    def poll_once(self) -> None:
        seen = 0
        for repo in self.store.q("SELECT * FROM repos WHERE removed=0 AND enabled=1"):
            prs = gh.as_installation(repo["installation_id"], "GET", f"/repos/{repo['full_name']}/pulls?state=open&per_page=50")
            for pr in prs:
                seen += 1
                if not self.store.pending_for(repo["full_name"], pr["number"], pr["head"]["sha"]):
                    rid = self.enqueue(repo["installation_id"], {"id": repo["id"], "full_name": repo["full_name"]},
                                       pr, "poll")
                    if rid:
                        self.store.upsert("deliveries", {"id": f"poll-{rid}", "event": "pull_request", "action": "poll",
                                                         "repo": repo["full_name"], "received_at": now(), "via": "poll",
                                                         "verified": 1, "outcome": f"queued {rid} (missed by the relay)"})
            # Merge state of PRs we reviewed and that are now closed.
            for r in self.store.q("SELECT DISTINCT pr_number FROM runs WHERE repo=? AND source='github' AND merged=0",
                                  (repo["full_name"],)):
                if not any(p["number"] == r["pr_number"] for p in prs):
                    pr = gh.as_installation(repo["installation_id"], "GET",
                                            f"/repos/{repo['full_name']}/pulls/{r['pr_number']}")
                    if pr.get("merged_at"):
                        self.store.x("UPDATE runs SET merged=1 WHERE repo=? AND pr_number=?",
                                     (repo["full_name"], r["pr_number"]))
        self.poll_state["seen_prs"] = seen

    # ------------------------------------------------------------------ relay
    def _relay(self) -> None:
        """Read the smee.io channel and forward each delivery to our own webhook endpoint.

        smee re-serialises the JSON body, so the endpoint checks the HMAC against
        the compact re-encoding as well as the raw bytes (see server.py).
        """
        backoff = 2
        while True:
            url = gh.load_relay()
            if not url:
                time.sleep(5)
                continue
            try:
                req = urllib.request.Request(url, headers={"Accept": "text/event-stream", "User-Agent": "lgtm-demo"})
                with urllib.request.urlopen(req, timeout=90) as resp:
                    self.relay_state.update(connected=True, since=now(), error=None)
                    backoff = 2
                    data: list[str] = []
                    for raw in resp:
                        line = raw.decode("utf-8", "replace").rstrip("\r\n")
                        if line.startswith("data:"):
                            data.append(line[5:].lstrip())
                        elif line == "" and data:
                            self._forward("\n".join(data))
                            data = []
            except Exception as exc:  # noqa: BLE001 - reconnect; polling covers the gap
                self.relay_state.update(connected=False, error=type(exc).__name__)
            self.relay_state["connected"] = False
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

    def _forward(self, data: str) -> None:
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return
        if "body" not in msg or "x-github-event" not in msg:
            return
        self.relay_state["last_event"] = now()
        body = json.dumps(msg["body"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-LGTM-Via": "relay",
                   "X-GitHub-Event": msg.get("x-github-event", ""),
                   "X-GitHub-Delivery": msg.get("x-github-delivery", ""),
                   "X-Hub-Signature-256": msg.get("x-hub-signature-256", "")}
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/github/webhook", data=body,
                                     headers=headers, method="POST")
        try:
            urllib.request.urlopen(req, timeout=30).read()
        except Exception:  # noqa: BLE001 - recorded by the endpoint itself
            pass


# ---------------------------------------------------------------------------
# Benchmark history, imported once into the runs table
# ---------------------------------------------------------------------------
SHOPLY_RUNS = REPO_ROOT / "benchmark" / "runs" / "shoply-20261029" / "lgtm"
SHOPLY_CASES = REPO_ROOT / "benchmark" / "cases"
IMPORT_SETS = [("heldout_v21", "lgtm"), ("real_prs_sqli", "lgtm"), ("real_prs", "lgtm"), ("live", "lgtm")]


def shoply_patch(case_id: str) -> Path | None:
    m = re.fullmatch(r"(sqli|authz)_(\d+)_(safe|vulnerable)", case_id)
    if not m:
        return None
    path = SHOPLY_CASES / m.group(1) / f"case_{m.group(2)}_{m.group(3)}.patch"
    return path if path.is_file() else None


def import_history(store: Store) -> int:
    """Benchmark runs appear in the history, marked as imported, never as connected repos."""
    added = 0
    seen_cases: set[str] = set()
    for ds_id, mode in IMPORT_SETS:
        directory = results.dataset(ds_id)["modes"][mode]
        for path in results.result_files(directory):
            try:
                rec = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            # v2.1 SQLi re-runs replace the v2.0 runs of the same rows
            if ds_id != "live" and rec.get("id") in seen_cases:
                continue
            seen_cases.add(rec.get("id"))
            added += _import_one(store, rec, ds_id, mode, path)
    for path in sorted(SHOPLY_RUNS.glob("*.json")) if SHOPLY_RUNS.is_dir() else []:
        if path.stem in ("run", "summary"):
            continue
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rec.setdefault("repo", "benchmark/shoply")
        rec["repo"] = rec["repo"] or "benchmark/shoply"
        added += _import_one(store, rec, "shoply", "lgtm", path)
    return added


def _import_one(store: Store, rec: dict, ds_id: str, mode: str, path: Path) -> int:
    run_id = f"imp-{ds_id}-{path.stem}"
    if store.run(run_id):
        return 0
    findings = results.normalise_findings(rec, mode)
    verdict = results.verdict_of(rec, findings)
    flagged = [f for f in findings if f["flagged"]]
    when = rec.get("started_at") or datetime.datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%dT%H:%M:%S")
    adv = results.ADVISORIES.get(rec.get("advisory") or "", {})
    side = "introducing" if rec.get("expected") == "vulnerable" else "fix"
    pr_num = rec.get("pr") if isinstance(rec.get("pr"), int) else (adv.get(side) or {}).get("pr")
    title = rec.get("title") or adv.get("title") or path.stem.replace("_", " ")
    if ds_id == "shoply":
        title = f"Shoply case {path.stem.replace('_', ' ')}"
    sev_max = max((f["severity"] for f in flagged), key=lambda s: SEVERITY_RANK.get(s, 0), default=None)
    row = {
        "id": run_id, "source": "imported", "repo": rec.get("repo") or "unknown", "pr_number": pr_num,
        "pr_title": title, "pr_url": (adv.get(side) or {}).get("url"), "head_sha": rec.get("pr_sha"),
        "base_sha": rec.get("base") or rec.get("base_sha"), "trigger": "benchmark", "status": "completed",
        "conclusion": "error" if verdict == "error" else ("blocked" if any(SEVERITY_RANK.get(f["severity"], 0) >= 3 for f in flagged)
                                                          else ("findings" if flagged else "passed")),
        "verdict": verdict, "n_flagged": len(flagged), "n_candidates": len(findings), "severity_max": sev_max,
        "created_at": when, "started_at": when, "finished_at": when, "latency": rec.get("latency_seconds"),
        "backend": rec.get("backend") or "gpu", "model": rec.get("model"), "error": rec.get("error"),
        "imported_dataset": ds_id, "imported_mode": mode, "imported_key": path.stem,
        "outcome": rec.get("outcome"), "expected": rec.get("expected"), "advisory": rec.get("advisory"),
        "merged": 1, "stage": "done",
    }
    store.upsert("runs", row)
    for f in findings:
        status = "filtered"
        if f["flagged"]:
            status = "fixed" if rec.get("outcome") == "TP" else ("false_positive" if rec.get("outcome") == "FP" else "open")
        store.upsert("findings", {
            "id": f"{run_id}:{f['id']}", "run_id": run_id, "source": "imported", "repo": row["repo"],
            "pr_number": pr_num, "pr_title": title, "file": f["file"], "line": f["line"], "cwe": f["cwe"],
            "category": f["category"], "severity": f["severity"], "agent": f["agent"],
            "flagged": 1 if f["flagged"] else 0, "kev_verdict": f["kev_verdict"], "title": finding_title(f),
            "explanation": (f["explanation"] or "")[:2000], "status": status,
            "note": "Imported from the benchmark; status from the advisory's answer key." if f["flagged"] else None,
            "created_at": when, "updated_at": when})
    return 1


def median(values) -> float | None:
    vals = [v for v in values if v is not None]
    return round(statistics.median(vals), 1) if vals else None
