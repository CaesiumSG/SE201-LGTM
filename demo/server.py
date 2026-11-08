#!/usr/bin/env python3
"""LGTM: the security reviewer as a GitHub App, with its dashboard.

Standard library plus PyJWT. One process serves:

    /                         the dashboard (demo/web), three skins over one app
    /auth/login, /auth/callback, /auth/logout     Sign in with GitHub (the app's OAuth)
    /github/manifest/callback  end of the App Manifest flow: stores the app's credentials
    /github/installed          GitHub sends the user here after installing the app
    /api/github/webhook        webhook deliveries (HMAC-verified), via the smee.io relay
    /api/...                   the dashboard API (see Handler.routes)

Reviews run one at a time in a worker thread (reviews.py); the poller and the
relay run beside it. Usage, from the repository root:

    /path/to/.venv/bin/python demo/server.py [--port 8765]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter, defaultdict
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import github_app as gh  # noqa: E402
import results  # noqa: E402
import report  # noqa: E402
import reviews  # noqa: E402
import brief  # noqa: E402
import claude_judge  # noqa: E402
import liveapp  # noqa: E402
import workspace  # noqa: E402
from bedrock_env import ledger_total, read_bedrock_key  # noqa: E402
from store import SEVERITY_RANK, Store, now  # noqa: E402

REPO_ROOT = HERE.parent
WEB = HERE / "web"
OLLAMA = ("127.0.0.1", 11435)
KEV = ("127.0.0.1", 8008)
SESSION_COOKIE = "lgtm_session"
SESSION_TTL = 8 * 3600
TRIAGE_STATES = {"open", "confirmed", "false_positive", "accepted_risk", "fixed"}

STORE: Store
ENGINE: reviews.Engine
BASE_URL = "http://127.0.0.1:8765"
SESSIONS: dict[str, dict] = {}       # in memory only: user tokens never touch the disk
OAUTH_STATES: dict[str, float] = {}
MANIFEST_STATES: dict[str, float] = {}
WS = workspace.Workspace()
APPS = liveapp.LiveApps(workspace.ROOT)


# ---------------------------------------------------------------------------
# Signed-in users
# ---------------------------------------------------------------------------
def load_user_scope(sess: dict) -> None:
    """The installations and repositories this user can see, as GitHub reports them."""
    token = sess["token"]
    installs = gh.as_user(token, "GET", "/user/installations?per_page=100").get("installations", [])
    app = gh.load_app() or {}
    repos, ids = set(), []
    for inst in installs:
        if app.get("id") and inst.get("app_id") != app["id"]:
            continue
        ids.append(inst["id"])
        for repo in gh.paged(lambda m, p: gh.as_user(token, m, p), f"/user/installations/{inst['id']}/repositories",
                             "repositories"):
            repos.add(repo["full_name"])
    sess.update(installations=ids, repos=repos, scoped_at=time.time())


def scope_sql(sess: dict, alias: str = "") -> tuple[str, list]:
    """WHERE fragment: imported benchmark rows, plus repos of installations this user can access."""
    p = f"{alias}." if alias else ""
    repos = sorted(sess.get("repos") or [])
    if not repos:
        return f"{p}source='imported'", []
    return f"({p}source='imported' OR {p}repo IN ({','.join('?' * len(repos))}))", repos


# ---------------------------------------------------------------------------
# Dashboard data
# ---------------------------------------------------------------------------
def source_clause(source: str) -> str:
    return {"connected": " AND source='github'", "imported": " AND source='imported'"}.get(source, "")


def overview(sess: dict, source: str) -> dict:
    where, args = scope_sql(sess)
    where += source_clause(source)
    runs = STORE.q(f"SELECT * FROM runs WHERE {where} ORDER BY created_at DESC", args)
    done = [r for r in runs if r["status"] == "completed"]
    finds = STORE.q(f"SELECT * FROM findings WHERE {where}", args)
    flagged = [f for f in finds if f["flagged"]]
    by_day: dict[str, Counter] = defaultdict(Counter)
    for r in done:
        by_day[(r["created_at"] or "")[:10]][r["conclusion"] or "passed"] += 1
    # A continuous axis: at least the last 14 days, empty days included.
    today = datetime.date.today()
    first = min([datetime.date.fromisoformat(d) for d in by_day if d] + [today - datetime.timedelta(days=13)])
    first = max(first, today - datetime.timedelta(days=29))
    days = [(first + datetime.timedelta(days=i)).isoformat() for i in range((today - first).days + 1)]
    by_cwe = Counter(f["cwe"] or "other" for f in flagged)
    repos = repo_rows(sess, source)
    return {
        "totals": {
            "runs": len(done), "prs": len({(r["repo"], r["pr_number"], r["head_sha"]) for r in done}),
            "repos": len(repos), "connected_repos": sum(1 for r in repos if r["source"] == "github"),
            "flagged": len(flagged), "candidates": len(finds),
            "filtered": len(finds) - len(flagged),
            "blocked": sum(1 for r in done if r["conclusion"] == "blocked"),
            "open": sum(1 for f in flagged if f["status"] in ("open", "confirmed")),
            "median_latency": reviews.median(r["latency"] for r in done),
            "running": sum(1 for r in runs if r["status"] in ("queued", "running")),
            "errors": sum(1 for r in done if r["verdict"] == "error"),
            "app_runs": sum(1 for r in done if r["source"] == "github"),
            "imported_runs": sum(1 for r in done if r["source"] == "imported"),
        },
        "severity": dict(Counter(f["severity"] for f in flagged)),
        "by_cwe": [{"cwe": k, "name": reviews.cwe_name(k), "n": v} for k, v in by_cwe.most_common(8)],
        "series": [{"day": d, **by_day[d]} for d in days],
        "repos": repos[:12],
        "recent": [run_row(r) for r in runs[:10]],
    }


def repo_rows(sess: dict, source: str = "all") -> list[dict]:
    where, args = scope_sql(sess)
    where += source_clause(source)
    stats = defaultdict(lambda: {"runs": 0, "flagged": 0, "blocked": 0, "lat": [], "last": None, "open": 0})
    for r in STORE.q(f"SELECT * FROM runs WHERE {where}", args):
        s = stats[r["repo"]]
        s["source"] = r["source"]
        if r["status"] == "completed":
            s["runs"] += 1
            s["flagged"] += r["n_flagged"] or 0
            s["blocked"] += r["conclusion"] == "blocked"
            s["lat"].append(r["latency"])
        if not s["last"] or (r["created_at"] or "") > s["last"]["created_at"]:
            s["last"] = r
    for f in STORE.q(f"SELECT repo, count(*) n FROM findings WHERE {where} AND flagged=1 "
                     "AND status IN ('open','confirmed') GROUP BY repo", args):
        stats[f["repo"]]["open"] = f["n"]
    meta = {r["full_name"]: r for r in STORE.q("SELECT * FROM repos WHERE removed=0")}
    visible = sess.get("repos") or set()
    if source != "imported":
        for name, r in meta.items():
            if name in visible and name not in stats:
                stats[name]["source"] = "github"
    out = []
    for name, s in stats.items():
        m = meta.get(name, {})
        out.append({"repo": name, "source": s.get("source", "github"), "runs": s["runs"], "flagged": s["flagged"],
                    "blocked": s["blocked"], "open": s["open"], "median_latency": reviews.median(s["lat"]),
                    "last": run_row(s["last"]) if s["last"] else None, "id": m.get("id"),
                    "private": m.get("private"), "enabled": m.get("enabled", 1), "language": m.get("language"),
                    "description": m.get("description"), "default_branch": m.get("default_branch")})
    out.sort(key=lambda r: (r["source"] != "github", -(r["last"] or {}).get("ts", 0), r["repo"]))
    return out


def run_row(r: dict) -> dict:
    out = {k: r.get(k) for k in (
        "id", "source", "repo", "pr_number", "pr_title", "pr_url", "author", "author_avatar", "head_sha", "base_sha",
        "head_ref", "base_ref", "trigger", "status", "conclusion", "verdict", "n_flagged", "n_candidates",
        "severity_max", "stage", "check_url", "review_url", "created_at", "started_at", "finished_at", "latency",
        "backend", "model", "error", "imported_dataset", "outcome", "expected", "advisory", "merged", "judge")}
    out["ts"] = time.mktime(time.strptime(r["created_at"][:19], "%Y-%m-%dT%H:%M:%S")) if r.get("created_at") else 0
    return out


def list_runs(sess: dict, q: dict) -> list[dict]:
    where, args = scope_sql(sess)
    where += source_clause(q.get("source", "all"))
    if q.get("repo"):
        where += " AND repo=?"
        args.append(q["repo"])
    if q.get("status"):
        where += " AND status=?"
        args.append(q["status"])
    if q.get("conclusion"):
        where += " AND conclusion=?"
        args.append(q["conclusion"])
    limit = min(int(q.get("limit") or 200), 500)
    return [run_row(r) for r in STORE.q(f"SELECT * FROM runs WHERE {where} ORDER BY created_at DESC LIMIT {limit}", args)]


def run_detail(sess: dict, run_id: str) -> dict:
    where, args = scope_sql(sess)
    run = STORE.one(f"SELECT * FROM runs WHERE id=? AND {where}", [run_id, *args])
    if not run:
        raise KeyError(run_id)
    out = {"run": run_row(run), "result": None, "events": len(STORE.events(run_id))}
    if run["source"] == "imported":
        if run["imported_dataset"] == "shoply":
            rec = json.loads((reviews.SHOPLY_RUNS / f"{run['imported_key']}.json").read_text(encoding="utf-8"))
            res = results.normalise(rec, "shoply", "lgtm")
            patch = reviews.shoply_patch(run["imported_key"])
            if patch:
                res["diff"] = {"files": results.parse_diff(patch.read_text(encoding="utf-8")), "available": True}
        else:
            rec = results.load_record(run["imported_dataset"], run["imported_mode"], run["imported_key"])
            res = results.normalise(rec, run["imported_dataset"], run["imported_mode"])
        out["result"] = res
    else:
        path = reviews.RUN_FILES / f"{run_id}.json"
        if path.is_file():
            rec = json.loads(path.read_text(encoding="utf-8"))
            owner, name = run["repo"].split("/")
            out["result"] = results.normalise(rec, "github", "lgtm", clone=reviews.CLONES / owner / name)
        elif run["base_sha"] and run["head_sha"]:
            owner, name = run["repo"].split("/")
            out["diff"] = results.build_diff(run["repo"], run["base_sha"], run["head_sha"], set(),
                                             reviews.CLONES / owner / name)
    status = {r["id"]: r["status"] for r in STORE.q("SELECT id, status FROM findings WHERE run_id=?", (run_id,))}
    if out["result"]:
        cached = {r["key"]: json.loads(r["body"]) for r in STORE.q("SELECT key, body FROM finding_briefs WHERE key LIKE ?", (f"{run_id}:%",))}
        for f in out["result"]["findings"]:
            f["triage"] = status.get(f"{run_id}:{f['id']}")
            f["key"] = f"{run_id}:{f['id']}"
            f["brief"] = cached.get(f["key"])
    out["other_runs"] = [run_row(r) for r in STORE.q(
        "SELECT * FROM runs WHERE repo=? AND pr_number IS ? AND id<>? ORDER BY created_at DESC LIMIT 10",
        (run["repo"], run["pr_number"], run_id))]
    return out


def run_briefs(detail: dict) -> dict:
    """Readable briefs for a review's reported findings, written (and cached) when missing."""
    if not detail.get("result"):
        return {}
    flagged = {f["key"]: f for f in detail["result"]["findings"] if f.get("flagged")}
    return brief.briefs(STORE, ENGINE.bedrock_key, ENGINE.bedrock_budget, flagged)


def run_log(sess: dict, run_id: str) -> str:
    where, args = scope_sql(sess)
    run = STORE.one(f"SELECT * FROM runs WHERE id=? AND {where}", [run_id, *args])
    if not run:
        raise KeyError(run_id)
    if run["source"] == "imported":
        return "This run was imported from the benchmark results; its process log was not kept.\n"
    path = reviews.RUN_FILES / f"{run_id}.log"
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    for needle in (str(reviews.CLONES), str(Path.home())):
        text = text.replace(needle, "<cache>")
    return gh.redact(text[-400_000:])


def list_findings(sess: dict, q: dict) -> list[dict]:
    where, args = scope_sql(sess)
    where += source_clause(q.get("source", "all"))
    where += " AND flagged=1" if q.get("include_filtered") != "1" else ""
    if q.get("status"):
        where += f" AND status IN ({','.join('?' * len(q['status'].split(',')))})"
        args += q["status"].split(",")
    if q.get("repo"):
        where += " AND repo=?"
        args.append(q["repo"])
    rows = STORE.q(f"SELECT * FROM findings WHERE {where} ORDER BY created_at DESC LIMIT 1000", args)
    rows.sort(key=lambda f: (f["status"] not in ("open", "confirmed"), -SEVERITY_RANK.get(f["severity"], 0),
                             f["created_at"] or ""), reverse=False)
    return rows


def accuracy() -> dict:
    sets = results.benchmark()
    shoply = []
    for path in sorted(reviews.SHOPLY_RUNS.glob("*.json")):
        if path.stem in ("run", "summary"):
            continue
        try:
            shoply.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    if shoply:
        n = {k: sum(1 for r in shoply if r.get("outcome") == k) for k in ("TP", "FP", "FN", "TN", "ERROR")}
        lat = [r["latency_seconds"] for r in shoply if r.get("latency_seconds")]
        sets.append({"id": "shoply", "label": "Shoply synthetic set", "note":
                     "52 hand-built cases (26 SQL-injection and authorization bugs, 26 safe controls) in a small Flask shop.",
                     "modes": [{"mode": "lgtm", "label": results.MODE_LABELS["lgtm"], **n, "advisories": len(shoply) // 2,
                                "on_target": n["TP"], "median_latency": reviews.median(lat)}]})
    return {"sets": sets}


GPU_MODEL = "qwen3.8:27b"
_GPU_CACHE: dict = {"at": 0.0, "value": None}
_GPU_LOCK = threading.Lock()


def _probe(addr, path: str, connect_cmd: str, check) -> dict:
    """Ask the server behind a tunnel for real: an open local port alone only means ssh is listening."""
    if not results_port(addr):
        return {"ok": False, "state": "no_tunnel", "detail": f"Tunnel not open. Start the GPU job and run {connect_cmd}."}
    try:
        with urllib.request.urlopen(f"http://{addr[0]}:{addr[1]}{path}", timeout=2.5) as resp:
            data = json.loads(resp.read() or b"{}")
    except (OSError, ValueError) as exc:
        reason = getattr(exc, "code", None)
        why = f"answered HTTP {reason}" if reason else "is not answering"
        return {"ok": False, "state": "no_server",
                "detail": f"Tunnel is open but the GPU job {why}: the job may have ended or still be loading."}
    return check(data)


def _check_qwen(data: dict) -> dict:
    names = [m.get("name") or m.get("model") for m in data.get("models", [])]
    if GPU_MODEL not in names:
        return {"ok": False, "state": "no_model", "detail": f"GPU server is up but {GPU_MODEL} is not loaded."}
    return {"ok": True, "state": "ok", "detail": f"Qwen 3.8 27B answering on the GPU job ({GPU_MODEL})."}


def _check_kev(data: dict) -> dict:
    if not (data.get("data") or data.get("models")):   # OpenAI-style "data", or the System One server's "models"
        return {"ok": False, "state": "no_model", "detail": "Kev server is up but lists no model."}
    return {"ok": True, "state": "ok", "detail": "Kev-4B judge answering on 127.0.0.1:8008 (this Mac or the GPU job)."}


def _check_claude_judge(data: dict) -> dict:
    if not data.get("ready"):
        return {"ok": False, "state": "no_key", "detail": "Claude judge needs a Bedrock key in .env."}
    return {"ok": True, "state": "ok", "detail": "Claude on Bedrock answering as the judge (a stand-in, not Kev)."}


def gpu_status() -> dict:
    with _GPU_LOCK:
        if _GPU_CACHE["value"] is None or time.time() - _GPU_CACHE["at"] > 4:
            _GPU_CACHE["value"] = {
                "reviewer": _probe(OLLAMA, "/api/tags", "model/deploy/connect.sh <job>", _check_qwen),
                "judge": _probe(KEV, "/v1/models", "model/deploy/kev-connect.sh <job>", _check_kev),
                "checked_at": now(),
            }
            _GPU_CACHE["at"] = time.time()
        return _GPU_CACHE["value"]


def health() -> dict:
    app = gh.public_app_info()
    gpu = dict(gpu_status())
    judge_kind = STORE.settings().get("judge", "kev")
    if judge_kind == "claude":
        gpu["judge"] = _probe(("127.0.0.1", claude_judge.PORT), "/v1/models", "the LGTM server", _check_claude_judge)
    return {
        "reviewer": gpu["reviewer"]["ok"], "judge": gpu["judge"]["ok"], "judge_kind": judge_kind, "bedrock": bool(ENGINE.bedrock_key),
        "gpu": gpu, "backend": STORE.settings().get("backend", "gpu"),
        "app": app, "relay": {**ENGINE.relay_state, "configured": bool(gh.load_relay())},
        "poll": ENGINE.poll_state, "queue": ENGINE.queue.qsize(), "current": ENGINE.current,
        "installations": STORE.q("SELECT * FROM installations WHERE removed=0"),
    }


def results_port(addr) -> bool:
    import socket
    try:
        with socket.create_connection(addr, timeout=0.4):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(SimpleHTTPRequestHandler):
    server_version = "LGTM/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def log_message(self, fmt, *args):
        if "/api/" in (self.path or "") or (args and str(args[1])[:1] in "45"):
            path = re.sub(r"([?&](code|state)=)[^&\s]+", r"\1…", fmt % args)
            sys.stderr.write("%s %s\n" % (self.log_date_time_string(), path))

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    # -- helpers --------------------------------------------------------------
    def send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, body: bytes, ctype: str, download: str | None = None):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str, status=HTTPStatus.OK):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookie: str | None = None):
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def session(self) -> dict | None:
        jar = SimpleCookie(self.headers.get("Cookie") or "")
        sid = jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else None
        sess = SESSIONS.get(sid or "")
        if not sess or time.time() - sess["created"] > SESSION_TTL:
            return None
        if time.time() - sess.get("scoped_at", 0) > 60:
            try:
                load_user_scope(sess)
            except Exception:  # noqa: BLE001 - keep the last known scope
                pass
        return sess

    def body_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}") if length else {}

    # -- GET --------------------------------------------------------------------
    def do_GET(self):  # noqa: N802 - http.server API
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        path = url.path
        try:
            if path == "/auth/login":
                return self.login()
            if path == "/auth/callback":
                return self.oauth_callback(q)
            if path == "/github/manifest/callback":
                return self.manifest_callback(q)
            if path == "/github/installed":
                try:
                    ENGINE.sync_installations()
                except Exception as exc:  # noqa: BLE001
                    sys.stderr.write(gh.redact(f"sync after install failed: {exc}\n"))
                for sess in SESSIONS.values():
                    sess["scoped_at"] = 0
                return self.redirect("/#/onboarding")
            if path.startswith("/api/"):
                return self.api_get(path, q)
        except KeyError:
            return self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except gh.GitHubError as exc:
            return self.send_json({"error": str(exc)}, HTTPStatus.BAD_GATEWAY)
        return super().do_GET()

    def api_get(self, path: str, q: dict):
        if path == "/api/me":
            sess = self.session()
            return self.send_json({
                "app": gh.public_app_info(), "relay": bool(gh.load_relay()),
                "user": {k: sess[k] for k in ("login", "name", "avatar")} if sess else None,
                "installations": STORE.q(
                    f"SELECT * FROM installations WHERE removed=0 AND id IN ({','.join('?' * len(sess['installations']))})",
                    sess["installations"]) if sess and sess.get("installations") else [],
                "install_url": f"https://github.com/apps/{gh.load_app()['slug']}/installations/new" if gh.load_app() else None,
            })
        if path == "/api/health":
            return self.send_json(health())
        if path == "/api/github/manifest":  # bootstrap: before the app exists nobody can sign in
            return self.send_json(self.manifest_form(q.get("name") or "LGTM Security Review"))
        sess = self.session()
        if sess is None:
            return self.send_json({"error": "sign in with GitHub first"}, HTTPStatus.UNAUTHORIZED)
        if path == "/api/overview":
            return self.send_json(overview(sess, q.get("source", "all")))
        if path == "/api/repos":
            return self.send_json(repo_rows(sess, q.get("source", "all")))
        if path == "/api/runs":
            return self.send_json(list_runs(sess, q))
        m = re.fullmatch(r"/api/runs/([\w-]+)(/events|/log|/report\.pdf|/report\.html|/briefs)?", path)
        if m and m.group(2) == "/briefs":
            return self.send_json(run_briefs(run_detail(sess, m.group(1))))
        if m and m.group(2) in ("/report.pdf", "/report.html"):
            detail = run_detail(sess, m.group(1))
            for k, b in run_briefs(detail).items():
                for f in detail["result"]["findings"]:
                    if f["key"] == k:
                        f["brief"] = b
            page = report.report_html(detail)
            if m.group(2) == "/report.html":
                return self.send_bytes(page.encode("utf-8"), "text/html; charset=utf-8")
            try:
                pdf = report.report_pdf(page)
            except Exception as exc:  # noqa: BLE001 - fall back to the printable page
                return self.send_json({"error": str(exc)[:300]}, HTTPStatus.BAD_GATEWAY)
            return self.send_bytes(pdf, "application/pdf", report.filename(detail["run"]))
        if m:
            if m.group(2) == "/events":
                run_detail(sess, m.group(1))  # access check
                return self.stream(m.group(1), int(q.get("from", self.headers.get("Last-Event-ID", -1) or -1)) + 1)
            if m.group(2) == "/log":
                return self.send_text(run_log(sess, m.group(1)))
            return self.send_json(run_detail(sess, m.group(1)))
        if path == "/api/findings":
            return self.send_json(list_findings(sess, q))
        if path == "/api/accuracy":
            return self.send_json(accuracy())
        if path == "/api/settings":
            return self.send_json(STORE.settings())
        if path == "/api/deliveries":
            return self.send_json(STORE.q("SELECT * FROM deliveries ORDER BY received_at DESC LIMIT 50"))
        if path.startswith("/api/ws/"):
            return self.ws_get(sess, path, q)
        raise KeyError(path)

    # -- POST -------------------------------------------------------------------
    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/github/webhook":
                return self.webhook()
            if path == "/auth/logout":
                jar = SimpleCookie(self.headers.get("Cookie") or "")
                if SESSION_COOKIE in jar:
                    SESSIONS.pop(jar[SESSION_COOKIE].value, None)
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
                return self.end_headers()
            if self.headers.get("Origin") not in (None, BASE_URL, BASE_URL.replace("127.0.0.1", "localhost")):
                return self.send_json({"error": "cross-site request refused"}, HTTPStatus.FORBIDDEN)
            sess = self.session()
            if sess is None:
                return self.send_json({"error": "sign in with GitHub first"}, HTTPStatus.UNAUTHORIZED)
            body = self.body_json()
            m = re.fullmatch(r"/api/runs/([\w-]+)/(cancel|rerun)", path)
            if m:
                run_detail(sess, m.group(1))
                if m.group(2) == "cancel":
                    return self.send_json({"cancelled": ENGINE.cancel(m.group(1))})
                return self.send_json({"run": ENGINE.rerun(m.group(1))})
            m = re.fullmatch(r"/api/findings/(.+)", path)
            if m:
                where, args = scope_sql(sess)
                row = STORE.one(f"SELECT * FROM findings WHERE id=? AND {where}", [m.group(1), *args])
                if not row or body.get("status") not in TRIAGE_STATES:
                    return self.send_json({"error": "bad request"}, HTTPStatus.BAD_REQUEST)
                STORE.update("findings", row["id"], status=body["status"], note=str(body.get("note") or "")[:500],
                             updated_at=now())
                return self.send_json(STORE.one("SELECT * FROM findings WHERE id=?", (row["id"],)))
            m = re.fullmatch(r"/api/repos/(\d+)", path)
            if m:
                repo = STORE.one("SELECT * FROM repos WHERE id=?", (int(m.group(1)),))
                if not repo or repo["full_name"] not in sess.get("repos", set()):
                    return self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                STORE.update("repos", repo["id"], enabled=1 if body.get("enabled") else 0)
                return self.send_json({"ok": True})
            if path == "/api/settings":
                if "backend" in body and body["backend"] not in ("gpu", "bedrock"):
                    return self.send_json({"error": "backend must be gpu or bedrock"}, HTTPStatus.BAD_REQUEST)
                if "judge" in body and body["judge"] not in ("kev", "claude"):
                    return self.send_json({"error": "judge must be kev or claude"}, HTTPStatus.BAD_REQUEST)
                for k, v in body.items():
                    STORE.set_setting(k, v)
                return self.send_json(STORE.settings())
            if path == "/api/sync":
                ENGINE.sync_installations()
                ENGINE.poll_once()
                sess["scoped_at"] = 0
                return self.send_json({"ok": True})
            if path.startswith("/api/ws/"):
                return self.ws_post(sess, path, body)
        except KeyError:
            return self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except gh.GitHubError as exc:
            return self.send_json({"error": str(exc)}, HTTPStatus.BAD_GATEWAY)
        return self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    # -- workspace (demo IDE) ----------------------------------------------------
    @staticmethod
    def ws_repo(sess: dict, repo: str) -> str:
        if repo not in sess.get("repos", set()):
            raise workspace.WorkspaceError("Connect this repository to LGTM first.", 404)
        return repo

    def ws_get(self, sess: dict, path: str, q: dict):
        try:
            if path == "/api/ws/presets":
                return self.send_json([p for p in WS.presets() if p["repo"] in sess.get("repos", set())])
            if path == "/api/ws/apps":
                return self.send_json(sorted(r for r in liveapp.APPS if r in sess.get("repos", set())))
            repo = self.ws_repo(sess, q.get("repo", ""))
            if path == "/api/ws/state":
                return self.send_json(WS.state(repo))
            if path == "/api/ws/tree":
                return self.send_json(WS.tree(repo))
            if path == "/api/ws/file":
                return self.send_json(WS.read(repo, q.get("path", "")))
            if path == "/api/ws/search":
                return self.send_json(WS.search(repo, q.get("q", "")))
            if path == "/api/ws/diff":
                return self.send_json(WS.diff(repo))
        except workspace.WorkspaceError as exc:
            return self.send_json({"error": str(exc)}, exc.status)
        raise KeyError(path)

    def ws_post(self, sess: dict, path: str, body: dict):
        try:
            repo = self.ws_repo(sess, body.get("repo", ""))
            if path == "/api/ws/open":
                return self.send_json(WS.open(repo, body.get("preset") or None))
            if path == "/api/ws/file":
                return self.send_json(WS.write(repo, body.get("path", ""), str(body.get("content") or ""), bool(body.get("deleted"))))
            if path == "/api/ws/push":
                gen = WS.push_stream(repo, body.get("branch", ""), body.get("message", ""), body.get("title", ""),
                                     sess["login"], body.get("how", ""))
                return self.ndjson(gen)
            if path == "/api/ws/generate":
                return self.ws_generate(repo, body)
            if path == "/api/ws/app/start":
                return self.send_json(APPS.start(repo))
            if path == "/api/ws/app/call":
                return self.send_json(APPS.call(repo, str(body.get("method") or "GET"), str(body.get("path") or "/"),
                                                body.get("token"), body.get("body")))
        except (workspace.WorkspaceError, liveapp.LiveAppError) as exc:
            return self.send_json({"error": str(exc)}, exc.status)
        return self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def ndjson(self, gen):
        """Stream a generator's events as newline-delimited JSON; errors before the first event are a normal error reply."""
        first = next(gen)   # WorkspaceError here is answered by the caller as JSON
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()
        try:
            self.wfile.write((json.dumps(first) + "\n").encode()); self.wfile.flush()
            for event in gen:
                self.wfile.write((json.dumps(event) + "\n").encode()); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001 - the terminal shows the failure
            self.wfile.write((json.dumps({"type": "error", "msg": gh.redact(str(exc))[:400]}) + "\n").encode())

    def ws_generate(self, repo: str, body: dict):
        """Stream Claude's rewrite of one file as newline-delimited JSON events."""
        gen = WS.generate(repo, body.get("path", ""), body.get("prompt", ""), ENGINE.bedrock_key, ENGINE.bedrock_budget)
        try:
            first = next(gen)
        except workspace.WorkspaceError:
            raise
        except Exception as exc:  # noqa: BLE001 - the model call failed before streaming
            return self.send_json({"error": gh.redact(f"The assistant could not start: {exc}")[:400]}, HTTPStatus.BAD_GATEWAY)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()
        try:
            for event in [first]:
                self.wfile.write((json.dumps(event) + "\n").encode())
            for event in gen:
                self.wfile.write((json.dumps(event) + "\n").encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001 - report mid-stream failures to the editor
            self.wfile.write((json.dumps({"type": "error", "msg": gh.redact(str(exc))[:400]}) + "\n").encode())

    # -- GitHub App -----------------------------------------------------------
    def manifest_form(self, name: str) -> dict:
        if gh.load_app():
            return {"exists": True, "app": gh.public_app_info()}
        relay = gh.load_relay()
        if not relay:
            relay = gh.new_relay_channel()
            gh.save_relay(relay)
        state = secrets.token_urlsafe(24)
        MANIFEST_STATES[state] = time.time()
        return {"exists": False, "post_url": f"https://github.com/settings/apps/new?state={state}",
                "manifest": json.dumps(gh.manifest(name[:34], BASE_URL, relay))}

    def manifest_callback(self, q: dict):
        state = q.get("state", "")
        if state not in MANIFEST_STATES or time.time() - MANIFEST_STATES.pop(state) > 3600:
            return self.send_text("This link has expired. Start again from the LGTM onboarding page.", HTTPStatus.BAD_REQUEST)
        if gh.load_app():
            return self.redirect("/#/onboarding")
        gh.convert_manifest(q.get("code", ""))
        return self.redirect("/#/onboarding")

    def login(self):
        if not gh.load_app():
            return self.redirect("/#/onboarding")
        state = secrets.token_urlsafe(24)
        OAUTH_STATES[state] = time.time()
        return self.redirect(gh.authorize_url(f"{BASE_URL}/auth/callback", state))

    def oauth_callback(self, q: dict):
        state = q.get("state", "")
        if state not in OAUTH_STATES or time.time() - OAUTH_STATES.pop(state) > 900:
            return self.redirect("/#/signin?error=expired")
        if "code" not in q:
            return self.redirect("/#/signin?error=denied")
        token = gh.exchange_user_code(q["code"], f"{BASE_URL}/auth/callback")
        user = gh.as_user(token, "GET", "/user")
        sid = secrets.token_urlsafe(32)
        sess = {"token": token, "login": user["login"], "name": user.get("name") or user["login"],
                "avatar": user.get("avatar_url"), "created": time.time()}
        load_user_scope(sess)
        SESSIONS[sid] = sess
        cookie = f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
        return self.redirect("/#/" if sess["repos"] else "/#/onboarding", cookie)

    def webhook(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        event = self.headers.get("X-GitHub-Event", "")
        delivery = self.headers.get("X-GitHub-Delivery") or f"local-{secrets.token_hex(6)}"
        via = "relay" if self.headers.get("X-LGTM-Via") == "relay" else "direct"
        sig = self.headers.get("X-Hub-Signature-256")
        verified = gh.verify_signature(raw, sig)
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {}
        if not verified and payload:
            # The relay re-encodes the body; GitHub's own encoding escapes non-ASCII.
            verified = gh.verify_signature(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(), sig)
        if STORE.one("SELECT id FROM deliveries WHERE id=?", (delivery,)):
            return self.send_json({"ok": True, "duplicate": True})
        row = {"id": delivery, "event": event, "action": payload.get("action", ""),
               "repo": (payload.get("repository") or {}).get("full_name", ""), "received_at": now(),
               "via": via, "verified": 1 if verified else 0, "outcome": ""}
        if not verified:
            row["outcome"] = "rejected: bad signature"
            STORE.upsert("deliveries", row)
            return self.send_json({"error": "bad signature"}, HTTPStatus.UNAUTHORIZED)
        try:
            row["outcome"] = ENGINE.handle_event(event, payload, via)
        except Exception as exc:  # noqa: BLE001
            row["outcome"] = gh.redact(f"error: {exc}")[:300]
        STORE.upsert("deliveries", row)
        return self.send_json({"ok": True, "outcome": row["outcome"]})

    # -- live events --------------------------------------------------------------
    def stream(self, run_id: str, start: int):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        i = max(0, start)
        try:
            while True:
                live = ENGINE.live.get(run_id)
                run = STORE.run(run_id)
                if live is None:
                    batch = STORE.events(run_id, i)
                    finished = run["status"] not in ("queued", "running")
                else:
                    with live.cond:
                        while i >= len(live.events) and not live.finished:
                            if not live.cond.wait(timeout=15):
                                break
                        batch = live.events[i:]
                        finished = live.finished and i + len(batch) >= len(live.events)
                if not batch:
                    self.wfile.write(b": keep-alive\n\n")
                for event in batch:
                    self.wfile.write(f"id: {event['seq']}\ndata: {json.dumps(event, default=str)}\n\n".encode())
                    i += 1
                self.wfile.flush()
                if finished:
                    self.wfile.write(b"event: end\ndata: {}\n\n")
                    self.wfile.flush()
                    return
                if live is None:
                    time.sleep(1.5)  # queued: not started yet
        except (BrokenPipeError, ConnectionResetError):
            return


def main() -> int:
    global STORE, ENGINE, BASE_URL
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--bedrock-allowance", type=float, default=10.0,
                        help="USD this server may add to the shared Bedrock ledger (default 10)")
    args = parser.parse_args()
    BASE_URL = f"http://127.0.0.1:{args.port}"
    STORE = Store()
    added = reviews.import_history(STORE)
    main_checkout = Path(subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True, text=True).stdout.strip() or REPO_ROOT / ".git").parent
    key = read_bedrock_key([REPO_ROOT / ".env", main_checkout / ".env"])
    budget = ledger_total() + args.bedrock_allowance
    ENGINE = reviews.Engine(STORE, sys.executable, BASE_URL, key, budget)
    ENGINE.start(args.port)
    claude_judge.serve(key, budget)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    app = gh.public_app_info()
    print(f"LGTM on {BASE_URL}/  (GitHub App: {app['slug'] if app else 'not created yet'}; "
          f"{added} benchmark runs imported)")
    print(f"  reviewer tunnel {'up' if results_port(OLLAMA) else 'down'}, Kev judge {'up' if results_port(KEV) else 'down'}, "
          f"Bedrock key {'found' if key else 'not found'} (ledger cap ${budget:.2f})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
