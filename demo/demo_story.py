"""The guided live demo: a local model writes a feature, LGTM reviews the pull request, its fix is committed, and the
shop is attacked as main, as the pull request and as the fix.

One story on one repository (shoply-demo) and one task (an order detail endpoint). Nothing in it is scripted: the
model writes the code live, the probes send real requests to the shop running that code, and the review is LGTM's
real review on GitHub. When the model happens to write safe or broken code, the page offers a recorded earlier run
(saved token by token when it happened) instead, labelled with its date.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import liveapp
import suggest
import workspace

REPO = "cyberjj999/shoply-demo"
PRESET = "shoply-order-details"
PROBE_PORT = 8792                      # the probe's own shop, apart from App mode's (8791)
HERE = Path(__file__).resolve().parent
RECORDED = HERE / ".data" / "demo" / "recorded.json"
ALICE, BOB = 1, 2                      # user ids in the launcher's seed data; orders 1-2 are alice's, 3-4 bob's


class StoryError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


class Story:
    def __init__(self, ws: workspace.Workspace, store):
        self.ws, self.store = ws, store
        self.probe_lock = threading.Lock()
        self._pr_cache: dict[int, tuple[float, dict]] = {}

    # ------------------------------------------------------------------ what the page needs to start
    def info(self) -> dict:
        p = self.ws.preset(PRESET)
        rec = self.recorded()
        return {"repo": REPO, "task": {"id": p["id"], "ask": p["ask"], "title": p.get("title"), "branch": p["branch"],
                                       "message": p["message"]},
                "model": workspace.WRITER_MODEL, "writer": self.writer_available(),
                "recorded": {k: rec[k] for k in ("at", "model", "seconds")} if rec else None,
                "backup_pr": self.backup_pr(), "state": self.ws.state(REPO)}

    @staticmethod
    def writer_available() -> bool:
        try:
            with urllib.request.urlopen(workspace.WRITER_URL.rstrip("/") + "/api/tags", timeout=2) as r:
                names = {m["name"] for m in json.loads(r.read()).get("models", [])}
        except (OSError, ValueError):
            return False
        m = workspace.WRITER_MODEL
        return m in names or f"{m}:latest" in names or m.removesuffix(":latest") in names

    def backup_pr(self) -> int | None:
        """A finished run of the story: a pull request LGTM blocked and then passed after its fix."""
        if os.environ.get("DEMO_BACKUP_PR"):
            return int(os.environ["DEMO_BACKUP_PR"])
        rows = self.store.q("SELECT pr_number, conclusion FROM runs WHERE repo=? AND source='github' AND status='completed' "
                            "AND head_ref LIKE 'demo/order-details%' ORDER BY created_at", (REPO,))
        seen: dict[int, list[str]] = {}
        for r in rows:
            seen.setdefault(r["pr_number"], []).append(r["conclusion"])
        done = [n for n, c in seen.items() if c and c[0] in ("blocked", "findings") and c[-1] == "passed"]
        return max(done) if done else None

    # ------------------------------------------------------------------ step 2: a clean copy for the model
    def start(self) -> dict:
        r = self.ws.open(REPO, PRESET)
        step = r["script"]["steps"][0]
        return {"path": step["path"], "before": step["before"], "state": r["state"]}

    # ------------------------------------------------------------------ recorded runs (the fallback)
    def record(self, run: dict) -> dict:
        RECORDED.parent.mkdir(parents=True, exist_ok=True)
        runs = self._recorded_all()
        entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": str(run.get("model") or workspace.WRITER_MODEL),
                 "path": str(run.get("path") or ""), "times": [[float(t), str(x)] for t, x in run.get("times", [])][:20000],
                 "outcome": str(run.get("outcome") or "")}
        entry["seconds"] = round(entry["times"][-1][0], 1) if entry["times"] else 0
        runs.append(entry)
        RECORDED.write_text(json.dumps(runs[-20:], indent=1), encoding="utf-8")
        return {"ok": True, "at": entry["at"]}

    def _recorded_all(self) -> list[dict]:
        try:
            return json.loads(RECORDED.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def recorded(self) -> dict | None:
        runs = [r for r in self._recorded_all() if r.get("outcome") == "vulnerable" and r.get("times")]
        return runs[-1] if runs else None

    # ------------------------------------------------------------------ probes: real requests to the shop
    def probe(self, ref: str, pr: int | None = None) -> dict:
        """Run the shop as ``ref`` ("draft": the workspace files; "main"; or a commit sha) and attack it."""
        d = self.ws.dir(REPO)
        with self.probe_lock, tempfile.TemporaryDirectory(prefix="lgtm-probe-") as tmp:
            src = Path(tmp) / "src"
            if ref == "draft":
                src = d
            else:
                if ref == "main":
                    sha = self.ws.git(d, "rev-parse", f"origin/{self.ws.default_branch(d)}").strip()
                else:
                    sha = ref
                    if pr:
                        self.ws.git(d, "fetch", "--quiet", "origin", f"+refs/pull/{pr}/head:refs/remotes/pr/{pr}", auth=True, check=False)
                    self.ws.have(d, sha)
                src.mkdir()
                arc = subprocess.run(["git", "-C", str(d), "archive", sha], capture_output=True, check=True).stdout
                subprocess.run(["tar", "-x", "-C", str(src)], input=arc, check=True)
            return self._attack(src, Path(tmp) / "data", ref)

    def _attack(self, src: Path, data: Path, ref: str) -> dict:
        liveapp.LiveApps._free_port({"launcher": HERE / "apps" / "shoply_launcher.py", "port": PROBE_PORT})
        log = data.parent / "shop.log"
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
        env.pop("AWS_BEARER_TOKEN_BEDROCK", None)
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.Popen([str(liveapp.VENV_PY), str(HERE / "apps" / "shoply_launcher.py"), str(src), str(data), str(PROBE_PORT)],
                                    cwd=data.parent, stdout=fh, stderr=subprocess.STDOUT, env=env)
        try:
            if not _wait(PROBE_PORT) or proc.poll() is not None:
                tail = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-6:]
                return {"ref": ref, "outcome": "broken", "why": "The shop does not start with this code.", "log": tail, "probes": []}
            routes = _req("GET", "/__lgtm/routes")[1] or []
            has = any(r.startswith("GET /orders/<") for r in routes)
            alice = (_req("POST", "/login", body={"username": "alice", "password": "demo"})[1] or {}).get("token")
            bob = (_req("POST", "/login", body={"username": "bob", "password": "demo"})[1] or {}).get("token")
            probes = [
                {"who": "alice", "what": "Alice opens her own order #1", "path": "/orders/1", "expect": "allow", "token": alice},
                {"who": "alice", "what": "Alice opens Bob's order #3", "path": "/orders/3", "expect": "deny", "token": alice},
                {"who": "bob", "what": "Bob opens his own order #3", "path": "/orders/3", "expect": "allow", "token": bob},
            ]
            for p in probes:
                status, body = _req("GET", p.pop("path_override", p["path"]), token=p.pop("token"))
                p["status"], p["body"] = status, _trim(body)
                if status >= 500:
                    p["crash"] = _crash(log)
            mine, theirs = probes[0], probes[1]
            if not has:
                outcome, why = "missing", "There is no order detail endpoint in this version."
            elif mine["status"] != 200:
                outcome, why = "broken", "The new endpoint does not work: Alice cannot open her own order."
            elif theirs["status"] == 200 and isinstance(theirs["body"], dict) and theirs["body"].get("user_id") == BOB:
                outcome, why = "vulnerable", "Alice can read Bob's order, with his home address."
            else:
                outcome, why = "safe", "Alice is refused Bob's order and still sees her own."
            return {"ref": ref, "outcome": outcome, "why": why, "probes": probes}
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    # ------------------------------------------------------------------ the pull request and LGTM's rounds
    def pr_meta(self, pr: int) -> dict:
        hit = self._pr_cache.get(pr)
        if hit and time.time() - hit[0] < 15:
            return hit[1]
        try:
            raw = self.ws.gh("pr", "view", str(pr), "--repo", REPO, "--json", "number,url,state,headRefName,title,baseRefOid")
            meta = json.loads(raw)
        except Exception:  # noqa: BLE001 - GitHub unreachable: the stored runs still tell the story
            meta = {"number": pr, "url": f"https://github.com/{REPO}/pull/{pr}", "state": "UNKNOWN"}
        self._pr_cache[pr] = (time.time(), meta)
        return meta

    def rounds(self, pr: int) -> dict:
        runs = self.store.q("SELECT * FROM runs WHERE repo=? AND pr_number=? AND source='github' ORDER BY created_at", (REPO, pr))
        out = []
        for r in runs:
            fs = self.store.q("SELECT * FROM findings WHERE run_id=? AND flagged=1", (r["id"],)) if r["status"] == "completed" else []
            briefs = {b["key"]: json.loads(b["body"]) for b in self.store.q(
                f"SELECT key, body FROM finding_briefs WHERE key IN ({','.join('?' * len(fs)) or 'NULL'})", [f["id"] for f in fs])} if fs else {}
            sugg = self.store.q("SELECT path, start_line, end_line, replacement, finding_key FROM suggestions WHERE run_id=?", (r["id"],))
            out.append({"id": r["id"], "sha": r.get("head_sha"), "base_sha": r.get("base_sha"), "status": r["status"],
                        "stage": r.get("stage"), "conclusion": r.get("conclusion"), "n_flagged": r.get("n_flagged"),
                        "latency": r.get("latency"), "judge": r.get("judge"), "trigger": r.get("trigger"),
                        "review_url": r.get("review_url"), "check_url": r.get("check_url"), "created_at": r.get("created_at"),
                        "findings": [{"key": f["id"], "cwe": f["cwe"], "severity": f["severity"], "file": f["file"], "line": f["line"],
                                      "explanation": f["explanation"], "brief": briefs.get(f["id"])} for f in fs],
                        "suggestions": sugg})
        return {"pr": self.pr_meta(pr), "rounds": out}

    def view(self, pr: int, sha: str, path: str, base: str | None) -> dict:
        """A file at a commit of the pull request, with the lines the pull request added."""
        d = self.ws.dir(REPO)
        if pr:
            self.ws.git(d, "fetch", "--quiet", "origin", f"+refs/pull/{pr}/head:refs/remotes/pr/{pr}", auth=True, check=False)
        if sha == "main":
            sha = f"origin/{self.ws.default_branch(d)}"
        else:
            self.ws.have(d, sha)
        text = self.ws.show(d, sha, path)
        if text is None:
            raise StoryError(f"{path} is not in commit {sha[:7]}", 404)
        added = sorted(suggest.added_lines(self.ws.git(d, "diff", "-U0", base or f"{sha}^", sha, "--", path, check=False)))
        return {"path": path, "sha": sha, "content": text, "added": added}

    # ------------------------------------------------------------------ step 4: commit LGTM's fix
    def checkout(self, pr: int, data: dict | None = None) -> str:
        """Put the workspace on the pull request's latest commit (after a restart, or for a working run opened
        later), so a fix is committed on top of it and pushed to the same branch. Returns the branch."""
        data = data or self.rounds(pr)
        branch = data["pr"].get("headRefName")
        if not branch or not data["rounds"]:
            raise StoryError("This pull request is not known here yet.", 409)
        head = data["rounds"][-1]["sha"]
        d = self.ws.dir(REPO)
        meta = self.ws.meta.setdefault(REPO, {})
        if self.ws.git(d, "rev-parse", "HEAD").strip() != head or meta.get("pushed") != branch:
            self.ws.git(d, "fetch", "--quiet", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}", auth=True)
            self.ws.git(d, "checkout", "--quiet", "--force", "-B", branch, head)
            meta.update(pushed=branch, pr={"number": pr, "url": data["pr"].get("url")}, label=f"branch {branch}", preset=PRESET)
            self.ws.save_meta()
        return branch

    def fix_stream(self, pr: int, login: str):
        data = self.rounds(pr)
        flagged = [r for r in data["rounds"] if r["status"] == "completed" and r["n_flagged"]]
        if not flagged:
            raise StoryError("LGTM has not reported anything on this pull request yet.", 409)
        run = flagged[-1]
        if not run["suggestions"]:
            raise StoryError("LGTM did not offer a committable fix on this review.", 409)
        branch = self.checkout(pr, data)
        by_path: dict[str, list[dict]] = {}
        for s in run["suggestions"]:
            by_path.setdefault(s["path"], []).append(s)
        for path, items in by_path.items():
            lines = (self.ws.read(REPO, path).get("content") or "").split("\n")
            for s in sorted(items, key=lambda x: -x["start_line"]):
                lines = suggest.apply_span(lines, s["start_line"], s["end_line"], s["replacement"])
            self.ws.write(REPO, path, "\n".join(lines))
        yield from self.ws.push_stream(REPO, branch, "Apply LGTM's suggested fix", "", login, "fix", PRESET)

    # ------------------------------------------------------------------ start over
    def close(self, pr: int | None) -> dict:
        closed = False
        if pr and pr != self.backup_pr():
            meta = self.pr_meta(pr)
            if meta.get("state") == "OPEN":
                self.ws.gh("pr", "close", str(pr), "--repo", REPO, "--delete-branch",
                           "--comment", "Demo run finished: closed without merging.")
                closed = True
            self._pr_cache.pop(pr, None)
        self.ws.meta.pop(REPO, None)
        self.ws.save_meta()
        self.ws.open(REPO)
        return {"closed": closed}


def _wait(port: int, timeout: float = 15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _req(method: str, path: str, token: str | None = None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{PROBE_PORT}{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except OSError:
        return 0, None
    try:
        return status, json.loads(raw or b"null")
    except ValueError:
        return status, raw.decode("utf-8", "replace")[:300]


def _trim(body):
    if isinstance(body, dict):
        return {k: v for k, v in body.items() if k != "password_hash"}
    return body if not isinstance(body, str) else body[:300]


def _crash(log: Path) -> str:
    import re
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines() if log.is_file() else []
    return next((ln.strip() for ln in reversed(lines) if re.match(r"^[\w.]+(Error|Exception)\b", ln.strip())), "")[:300]
