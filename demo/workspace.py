"""The demo workspace: a working clone per connected repository that the dashboard can browse, edit and push from.

Pushes and pull requests go out under the GitHub account the ``gh`` CLI is signed in as on this machine
(the developer), never as the LGTM app: the app only reads code and writes checks and reviews.

Scripted tasks (workspace_presets.json) replay a real commit: the editor starts at ``base`` and the
changes of ``source`` are typed in. A task with ``follows`` continues on the branch the earlier task pushed.
The free-text assistant asks Claude on Bedrock to rewrite one file, streamed, with spend on the shared ledger.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE / ".data" / "workspace"
PRESETS_FILE = HERE / "workspace_presets.json"
META_FILE = ROOT / "meta.json"   # what each workspace was opened at and pushed to, kept across server restarts
LEDGER = Path.home() / ".lgtm" / "bedrock-spend.jsonl"
MODEL = "global.anthropic.claude-sonnet-4-6"
# "Write it live": a small local coding model writes the task on this machine's GPU, with nothing scripted.
WRITER_URL = os.environ.get("LGTM_WRITER_URL", "http://127.0.0.1:11434")
# llama3.2 (3B) writes a file in about 5 seconds; like a hurried junior, it often skips the ownership check.
WRITER_MODEL = os.environ.get("LGTM_WRITER_MODEL", "llama3.2:latest")
PRICE_IN, PRICE_OUT, PRICE_SAFETY = 3.00, 15.00, 1.10   # USD per million tokens, as in lgtm.agents.bedrock_llm
MAX_FILE = 400_000
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_LEDGER_LOCK = threading.Lock()


class WorkspaceError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def gh_bin() -> str | None:
    found = shutil.which("gh")
    if found:
        return found
    return next((p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if Path(p).exists()), None)


def ledger_total() -> float:
    total = 0.0
    if LEDGER.is_file():
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            try:
                total += float(json.loads(line).get("usd") or 0)
            except (ValueError, json.JSONDecodeError, AttributeError):
                continue
    return total


class Workspace:
    def __init__(self) -> None:
        self.locks: dict[str, threading.Lock] = {}
        self._login: str | None = None
        ROOT.mkdir(parents=True, exist_ok=True)
        try:
            self.meta: dict[str, dict] = json.loads(META_FILE.read_text(encoding="utf-8"))   # repo -> base, label, preset, pushed, pr
        except (OSError, ValueError):
            self.meta = {}

    def save_meta(self) -> None:
        META_FILE.write_text(json.dumps(self.meta, indent=1), encoding="utf-8")

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def presets(repo: str | None = None) -> list[dict]:
        items = json.loads(PRESETS_FILE.read_text(encoding="utf-8")) if PRESETS_FILE.is_file() else []
        return [p for p in items if not repo or p["repo"] == repo]

    def preset(self, pid: str) -> dict:
        for p in self.presets():
            if p["id"] == pid:
                return p
        raise WorkspaceError("Unknown task", 404)

    def _cred(self) -> list[str]:
        gh = gh_bin()
        if not gh:
            raise WorkspaceError("The GitHub CLI (gh) is not installed, so the workspace cannot reach GitHub.", 500)
        return ["-c", "credential.helper=", "-c", f"credential.helper=!{gh} auth git-credential"]

    def git(self, d: Path, *args: str, auth: bool = False, check: bool = True, timeout: int = 300) -> str:
        cmd = ["git", *(self._cred() if auth else []), "-C", str(d), *args]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if check and p.returncode != 0:
            raise WorkspaceError(f"git {args[0]} failed: {(p.stderr or p.stdout).strip()[-400:]}", 502)
        return p.stdout

    def gh(self, *args: str, cwd: Path | None = None) -> str:
        gh = gh_bin()
        if not gh:
            raise WorkspaceError("The GitHub CLI (gh) is not installed.", 500)
        p = subprocess.run([gh, *args], capture_output=True, text=True, timeout=90, cwd=cwd,
                           env={**os.environ, "GH_PROMPT_DISABLED": "1"})
        if p.returncode != 0:
            raise WorkspaceError(f"gh {args[0]} failed: {(p.stderr or p.stdout).strip()[-400:]}", 502)
        return p.stdout

    def gh_login(self) -> str:
        if not self._login:
            self._login = self.gh("api", "user", "--jq", ".login").strip()
        return self._login

    def dir(self, repo: str) -> Path:
        if not REPO_RE.match(repo or ""):
            raise WorkspaceError("Bad repository name")
        owner, name = repo.split("/")
        return ROOT / owner / name

    def lock(self, repo: str) -> threading.Lock:
        return self.locks.setdefault(repo, threading.Lock())

    def path_in(self, d: Path, rel: str) -> Path:
        p = (d / (rel or "")).resolve()
        if d.resolve() not in p.parents or ".git" in p.relative_to(d.resolve()).parts:
            raise WorkspaceError("That path is outside the repository", 403)
        return p

    def ensure_clone(self, repo: str) -> Path:
        d = self.dir(repo)
        if not (d / ".git").is_dir():
            d.parent.mkdir(parents=True, exist_ok=True)
            p = subprocess.run(["git", *self._cred(), "clone", "--quiet", f"https://github.com/{repo}.git", str(d)],
                               capture_output=True, text=True, timeout=900, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
            if p.returncode != 0:
                shutil.rmtree(d, ignore_errors=True)
                raise WorkspaceError(f"Could not clone {repo}: {p.stderr.strip()[-300:]}", 502)
        return d

    def default_branch(self, d: Path) -> str:
        ref = self.git(d, "symbolic-ref", "--short", "refs/remotes/origin/HEAD", check=False).strip()
        return ref.split("/", 1)[1] if "/" in ref else "main"

    def have(self, d: Path, sha: str) -> None:
        if subprocess.run(["git", "-C", str(d), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True).returncode == 0:
            return
        self.git(d, "fetch", "--quiet", "origin", sha, auth=True)

    def show(self, d: Path, ref: str, path: str) -> str | None:
        p = subprocess.run(["git", "-C", str(d), "show", f"{ref}:{path}"], capture_output=True)
        if p.returncode != 0:
            return None
        try:
            return p.stdout.decode("utf-8")
        except UnicodeDecodeError:
            return None

    # ------------------------------------------------------------------ state
    def state(self, repo: str) -> dict:
        d = self.dir(repo)
        if not (d / ".git").is_dir():
            return {"repo": repo, "opened": False}
        meta = self.meta.get(repo, {})
        branch = self.git(d, "symbolic-ref", "--short", "-q", "HEAD", check=False).strip() or None
        head = self.git(d, "rev-parse", "HEAD").strip()
        changed = []
        for line in self.git(d, "status", "--porcelain=v1", "-uall").splitlines():
            if len(line) > 3:
                code = line[:2].strip() or "M"
                changed.append({"path": line[3:].split(" -> ")[-1].strip('"'), "status": "A" if code == "??" else code[0]})
        return {"repo": repo, "opened": True, "default_branch": self.default_branch(d), "branch": branch,
                "head": head[:7], "base_label": meta.get("label") or (f"branch {branch}" if branch else f"commit {head[:7]}"),
                "preset": meta.get("preset"), "pushed": meta.get("pushed"), "pr": meta.get("pr"),
                "changed": changed, "login": self.gh_login() if gh_bin() else None}

    # ------------------------------------------------------------------ open / reset
    def open(self, repo: str, preset_id: str | None = None) -> dict:
        with self.lock(repo):
            d = self.ensure_clone(repo)
            self.git(d, "fetch", "--quiet", "--prune", "origin", auth=True)
            preset = self.preset(preset_id) if preset_id else None
            if preset and preset["repo"] != repo:
                raise WorkspaceError("That task belongs to another repository")
            if preset and preset.get("follows"):
                meta = self.meta.get(repo, {})
                if meta.get("preset") != preset["follows"] or not meta.get("pushed"):
                    first = self.preset(preset["follows"])
                    raise WorkspaceError(f"Run “{first['title']}” and push it first: this task continues that pull request.", 409)
                script = self._script(d, preset)
                meta["preset"] = preset["id"]
                self.save_meta()
                return {"state": self.state(repo), "script": script}
            default = self.default_branch(d)
            base = preset["base"] if preset else f"origin/{default}"
            if preset:
                self.have(d, base)
            self.git(d, "checkout", "--quiet", "--force", "--detach", base)
            self.git(d, "reset", "--quiet", "--hard")
            self.git(d, "clean", "-fdq")
            sha = self.git(d, "rev-parse", "HEAD").strip()
            label = f"{default} at {sha[:7]}" if not preset else f"{sha[:7]}, before this change"
            self.meta[repo] = {"base": sha, "label": label, "preset": preset["id"] if preset else None}
            self.save_meta()
            script = self._script(d, preset) if preset else None
            return {"state": self.state(repo), "script": script}

    def _script(self, d: Path, preset: dict) -> dict:
        src = preset["source"]
        self.have(d, src)
        steps = []
        for line in self.git(d, "diff", "--name-status", "--no-renames", f"{src}^", src).splitlines():
            status, path = line.split("\t", 1)
            after = "" if status == "D" else self.show(d, src, path)
            if after is None:
                continue  # binary
            cur = self.path_in(d, path)
            before = cur.read_text(encoding="utf-8") if cur.is_file() else ""
            if before != after:
                steps.append({"path": path, "before": before, "after": after, "deleted": status == "D"})
        stamp = time.strftime("%m%d-%H%M")
        return {"id": preset["id"], "title": preset["title"], "ask": preset.get("ask", ""), "message": preset["message"],
                "branch": f"{preset.get('branch', 'demo/change')}-{stamp}", "steps": steps, "follows": preset.get("follows")}

    # ------------------------------------------------------------------ files
    def tree(self, repo: str) -> dict:
        d = self.dir(repo)
        files = self.git(d, "ls-files", "-co", "--exclude-standard").splitlines()
        return {"files": sorted(set(files)), "state": self.state(repo)}

    def read(self, repo: str, path: str) -> dict:
        d = self.dir(repo)
        p = self.path_in(d, path)
        if not p.is_file():
            raise WorkspaceError("No such file", 404)
        if p.stat().st_size > MAX_FILE:
            return {"path": path, "content": None, "reason": "This file is too large to show here."}
        try:
            return {"path": path, "content": p.read_text(encoding="utf-8")}
        except UnicodeDecodeError:
            return {"path": path, "content": None, "reason": "Binary file, not shown."}

    def write(self, repo: str, path: str, content: str, deleted: bool = False) -> dict:
        d = self.dir(repo)
        p = self.path_in(d, path)
        with self.lock(repo):
            if deleted:
                if p.is_file():
                    p.unlink()
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
        return {"ok": True}

    def search(self, repo: str, q: str) -> dict:
        d = self.dir(repo)
        if len(q.strip()) < 2:
            return {"hits": []}
        out = self.git(d, "grep", "-n", "-I", "-i", "--untracked", "--fixed-strings", "-e", q, "--", ".", check=False)
        hits = []
        for line in out.splitlines()[:300]:
            parts = line.split(":", 2)
            if len(parts) == 3 and parts[1].isdigit():
                hits.append({"path": parts[0], "line": int(parts[1]), "text": parts[2][:240]})
        return {"hits": hits, "more": len(out.splitlines()) > 300}

    def diff(self, repo: str) -> dict:
        d = self.dir(repo)
        files = []
        for c in self.state(repo)["changed"]:
            p = d / c["path"]
            files.append({"path": c["path"], "status": c["status"],
                          "original": self.show(d, "HEAD", c["path"]) or "",
                          "modified": p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""})
        return {"files": files}

    # ------------------------------------------------------------------ push
    def push(self, repo: str, branch: str, message: str, title: str, login: str, how: str, preset_id: str = "") -> dict:
        result = {}
        for ev in self.push_stream(repo, branch, message, title, login, how, preset_id):
            if ev["type"] == "done":
                result = ev["result"]
        return result

    def _run(self, d: Path, shown: list[str], real: list[str]):
        """Run one command for the push terminal: announce it, run it, then report its real output."""
        yield {"type": "cmd", "cmd": shlex.join(shown)}
        started = time.monotonic()
        p = subprocess.run(real, capture_output=True, text=True, timeout=180, cwd=d,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1"})
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        yield {"type": "out", "text": out[-3000:], "ok": p.returncode == 0, "seconds": round(time.monotonic() - started, 1)}
        if p.returncode != 0:
            raise WorkspaceError(f"{shown[0]} {shown[1]} failed: {out[-300:]}", 502)
        return out

    def push_stream(self, repo: str, branch: str, message: str, title: str, login: str, how: str, preset_id: str = ""):
        """Commit, push and open (or update) the pull request, yielding each command and its output as it runs.

        Checks happen before the first event, so a refused push raises WorkspaceError straight away."""
        me = self.gh_login()
        if login != me:
            raise WorkspaceError(f"Pushes go out under the GitHub account the gh CLI is signed in as ({me}). "
                                 f"Sign in to the dashboard as {me} to push.", 403)
        message = (message or "").strip() or "Update from the LGTM workspace"
        lock = self.lock(repo)
        lock.acquire()
        try:
            d = self.dir(repo)
            default = self.default_branch(d)
            if not self.state(repo)["changed"]:
                raise WorkspaceError("Nothing to commit: change a file first.")
            meta = self.meta.setdefault(repo, {})
            current = self.git(d, "symbolic-ref", "--short", "-q", "HEAD", check=False).strip()
            again = bool(current and current == meta.get("pushed"))
            if again:
                branch = current  # pushing again updates the same pull request
            else:
                branch = (branch or "").strip()
                if not BRANCH_RE.match(branch) or ".." in branch or branch.endswith((".lock", "/")):
                    raise WorkspaceError("Use a branch name made of letters, digits, '.', '_', '-' and '/'.")
                if branch == default:
                    raise WorkspaceError(f"Push to a new branch, not {default}.")
                if self.git(d, "ls-remote", "--heads", "origin", branch, auth=True).strip():
                    raise WorkspaceError(f"A branch called {branch} already exists on GitHub. Pick another name.", 409)
            return (yield from self._push_steps(d, repo, default, branch, again, message, title, how, meta, preset_id))
        finally:
            lock.release()

    def _push_steps(self, d, repo, default, branch, again, message, title, how, meta, preset_id=""):
        gh = gh_bin()
        cred = self._cred()
        if not again:
            yield from self._run(d, ["git", "checkout", "-b", branch], ["git", "checkout", "-B", branch])
        yield from self._run(d, ["git", "add", "-A"], ["git", "add", "-A"])
        yield from self._run(d, ["git", "commit", "-m", message], ["git", "commit", "-m", message])
        sha = self.git(d, "rev-parse", "HEAD").strip()
        yield from self._run(d, ["git", "push", "origin", branch], ["git", *cred, "push", "origin", f"HEAD:refs/heads/{branch}"])
        found = json.loads(self.gh("pr", "list", "--repo", repo, "--head", branch, "--state", "open", "--json", "number,url", cwd=d) or "[]")
        created = not found
        if found:
            pr = found[0]
            yield {"type": "cmd", "cmd": f"gh pr view {branch} --json url"}
            yield {"type": "out", "text": f"{pr['url']}  (already open: this push updates it)", "ok": True, "seconds": 0}
        else:
            written = ""
            if how == "replay" and preset_id:   # a replayed change reads as the real pull request it was
                written = next((p.get("pr_body", "") for p in self.presets(repo) if p["id"] == preset_id), "")
            if how in ("live", "recorded") and preset_id:     # written by the local model from the task's request
                ask = next((p.get("ask", "") for p in self.presets(repo) if p["id"] == preset_id), "")
                written = f"{ask}\n\n" + (f"Written live in the LGTM demo by a local coding model ({WRITER_MODEL})." if how == "live"
                                            else "Replayed from a recorded earlier run of the local coding model in the LGTM demo.")
            body = written or ("Opened from the LGTM demo workspace. "
                               + ("The change was written by Claude from a developer's request." if how == "model"
                                  else "The change was written in the workspace editor."))
            pr_title = (title or message.splitlines()[0])[:200]
            out = yield from self._run(d, ["gh", "pr", "create", "--base", default, "--head", branch, "--title", pr_title],
                                       [gh, "pr", "create", "--repo", repo, "--base", default, "--head", branch, "--title", pr_title, "--body", body])
            url = out.strip().splitlines()[-1]
            pr = {"url": url, "number": int(url.rstrip("/").rsplit("/", 1)[-1])}
        meta.update(pushed=branch, pr=pr, label=f"branch {branch}")
        self.save_meta()
        result = {"branch": branch, "commit": sha[:7], "pr": pr, "created": created, "state": self.state(repo)}
        yield {"type": "done", "result": result}
        return result

    # ------------------------------------------------------------------ AI assistant (Claude on Bedrock)
    def _prompt(self, repo: str, path: str, prompt: str) -> tuple[str, str]:
        d = self.dir(repo)
        f = self.read(repo, path)
        if f.get("content") is None:
            raise WorkspaceError(f.get("reason") or "That file cannot be edited here.")
        if len(f["content"]) > 60_000:
            raise WorkspaceError("That file is too long for the assistant. Open a smaller file.")
        files = self.git(d, "ls-files").splitlines()
        listing = "\n".join(files[:400]) + ("\n…" if len(files) > 400 else "")
        system = ("You are the coding assistant inside a developer's editor. You change exactly one file to do what "
                  "the developer asks. Reply with the complete new content of that file and nothing else: no "
                  "explanation and no Markdown fences. Keep the file's existing style and leave unrelated code unchanged.")
        user = (f"Repository: {repo}\nFiles in the repository:\n{listing}\n\nFile to change: {path}\n<file>\n{f['content']}\n</file>\n\n"
                f"Request: {prompt.strip()[:2000]}")
        return system, user

    def write_live(self, repo: str, path: str, prompt: str):
        """Yield events: text deltas of the complete new file from the local coding model, then done."""
        import urllib.error
        import urllib.request

        system, user = self._prompt(repo, path, prompt)
        body = {"model": WRITER_MODEL, "stream": True, "options": {"temperature": 0.7, "num_ctx": 8192},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        req = urllib.request.Request(WRITER_URL.rstrip("/") + "/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=300)
        except (urllib.error.URLError, OSError) as exc:
            raise WorkspaceError(f"The local coding model ({WRITER_MODEL}) is not running: start Ollama, or use Replay. ({exc})", 503) from exc
        with resp:
            for raw in resp:
                if not raw.strip():
                    continue
                ev = json.loads(raw)
                if ev.get("error"):
                    raise WorkspaceError(f"The local coding model failed: {ev['error']}", 502)
                piece = (ev.get("message") or {}).get("content") or ""
                if piece:
                    yield {"type": "text", "delta": piece}
                if ev.get("done"):
                    break
        yield {"type": "done", "model": WRITER_MODEL}
