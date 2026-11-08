"""GitHub App plumbing for the LGTM demo: manifest flow, app and installation
tokens, user sign-in, webhook signatures and the few REST calls a review needs.

Standard library plus PyJWT (already in the project venv). Credentials live in
``demo/.secrets/github-app.json`` (mode 600, git-ignored) and are never logged:
error messages from GitHub are passed through ``redact`` first.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import jwt

API = "https://api.github.com"
WEB = "https://github.com"
SECRETS_DIR = Path(__file__).resolve().parent / ".secrets"
APP_FILE = SECRETS_DIR / "github-app.json"
RELAY_FILE = SECRETS_DIR / "relay.json"

PERMISSIONS = {"contents": "read", "metadata": "read", "pull_requests": "write", "checks": "write"}
# installation and installation_repositories are always delivered to a GitHub
# App; they cannot (and need not) be listed here.
EVENTS = ["pull_request", "check_run"]


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


# ---------------------------------------------------------------------------
# Local secret storage
# ---------------------------------------------------------------------------
def _write_private(path: Path, payload: dict) -> None:
    SECRETS_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def load_app() -> dict | None:
    if not APP_FILE.is_file():
        return None
    return json.loads(APP_FILE.read_text(encoding="utf-8"))


def load_relay() -> str | None:
    if not RELAY_FILE.is_file():
        return None
    return json.loads(RELAY_FILE.read_text(encoding="utf-8")).get("url")


def save_relay(url: str) -> None:
    _write_private(RELAY_FILE, {"url": url})


def new_relay_channel() -> str:
    """Ask smee.io for a fresh channel (it answers /new with a redirect)."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(urllib.request.Request("https://smee.io/new", method="HEAD"), timeout=15)
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "")
        if exc.code in (301, 302, 303, 307) and location.startswith("https://smee.io/"):
            return location
        raise
    raise RuntimeError("smee.io did not hand out a channel")


_SECRET_KEYS = ("pem", "webhook_secret", "client_secret", "token", "access_token")


def redact(text: str) -> str:
    """Strip anything that looks like a credential before it reaches a log or a page."""
    text = re.sub(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", "<redacted key>", text, flags=re.S)
    text = re.sub(r"\b(gh[pousr]_[A-Za-z0-9_]{20,}|ghu_[A-Za-z0-9_]+|v1\.[0-9a-f]{40})\b", "<redacted>", text)
    app = load_app() or {}
    for key in _SECRET_KEYS:
        value = app.get(key)
        if isinstance(value, str) and len(value) > 6:
            text = text.replace(value, "<redacted>")
    return text


# ---------------------------------------------------------------------------
# Manifest flow
# ---------------------------------------------------------------------------
def manifest(name: str, base_url: str, webhook_url: str) -> dict:
    return {
        "name": name,
        "url": base_url,
        "description": "LGTM reviews every pull request for security bugs (SQL injection, broken "
                       "authorization) and posts evidence-backed findings as a check run and review.",
        "hook_attributes": {"url": webhook_url, "active": True},
        "redirect_url": f"{base_url}/github/manifest/callback",
        "callback_urls": [f"{base_url}/auth/callback"],
        "setup_url": f"{base_url}/github/installed",
        "setup_on_update": True,
        "request_oauth_on_install": False,
        "public": False,
        "default_permissions": PERMISSIONS,
        "default_events": EVENTS,
    }


def convert_manifest(code: str) -> dict:
    """Exchange the one-time code for the new app's credentials and store them."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", code):
        raise ValueError("bad manifest code")
    data = _request("POST", f"{API}/app-manifests/{code}/conversions", token=None)
    keep = {k: data.get(k) for k in ("id", "slug", "name", "client_id", "client_secret",
                                      "webhook_secret", "pem", "html_url")}
    keep["owner"] = (data.get("owner") or {}).get("login")
    keep["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _write_private(APP_FILE, keep)
    return public_app_info(keep)


def public_app_info(app: dict | None = None) -> dict | None:
    app = app if app is not None else load_app()
    if not app:
        return None
    return {k: app.get(k) for k in ("id", "slug", "name", "html_url", "owner", "created_at")}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _request(method: str, url: str, token: str | None, body: dict | None = None,
             auth_scheme: str = "Bearer", accept: str = "application/vnd.github+json") -> dict | list:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "lgtm-demo"}
    if token:
        headers["Authorization"] = f"{auth_scheme} {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:600]
        raise GitHubError(exc.code, redact(detail)) from None
    return json.loads(raw) if raw else {}


def app_jwt() -> str:
    app = load_app()
    if not app:
        raise RuntimeError("the GitHub App is not set up yet")
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(app["client_id"] or app["id"])},
                      app["pem"], algorithm="RS256")


class Tokens:
    """Installation tokens, cached in memory until shortly before they expire."""

    def __init__(self) -> None:
        self._cache: dict[int, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def installation(self, installation_id: int) -> str:
        with self._lock:
            hit = self._cache.get(installation_id)
            if hit and hit[1] - time.time() > 300:
                return hit[0]
            data = _request("POST", f"{API}/app/installations/{installation_id}/access_tokens", app_jwt())
            expires = calendar.timegm(time.strptime(data["expires_at"], "%Y-%m-%dT%H:%M:%SZ"))
            self._cache[installation_id] = (data["token"], expires)
            return data["token"]


TOKENS = Tokens()


def as_app(method: str, path: str, body: dict | None = None):
    return _request(method, API + path, app_jwt(), body)


def as_installation(installation_id: int, method: str, path: str, body: dict | None = None):
    return _request(method, API + path, TOKENS.installation(installation_id), body)


def as_user(token: str, method: str, path: str, body: dict | None = None):
    return _request(method, API + path, token, body)


def paged(fn, path: str, key: str | None, limit: int = 500) -> list:
    """Follow ``page=`` until a short page; good enough for the demo's small accounts."""
    out: list = []
    page = 1
    sep = "&" if "?" in path else "?"
    while len(out) < limit:
        data = fn("GET", f"{path}{sep}per_page=100&page={page}")
        items = data.get(key, []) if key else data
        out.extend(items)
        if len(items) < 100:
            break
        page += 1
    return out


def git_auth_env(installation_id: int) -> dict:
    """Environment for ``git fetch`` over HTTPS: the token never appears on a command line."""
    basic = base64.b64encode(f"x-access-token:{TOKENS.installation(installation_id)}".encode()).decode()
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}", "GIT_TERMINAL_PROMPT": "0"}


# ---------------------------------------------------------------------------
# User sign-in (the app's own OAuth credentials)
# ---------------------------------------------------------------------------
def authorize_url(redirect_uri: str, state: str) -> str:
    app = load_app()
    if not app:
        raise RuntimeError("the GitHub App is not set up yet")
    # prompt=select_account makes GitHub show its account picker every time instead of
    # silently signing in with the browser's current session (useful when recording a demo).
    q = urllib.parse.urlencode({"client_id": app["client_id"], "redirect_uri": redirect_uri, "state": state,
                                "prompt": "select_account"})
    return f"{WEB}/login/oauth/authorize?{q}"


def exchange_user_code(code: str, redirect_uri: str) -> str:
    app = load_app()
    body = {"client_id": app["client_id"], "client_secret": app["client_secret"],
            "code": code, "redirect_uri": redirect_uri}
    data = _request("POST", f"{WEB}/login/oauth/access_token", None, body, accept="application/json")
    if "access_token" not in data:
        raise GitHubError(400, data.get("error_description") or data.get("error") or "sign-in failed")
    return data["access_token"]


def new_state() -> str:
    return pysecrets.token_urlsafe(24)


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------
def verify_signature(body: bytes, signature: str | None) -> bool:
    app = load_app()
    if not app or not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(app["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature[7:])


# ---------------------------------------------------------------------------
# Text that goes to github.com
# ---------------------------------------------------------------------------
_WJ = "⁠"

_FENCE_RE = re.compile(
    r"(?m)"
    r"^[ ]{0,3}"
    r"(?:(`{3,})[^\n`]*\n[\s\S]*?(?:^[ ]{0,3}\1+[ ]*(?:\n|\Z)|\Z)"
    r"|"
    r"(~{3,})[^\n]*\n[\s\S]*?(?:^[ ]{0,3}\2+[ ]*(?:\n|\Z)|\Z))"
)


def _find_code_intervals(text: str) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []

    for m in _FENCE_RE.finditer(text):
        intervals.append((m.start(), m.end()))

    def in_fence(p: int) -> bool:
        return any(s <= p < e for s, e in intervals)

    pos = 0
    n = len(text)
    while pos < n:
        if in_fence(pos):
            for s, e in intervals:
                if s <= pos < e:
                    pos = e
                    break
            continue

        if text[pos] == "`":
            bs_count = 0
            k = pos - 1
            while k >= 0 and text[k] == "\\":
                bs_count += 1
                k -= 1
            if bs_count % 2 == 1:
                pos += 1
                continue

            start_delim_start = pos
            while pos < n and text[pos] == "`":
                pos += 1
            delim_len = pos - start_delim_start

            next_fence = next((s for s, e in intervals if s >= pos), n)
            blank_m = re.search(r"\n[ \t]*\n", text[pos:next_fence])
            limit = pos + blank_m.start() if blank_m else next_fence

            close_pattern = re.compile(r"(?<!`)" + re.escape("`" * delim_len) + r"(?!`)")
            m_close = close_pattern.search(text, pos, limit)
            if m_close:
                intervals.append((start_delim_start, m_close.end()))
                pos = m_close.end()
        else:
            pos += 1

    intervals.sort(key=lambda x: x[0])
    return intervals


def safe_markdown(text: str, own_owner: str) -> str:
    """Make text safe to post: no @mentions, no cross-repository references or links.

    Model output quotes decorators such as ``@login_required``; on GitHub that
    would mention whoever owns that login. Links or ``owner/repo#123`` shorthand
    to another project would put a "mentioned this" backlink on it.
    """
    intervals = _find_code_intervals(text)
    if not intervals:
        parts = [text]
    else:
        parts = []
        last_idx = 0
        for start, end in intervals:
            parts.append(text[last_idx:start])
            parts.append(text[start:end])
            last_idx = end
        parts.append(text[last_idx:])

    for i in range(0, len(parts), 2):
        chunk = parts[i]

        # 1. Markdown link syntax: [label](url "optional title")
        def _replace_md_link(m: re.Match) -> str:
            label, url = m.group(1), m.group(2)
            if re.match(r"^https?://(?:www\.)?github\.com/" + re.escape(own_owner) + r"/", url):
                return m.group(0)
            if label.strip() == url.strip():
                return "(link removed)"
            return f"{label} (link removed)"

        chunk = re.sub(
            r"\[([^\]]+)\]\((https?://(?:www\.)?github\.com/[^\s)]+?)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)",
            _replace_md_link,
            chunk,
        )

        # 2. Bare external GitHub URLs (excluding trailing punctuation)
        chunk = re.sub(
            r"https?://(?:www\.)?github\.com/(?!" + re.escape(own_owner) + r"/)[^\s)>\]]*[^\s)>\].,:;]",
            "(link removed)",
            chunk,
        )

        # 3. Defang @mentions (ignores email addresses where @ is preceded by word chars)
        chunk = re.sub(r"(?<!\w)@(?=[A-Za-z0-9-])", f"@{_WJ}", chunk)

        # 4. Cross-repository shorthand (owner/repo#123 or owner/repo@sha)
        chunk = re.sub(
            r"\b([A-Za-z0-9][\w.-]*)/([\w.-]+)(#|@)(?=\w)",
            lambda m: f"{m.group(1)}/{m.group(2)}{m.group(3)}{_WJ}",
            chunk,
        )

        # 5. Local issue/PR shorthand (#123 or GH-123)
        chunk = re.sub(r"(?<![\w/])(GH-|#)(?=\d)", lambda m: f"{m.group(1)}{_WJ}", chunk)

        parts[i] = chunk

    return "".join(parts)
