"""Authored fixtures for the Kev validation benchmark: two small case repositories and labelled findings
(10 in each of 7 incorrect kinds, 20 correct controls) that cite them. Each case states its verdict,
severity and provenance ground truth."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from lgtm.agents.base import AgentFinding, EvidenceItem

KINDS = (
    "safe_twin",
    "unrelated_code",
    "missing_check",
    "sqli_no_sql",
    "wrong_cwe",
    "live_shaped",
    "real_elsewhere",
)
CONTROL = "control"

REPOS: dict[str, dict[str, str]] = {
    "shop": {
        "app/db.py": '''import sqlite3


def find_user(conn, name):
    query = "SELECT id, email FROM users WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()


def find_user_safe(conn, name):
    return conn.execute("SELECT id, email FROM users WHERE name = ?", (name,)).fetchall()


def search_orders(conn, term):
    sql = f"SELECT * FROM orders WHERE note LIKE '%{term}%'"
    return conn.execute(sql).fetchall()


def search_orders_safe(conn, term):
    return conn.execute("SELECT * FROM orders WHERE note LIKE ?", (f"%{term}%",)).fetchall()


def delete_item(conn, item_id):
    conn.execute("DELETE FROM items WHERE id = %s" % item_id)
    conn.commit()
''',
        "app/views.py": '''from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)


@app.route("/invoices/<int:invoice_id>")
def get_invoice(invoice_id):
    return jsonify(Invoice.query.get(invoice_id).to_dict())


@app.route("/invoices/<int:invoice_id>/owned")
def get_invoice_owned(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    if invoice.owner_id != g.user.id:
        abort(403)
    return jsonify(invoice.to_dict())


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return "", 204


@app.route("/admin/users/<int:user_id>/remove", methods=["POST"])
@require_role("admin")
def remove_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return "", 204


@app.route("/reports/<int:report_id>")
def get_report(report_id):
    report = Report.query.get_or_404(report_id)
    if not g.user.can("reports:read", report):
        abort(403)
    return jsonify(report.to_dict())


@app.route("/profile")
def profile():
    if not g.user.is_authenticated:
        abort(401)
    return jsonify(g.user.to_dict())


@app.route("/projects/<int:project_id>", methods=["PUT"])
def update_project(project_id):
    project = Project.query.get_or_404(project_id)
    if not g.user.can("projects:write", project):
        abort(403)
    project.update(request.json)
    return jsonify(project.to_dict())


@app.route("/exports/<int:export_id>")
@login_required
def download_export(export_id):
    return send_export(export_id, g.user)


@app.route("/internal/export")
def export_all():
    return jsonify([user.to_dict() for user in User.query.all()])


@app.route("/account/email", methods=["POST"])
def change_email():
    g.user.email = request.form["email"]
    db.session.commit()
    return "", 204
''',
        "app/render.py": '''import html

from flask import request


def greet():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"


def greet_safe():
    name = request.args.get("name", "")
    return "<h1>Hello " + html.escape(name) + "</h1>"
''',
        "app/config.py": '''import logging

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
PAGE_SIZE = 25
DEBUG = False
API_KEY = "sk_live_51H8x2exampleKey"


def setup_logging():
    logging.basicConfig(format=LOG_FORMAT)
''',
        "app/util.py": '''import datetime


def slugify(title):
    return "-".join(title.lower().split())


def format_price(cents):
    return f"{cents // 100}.{cents % 100:02d}"


def chunk(items, size):
    return [items[i : i + size] for i in range(0, len(items), size)]


def mask_email(address):
    name, _, domain = address.partition("@")
    return name[:1] + "***@" + domain


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def human_size(count):
    return f"{count / 1024:.1f} KiB"
''',
        "app/orders.py": '''def lookup_order(conn, ref):
    stmt = "SELECT * FROM orders WHERE ref = '" + ref + "'"
    return conn.execute(stmt).fetchall()


def lookup_order_safe(conn, ref):
    return conn.execute("SELECT * FROM orders WHERE ref = ?", (ref,)).fetchall()


def rename_tag(conn, old, new):
    conn.execute(f"UPDATE tags SET label = '{new}' WHERE label = '{old}'")
    conn.commit()


def rename_tag_safe(conn, old, new):
    conn.execute("UPDATE tags SET label = ? WHERE label = ?", (new, old))
    conn.commit()
''',
        "app/text.py": '''def pluralize(word, count):
    return word if count == 1 else word + "s"


def truncate(text, width):
    return text if len(text) <= width else text[: width - 1] + "..."


def title_case(text):
    return " ".join(part.capitalize() for part in text.split())


def initials(name):
    return "".join(part[0].upper() for part in name.split())
''',
        "app/api.py": '''from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)


@app.route("/teams/<int:team_id>/members")
def list_members(team_id):
    team = Team.query.get_or_404(team_id)
    if not g.user.can("teams:read", team):
        abort(403)
    return jsonify(team.members())


@app.route("/teams/<int:team_id>/purge", methods=["POST"])
def purge_team(team_id):
    Team.query.filter_by(id=team_id).delete()
    return "", 204


@app.route("/teams/<int:team_id>/archive", methods=["POST"])
@require_role("admin")
def archive_team(team_id):
    Team.query.filter_by(id=team_id).update({"archived": True})
    return "", 204


@app.route("/notes/<int:note_id>")
def get_note(note_id):
    return jsonify(Note.query.get(note_id).to_dict())


@app.route("/comments/<int:comment_id>", methods=["DELETE"])
@require_role("moderator")
def delete_comment(comment_id):
    Comment.query.filter_by(id=comment_id).delete()
    return "", 204


@app.route("/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    note = Note.query.get_or_404(note_id)
    if not g.user.can("notes:write", note):
        abort(403)
    note.update(request.json)
    return jsonify(note.to_dict())
''',
        "docs/security.md": """# Security policy

Administrative actions require the admin role.
Records may be read only by their owner.
Secrets are never stored in source code.
""",
    },
    "ops": {
        "ops/shell.py": '''import os
import subprocess


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)


def ping_safe(host):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True)


def archive(name):
    os.system("tar czf /tmp/" + name + ".tgz /srv/data")


def archive_safe(name):
    return subprocess.run(["tar", "czf", "/tmp/" + name + ".tgz", "/srv/data"], capture_output=True)
''',
        "ops/files.py": '''import os

BASE = "/srv/uploads"


def read_upload(name):
    with open(os.path.join(BASE, name)) as handle:
        return handle.read()


def read_upload_safe(name):
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        raise PermissionError(name)
    with open(path) as handle:
        return handle.read()
''',
        "ops/loader.py": '''import pickle

import yaml


def load_session(blob):
    return pickle.loads(blob)


def load_settings(text):
    return yaml.safe_load(text)


def calc(expression):
    return eval(expression)
''',
        "ops/net.py": '''import urllib.parse

import requests

ALLOWED = {"api.example.com"}


def fetch_any(url):
    return requests.get(url, timeout=5).text


def fetch_allowed(url):
    host = urllib.parse.urlsplit(url).hostname
    if host not in ALLOWED:
        raise PermissionError(host)
    return requests.get(url, timeout=5).text
''',
        "ops/fetch.py": '''import requests


def preview(url):
    return requests.get(url, timeout=5).text
''',
    },
}

POLICY = "docs/security.md"
OTHER_FLAW = "other_flaw"
_OTHER_FLAW_CASES = frozenset(f"wrong_cwe-{n:02d}" for n in range(1, 11))
_AUTHZ = {"CWE-285", "CWE-287", "CWE-306", "CWE-639", "CWE-862", "CWE-863"}


@dataclass
class Fixture:
    case_id: str
    kind: str
    repo: str
    finding: AgentFinding
    verdict: str
    severity: str | None
    provenance: str
    tags: tuple[str, ...] = ()


def _cite(repo: str, path: str, first: str, last: str | None = None) -> EvidenceItem:
    lines = REPOS[repo][path].splitlines()
    start = next(i for i, line in enumerate(lines) if first in line)
    end = start if last is None else next(i for i in range(start, len(lines)) if last in lines[i])
    return EvidenceItem(
        type="code", file=path, lines=[start + 1, end + 1], content="\n".join(lines[start : end + 1])
    )


def _policy(line: str) -> EvidenceItem:
    return EvidenceItem(type="policy", source=POLICY, content=line)


# (repo, path, first marker, last marker, claimed CWE, explanation, policy line)
_CASES: dict[str, list[tuple]] = {
    "safe_twin": [
        ("shop", "app/db.py", "def find_user_safe(", "return conn", "CWE-89",
         "The user name is concatenated into the SQL string, so a crafted name changes the query.", ""),
        ("shop", "app/db.py", "def search_orders_safe(", "return conn", "CWE-89",
         "The search term is formatted into the LIKE clause, which allows SQL injection.", ""),
        ("ops", "ops/shell.py", "def ping_safe(", "return subprocess", "CWE-78",
         "The host is passed to a shell command, so shell metacharacters run extra commands.", ""),
        ("shop", "app/render.py", "def greet_safe(", "return", "CWE-79",
         "The name from the query string is written into the page without encoding.", ""),
        ("ops", "ops/files.py", "def read_upload_safe(", "return handle", "CWE-22",
         "The upload name is joined to the base directory without confining the result.", ""),
        ("ops", "ops/loader.py", "def load_settings(", "return yaml", "CWE-502",
         "The settings text is deserialized with a loader that can create arbitrary objects.", ""),
        ("shop", "app/orders.py", "def lookup_order_safe(", "return conn", "CWE-89",
         "The order reference is concatenated into the SELECT statement, so a crafted reference alters the query.", ""),
        ("shop", "app/orders.py", "def rename_tag_safe(", "conn.execute", "CWE-89",
         "The tag labels are formatted into the UPDATE statement, which allows SQL injection.", ""),
        ("ops", "ops/net.py", "def fetch_allowed(", "return requests", "CWE-918",
         "The server fetches a caller-supplied URL without restricting the destination.", ""),
        ("ops", "ops/shell.py", "def archive_safe(", "return subprocess", "CWE-78",
         "The archive name is concatenated into a command run through the shell.", ""),
    ],
    "unrelated_code": [
        ("shop", "app/config.py", "PAGE_SIZE =", None, "CWE-862",
         "The handler performs the operation without any authorization check.", ""),
        ("shop", "app/config.py", "LOG_FORMAT =", None, "CWE-79",
         "User input is written into the HTML response without output encoding.", ""),
        ("shop", "app/util.py", "def human_size(", "return", "CWE-78",
         "The size helper passes untrusted input to an operating system command.", ""),
        ("shop", "app/util.py", "def utcnow(", "return", "CWE-502",
         "Untrusted data is deserialized with pickle here.", ""),
        ("shop", "app/config.py", "DEBUG =", None, "CWE-200",
         "Sensitive data is returned to callers who are not authorized to see it.", ""),
        ("shop", "app/views.py", "app = Flask(", None, "CWE-287",
         "The application accepts caller identity without proving it.", ""),
        ("shop", "app/text.py", "def pluralize(", "return", "CWE-918",
         "The helper fetches a caller-supplied URL without restricting the destination.", ""),
        ("shop", "app/text.py", "def truncate(", "return", "CWE-22",
         "The text is used to build a file path that is not confined to an intended directory.", ""),
        ("shop", "app/text.py", "def title_case(", "return", "CWE-352",
         "The state-changing request is accepted without any token showing the user intended it.", ""),
        ("shop", "app/text.py", "def initials(", "return", "CWE-611",
         "The name is parsed as XML with external entity resolution enabled.", ""),
    ],
    "missing_check": [
        ("shop", "app/views.py", "/owned", "return jsonify(invoice", "CWE-639",
         "The invoice is fetched by a caller-supplied id with no check that the caller owns it.", ""),
        ("shop", "app/views.py", "/remove", "return \"\", 204", "CWE-862",
         "The removal endpoint deletes the user with no authorization check.", ""),
        ("shop", "app/views.py", "/reports/", "return jsonify(report", "CWE-285",
         "The report is returned without checking that the caller is allowed to read it.", ""),
        ("shop", "app/views.py", "\"/profile\"", "return jsonify(g.user", "CWE-306",
         "The profile endpoint can be reached without any authentication check.", ""),
        ("shop", "app/views.py", "methods=[\"PUT\"]", "return jsonify(project", "CWE-863",
         "No permission check guards the project update, so any caller can change a project.", ""),
        ("shop", "app/views.py", "/exports/", "return send_export", "CWE-287",
         "The export download accepts the caller identity without verifying it.", ""),
        ("shop", "app/api.py", "/members", "return jsonify(team", "CWE-862",
         "The member list is returned with no authorization check on the caller.", ""),
        ("shop", "app/api.py", "/archive", "return \"\", 204", "CWE-862",
         "The archive endpoint changes the team with no authorization check.", ""),
        ("shop", "app/api.py", "def delete_comment(", "return \"\", 204", "CWE-863",
         "The comment is deleted without any permission check on the caller.", ""),
        ("shop", "app/api.py", "def update_note(", "return jsonify(note", "CWE-863",
         "No permission check guards the note update, so any caller can change a note.", ""),
    ],
    "sqli_no_sql": [
        ("shop", "app/util.py", "def slugify(", "return", "CWE-89",
         "The title is concatenated into an SQL statement, which allows SQL injection.", ""),
        ("shop", "app/util.py", "def format_price(", "return", "CWE-89",
         "The price value is formatted into a query string without parameter binding.", ""),
        ("shop", "app/util.py", "def chunk(", "return", "CWE-89",
         "User-supplied items are built into a SQL query by string formatting.", ""),
        ("shop", "app/util.py", "def mask_email(", "return", "CWE-89",
         "The address is placed into a SQL statement unescaped, enabling SQL injection.", ""),
        ("shop", "app/config.py", "def setup_logging(", "basicConfig", "CWE-89",
         "The log format is interpolated into a SQL command, so injected input alters the query.", ""),
        ("ops", "ops/files.py", "BASE =", None, "CWE-89",
         "The base path is concatenated into a SQL query with untrusted input.", ""),
        ("shop", "app/text.py", "def pluralize(", "return", "CWE-89",
         "The word is placed into a SQL query string without parameter binding.", ""),
        ("shop", "app/text.py", "def truncate(", "return", "CWE-89",
         "The text is concatenated into a SELECT statement, which allows SQL injection.", ""),
        ("shop", "app/text.py", "def title_case(", "return", "CWE-89",
         "The title is interpolated into a WHERE clause, so crafted input changes the query.", ""),
        ("shop", "app/text.py", "def initials(", "return", "CWE-89",
         "The name is built into an INSERT statement unescaped, enabling SQL injection.", ""),
    ],
    "wrong_cwe": [
        ("shop", "app/db.py", "def find_user(", "return conn", "CWE-79",
         "The user name is written into an HTML page without output encoding.", ""),
        ("ops", "ops/shell.py", "def ping(", "return subprocess", "CWE-22",
         "The host name builds a file path that is not confined to an intended directory.", ""),
        ("shop", "app/render.py", "def greet(", "return", "CWE-78",
         "The name reaches an operating system command without being neutralized.", ""),
        ("ops", "ops/files.py", "def read_upload(", "return handle", "CWE-502",
         "The upload content is deserialized with a mechanism that can create arbitrary objects.", ""),
        ("shop", "app/views.py", "<int:invoice_id>\")", "return jsonify(Invoice", "CWE-798",
         "A secret is written into the source code of the invoice endpoint.", ""),
        ("ops", "ops/loader.py", "def load_session(", "return pickle", "CWE-918",
         "The server fetches a caller-supplied URL without restricting the destination.", ""),
        ("shop", "app/orders.py", "def lookup_order(", "return conn", "CWE-22",
         "The order reference builds a file path that is not confined to an intended directory.", ""),
        ("shop", "app/orders.py", "def rename_tag(", "conn.execute", "CWE-352",
         "The tag change is accepted from a request without any token showing the user intended it.", ""),
        ("ops", "ops/loader.py", "def calc(", "return eval", "CWE-22",
         "The expression is joined into a file path without confining the result.", ""),
        ("ops", "ops/shell.py", "def archive(", "os.system", "CWE-502",
         "The archive name is deserialized with a mechanism that can create arbitrary objects.", ""),
    ],
    "real_elsewhere": [
        ("shop", "app/util.py", "def format_price(", "return", "CWE-89",
         "The user name is concatenated into the SQL string, so a crafted name changes the query.", ""),
        ("shop", "app/config.py", "def setup_logging(", "basicConfig", "CWE-89",
         "The search term is formatted into the LIKE clause, which allows SQL injection.", ""),
        ("shop", "app/text.py", "def truncate(", "return", "CWE-89",
         "The item id is interpolated into the DELETE statement instead of being bound.", ""),
        ("ops", "ops/loader.py", "def load_settings(", "return yaml", "CWE-78",
         "The host is passed to a shell command, so shell metacharacters run extra commands.", ""),
        ("ops", "ops/files.py", "def read_upload_safe(", "return handle", "CWE-78",
         "The archive name is concatenated into a command run through the shell.", ""),
        ("shop", "app/util.py", "def mask_email(", "return", "CWE-79",
         "The name from the query string is written into the page without encoding.", ""),
        ("ops", "ops/net.py", "def fetch_allowed(", "return requests", "CWE-22",
         "The upload name is joined to the base directory without confining the result.", ""),
        ("shop", "app/config.py", "PAGE_SIZE =", None, "CWE-639",
         "The invoice is fetched by a caller-supplied id with no check that the caller owns it.", ""),
        ("shop", "app/util.py", "def chunk(", "return", "CWE-862",
         "The delete endpoint removes the user with no authorization check.", ""),
        ("shop", "app/text.py", "def title_case(", "return", "CWE-798",
         "A live API key is written into the source code.", ""),
    ],
    CONTROL: [
        ("shop", "app/db.py", "def find_user(", "return conn", "CWE-89",
         "The user name is concatenated into the SQL string, so a crafted name changes the query.", ""),
        ("shop", "app/db.py", "def search_orders(", "return conn", "CWE-89",
         "The search term is formatted into the LIKE clause, which allows SQL injection.", ""),
        ("shop", "app/db.py", "def delete_item(", "conn.execute", "CWE-89",
         "The item id is interpolated into the DELETE statement instead of being bound.", ""),
        ("ops", "ops/shell.py", "def ping(", "return subprocess", "CWE-78",
         "The host is passed to a shell command, so shell metacharacters run extra commands.", ""),
        ("ops", "ops/shell.py", "def archive(", "os.system", "CWE-78",
         "The archive name is concatenated into a command run through the shell.", ""),
        ("shop", "app/render.py", "def greet(", "return", "CWE-79",
         "The name from the query string is written into the page without encoding.", ""),
        ("ops", "ops/files.py", "def read_upload(", "return handle", "CWE-22",
         "The upload name is joined to the base directory without confining the result.", ""),
        ("shop", "app/views.py", "<int:invoice_id>\")", "return jsonify(Invoice", "CWE-639",
         "The invoice is fetched by a caller-supplied id with no check that the caller owns it.",
         "Records may be read only by their owner."),
        ("shop", "app/views.py", "/delete", "return \"\", 204", "CWE-862",
         "The delete endpoint removes the user with no authorization check.",
         "Administrative actions require the admin role."),
        ("shop", "app/config.py", "API_KEY =", None, "CWE-798",
         "A live API key is written into the source code.",
         "Secrets are never stored in source code."),
        ("ops", "ops/loader.py", "def load_session(", "return pickle", "CWE-502",
         "Session bytes are deserialized with pickle, which can create arbitrary objects.", ""),
        ("ops", "ops/loader.py", "def calc(", "return eval", "CWE-94",
         "The expression from the caller is evaluated as code.", ""),
        ("ops", "ops/fetch.py", "def preview(", "return requests", "CWE-918",
         "The server fetches a caller-supplied URL without restricting the destination.", ""),
        ("shop", "app/views.py", "/internal/export", "return jsonify([user", "CWE-306",
         "The export of all users can be reached without any authentication check.", ""),
        ("shop", "app/views.py", "/account/email", "return \"\", 204", "CWE-352",
         "The email change is accepted from a POST without any token showing the user intended it.", ""),
        ("shop", "app/orders.py", "def lookup_order(", "return conn", "CWE-89",
         "The order reference is concatenated into the SELECT statement, so a crafted reference alters the query.", ""),
        ("shop", "app/orders.py", "def rename_tag(", "conn.execute", "CWE-89",
         "The tag labels are formatted into the UPDATE statement, which allows SQL injection.", ""),
        ("ops", "ops/net.py", "def fetch_any(", "return requests", "CWE-918",
         "The server fetches a caller-supplied URL without restricting the destination.", ""),
        ("shop", "app/api.py", "def get_note(", "return jsonify(Note", "CWE-639",
         "The note is fetched by a caller-supplied id with no check that the caller owns it.",
         "Records may be read only by their owner."),
        ("shop", "app/api.py", "/purge", "return \"\", 204", "CWE-862",
         "The purge endpoint removes the team with no authorization check.",
         "Administrative actions require the admin role."),
    ],
}

_SEVERITY = {
    "CWE-89": "high", "CWE-78": "critical", "CWE-79": "medium", "CWE-22": "high", "CWE-639": "high",
    "CWE-862": "high", "CWE-798": "high", "CWE-502": "critical", "CWE-94": "critical",
    "CWE-918": "medium", "CWE-306": "high", "CWE-352": "medium",
}

# (repo, path, first marker, last marker, extra citations, claimed CWE, claim with {quote}, quote marker, policy line)
_LIVE: list[tuple] = [
    ("shop", "app/db.py", "def find_user_safe(", "return conn",
     [("app/config.py", "LOG_FORMAT =", None), ("app/util.py", "def utcnow(", "return")], "CWE-89",
     "The helper find_user_safe runs `{quote}`, which sends the caller-supplied name to the database and allows SQL injection.",
     "return conn.execute", ""),
    ("shop", "app/db.py", "def search_orders_safe(", "return conn",
     [("app/util.py", "def human_size(", "return")], "CWE-89",
     "The search term reaches the database through `{quote}`, so a crafted term changes the LIKE query.",
     "return conn.execute", "Secrets are never stored in source code."),
    ("shop", "app/render.py", "def greet_safe(", "return",
     [("app/config.py", "DEBUG =", None), ("app/text.py", "def initials(", "return")], "CWE-79",
     "The page is built by `{quote}`, which writes the query-string name into HTML without encoding.",
     "html.escape", ""),
    ("ops", "ops/shell.py", "def ping_safe(", "return subprocess",
     [("ops/files.py", "BASE =", None), ("ops/net.py", "ALLOWED =", None)], "CWE-78",
     "The host is passed to `{quote}`, so shell metacharacters in it run extra commands.",
     "return subprocess", ""),
    ("ops", "ops/files.py", "def read_upload_safe(", "return handle",
     [("ops/fetch.py", "def preview(", "return requests"), ("ops/net.py", "ALLOWED =", None)], "CWE-22",
     "The upload name is joined to the base directory and `{quote}` does not stop a crafted name from leaving it.",
     "if not path.startswith", ""),
    ("ops", "ops/loader.py", "def load_settings(", "return yaml",
     [("ops/files.py", "BASE =", None), ("ops/fetch.py", "def preview(", "return requests")], "CWE-502",
     "The settings text is deserialized by `{quote}`, which can create arbitrary objects.",
     "return yaml.safe_load", ""),
    ("shop", "app/views.py", "def get_invoice_owned(", "return jsonify(invoice",
     [("app/config.py", "PAGE_SIZE =", None)], "CWE-639",
     "The invoice is fetched by id and `{quote}` is not enough to stop another caller from reading it.",
     "if invoice.owner_id", "Records may be read only by their owner."),
    ("shop", "app/views.py", "/remove", "return \"\", 204",
     [("app/util.py", "def chunk(", "return")], "CWE-862",
     "The removal endpoint is reachable by any caller; `{quote}` does not restrict who may delete users.",
     "@require_role", "Administrative actions require the admin role."),
    ("shop", "app/views.py", "/reports/", "return jsonify(report",
     [("app/util.py", "def human_size(", "return")], "CWE-285",
     "The report is returned to the caller although `{quote}` never checks the report's owner.",
     "if not g.user.can", "Records may be read only by their owner."),
    ("shop", "app/views.py", "methods=[\"PUT\"]", "return jsonify(project",
     [("app/config.py", "DEBUG =", None), ("app/text.py", "def pluralize(", "return")], "CWE-863",
     "The project update trusts `{quote}`, which does not verify that the caller may write this project.",
     "if not g.user.can", "Administrative actions require the admin role."),
]


def load_fixtures() -> list[Fixture]:
    cases = {kind: [(*c[:4], [], *c[4:]) for c in rows] for kind, rows in _CASES.items()}
    cases["live_shaped"] = [(*c[:5], c[5], c[6], c[8]) for c in _LIVE]
    quotes = {i: c[7] for i, c in enumerate(_LIVE)}
    fixtures = []
    for kind, rows in cases.items():
        for number, (repo, path, first, last, extras, cwe, explanation, policy) in enumerate(rows, 1):
            evidence = [_cite(repo, path, first, last)]
            evidence += [_cite(repo, *extra) for extra in extras]
            if kind == "live_shaped":
                quote = next(row.strip() for row in evidence[0].content.splitlines() if quotes[number - 1] in row)
                explanation = explanation.replace("{quote}", quote)
            if policy:
                evidence.append(_policy(policy))
            case_id = f"{kind}-{number:02d}"
            real = kind == CONTROL
            fixtures.append(
                Fixture(
                    case_id=case_id,
                    kind=kind,
                    repo=repo,
                    finding=AgentFinding(
                        finding_id=case_id,
                        cwe_id=cwe,
                        explanation=explanation,
                        evidence=evidence,
                        category="sqli" if cwe == "CWE-89" else "authz" if cwe in _AUTHZ else "other",
                        file=path,
                        line=evidence[0].lines[0],
                    ),
                    verdict="real" if real else "not_real",
                    severity=_SEVERITY[cwe] if real else None,
                    provenance="supported" if kind == CONTROL else "unsupported",
                    tags=(OTHER_FLAW,) if case_id in _OTHER_FLAW_CASES else (),
                )
            )
    return fixtures


def build_repos(root: Path) -> dict[str, Path]:
    """Write each case repository under ``root`` as a one-commit git repository."""
    git = ["git", "-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "-c", "commit.gpgsign=false"]
    paths = {}
    for key, files in REPOS.items():
        repo = Path(root) / key
        for name, text in files.items():
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "case repository"]):
            subprocess.run([*git, *args], cwd=repo, check=True, capture_output=True)
        paths[key] = repo
    return paths
