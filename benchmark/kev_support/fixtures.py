"""Authored fixtures for the Kev validation benchmark: two small case repositories and 45 findings
(6 wrong findings in each of 5 kinds, 15 correct controls) that cite them."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from lgtm.agents.base import AgentFinding, EvidenceItem

KINDS = ("safe_twin", "unrelated_code", "missing_check", "sqli_no_sql", "wrong_cwe")
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
        "ops/fetch.py": '''import requests


def preview(url):
    return requests.get(url, timeout=5).text
''',
    },
}

POLICY = "docs/security.md"
_AUTHZ = {"CWE-285", "CWE-287", "CWE-306", "CWE-639", "CWE-862", "CWE-863"}


@dataclass
class Fixture:
    case_id: str
    kind: str
    repo: str
    finding: AgentFinding


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
    ],
}


def load_fixtures() -> list[Fixture]:
    fixtures = []
    for kind, cases in _CASES.items():
        for number, (repo, path, first, last, cwe, explanation, policy) in enumerate(cases, 1):
            evidence = [_cite(repo, path, first, last)]
            if policy:
                evidence.append(_policy(policy))
            case_id = f"{kind}-{number:02d}"
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
