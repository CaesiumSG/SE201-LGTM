#!/usr/bin/env python3
"""Generate the 24 benchmark PR patches and labels.json.

Each case is defined as a set of edits (string replacements and/or an
appended endpoint) against the base Shoply app. Patches are produced by a
real ``git diff`` inside a temp repository, so they are guaranteed to apply
cleanly with ``git apply``. Ground-truth vulnerable line numbers are
derived from the patch itself via per-case marker substrings.

Usage:
    python benchmark/tools/generate_cases.py
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Case:
    id: str  # e.g. "sqli_01_vulnerable"
    category: str  # "sqli" | "authz"
    expected_verdict: str  # "vulnerable" | "safe"
    cwe: str
    file: str  # file the case modifies, relative to benchmark root
    append: str = ""  # code appended to the end of `file`
    replacements: list[tuple[str, str]] = field(default_factory=list)
    vuln_markers: list[str] = field(default_factory=list)
    description: str = ""

    @property
    def patch_name(self) -> str:
        num = self.id.split("_")[1]
        variant = self.id.rsplit("_", 1)[1]
        return f"case_{num}_{variant}.patch"


# ---------------------------------------------------------------------------
# Shared import tweaks
# ---------------------------------------------------------------------------
USERS_ADD_TEXT_IMPORT = (
    "from app.auth import",
    "from sqlalchemy import text\n\nfrom app.auth import",
)
ORDERS_ADD_TEXT_IMPORT = (
    "from app.auth import",
    "from sqlalchemy import text\n\nfrom app.auth import",
)

CASES: list[Case] = []

# ===========================================================================
# SQL INJECTION PAIRS (CWE-89)
# ===========================================================================

# --- Pair 1: raw SQL with f-string vs bound parameter ---------------------
CASES.append(Case(
    id="sqli_01_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/users.py",
    replacements=[USERS_ADD_TEXT_IMPORT],
    append='''

@users_bp.route("/search", methods=["GET"])
@require_role("manager")
def search_users():
    """Search users by username fragment."""
    name = request.args.get("name", "")
    session = get_session()
    rows = session.execute(
        text(f"SELECT id, username, role FROM users WHERE username LIKE '%{name}%'")
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["WHERE username LIKE '%{name}%'"],
    description="Raw SQL built with an f-string from a query parameter.",
))

CASES.append(Case(
    id="sqli_01_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/users.py",
    replacements=[USERS_ADD_TEXT_IMPORT],
    append='''

@users_bp.route("/search", methods=["GET"])
@require_role("manager")
def search_users():
    """Search users by username fragment."""
    name = request.args.get("name", "")
    session = get_session()
    rows = session.execute(
        text("SELECT id, username, role FROM users WHERE username LIKE :pattern"),
        {"pattern": f"%{name}%"},
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same search endpoint with a bound :pattern parameter.",
))

# --- Pair 2: ORM raw query via string concatenation vs bound param --------
CASES.append(Case(
    id="sqli_02_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/by-status", methods=["GET"])
@require_role("manager")
def orders_by_status():
    """List orders filtered by status."""
    status = request.args.get("status", "pending")
    session = get_session()
    query = "SELECT id, user_id, status, total FROM orders WHERE status = '" + status + "'"
    rows = session.execute(text(query))
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["WHERE status = '\" + status"],
    description="ORM raw query assembled by string concatenation.",
))

CASES.append(Case(
    id="sqli_02_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/by-status", methods=["GET"])
@require_role("manager")
def orders_by_status():
    """List orders filtered by status."""
    status = request.args.get("status", "pending")
    session = get_session()
    rows = session.execute(
        text("SELECT id, user_id, status, total FROM orders WHERE status = :status"),
        {"status": status},
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same filter endpoint with a bound :status parameter.",
))

# --- Pair 3: dynamic ORDER BY column vs allowlist --------------------------
CASES.append(Case(
    id="sqli_03_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/sorted", methods=["GET"])
@require_role("manager")
def sorted_orders():
    """List orders sorted by an arbitrary column."""
    sort_by = request.args.get("sort_by", "created_at")
    session = get_session()
    rows = session.execute(
        text(f"SELECT id, user_id, status, total FROM orders ORDER BY {sort_by}")
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["ORDER BY {sort_by}"],
    description="User-controlled column name interpolated into ORDER BY.",
))

CASES.append(Case(
    id="sqli_03_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

ALLOWED_SORT_COLUMNS = {"created_at", "total", "status", "id"}


@orders_bp.route("/sorted", methods=["GET"])
@require_role("manager")
def sorted_orders():
    """List orders sorted by an allowlisted column."""
    sort_by = request.args.get("sort_by", "created_at")
    if sort_by not in ALLOWED_SORT_COLUMNS:
        return jsonify({"error": "invalid sort column"}), 400
    session = get_session()
    rows = session.execute(
        text(f"SELECT id, user_id, status, total FROM orders ORDER BY {sort_by}")
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Dynamic sort column validated against a hard-coded allowlist "
                "(still trips SAST f-string rules — false-positive control).",
))

# --- Pair 4: maintenance procedure with %-format vs DB-API placeholder ----
ADMIN_SQLI_IMPORTS = [
    ("from flask import Blueprint, jsonify",
     "from flask import Blueprint, jsonify, request"),
    ("from app.models import AuditLog, Order, User, get_session",
     "from app.models import AuditLog, Order, User, get_engine, get_session"),
]

CASES.append(Case(
    id="sqli_04_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/admin.py",
    replacements=ADMIN_SQLI_IMPORTS,
    append='''

@admin_bp.route("/maintenance", methods=["POST"])
@require_role("admin")
def run_maintenance():
    """Purge audit-log entries for a user (maintenance procedure)."""
    user_id = request.args.get("user_id", "")
    conn = get_engine().raw_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_log WHERE user_id = %s" % user_id)
        conn.commit()
    finally:
        conn.close()
    return jsonify({"status": "maintenance complete"})
''',
    vuln_markers=['WHERE user_id = %s" % user_id'],
    description="Maintenance procedure call with %-formatted user input.",
))

CASES.append(Case(
    id="sqli_04_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/admin.py",
    replacements=ADMIN_SQLI_IMPORTS,
    append='''

@admin_bp.route("/maintenance", methods=["POST"])
@require_role("admin")
def run_maintenance():
    """Purge audit-log entries for a user (maintenance procedure)."""
    user_id = request.args.get("user_id", "")
    conn = get_engine().raw_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_log WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"status": "maintenance complete"})
''',
    description="Same maintenance procedure with a DB-API placeholder.",
))

# --- Pair 5: search endpoint injection vs proper binding -------------------
CASES.append(Case(
    id="sqli_05_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/search", methods=["GET"])
@require_auth
def search_orders():
    """Search the current user's orders by shipping address."""
    q = request.args.get("q", "")
    session = get_session()
    sql = (
        f"SELECT id, user_id, status, total FROM orders "
        f"WHERE user_id = {g.current_user.id} AND shipping_address LIKE '%{q}%'"
    )
    rows = session.execute(text(sql))
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["shipping_address LIKE '%{q}%'"],
    description="Search endpoint interpolating the query term into SQL.",
))

CASES.append(Case(
    id="sqli_05_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/search", methods=["GET"])
@require_auth
def search_orders():
    """Search the current user's orders by shipping address."""
    q = request.args.get("q", "")
    session = get_session()
    rows = session.execute(
        text(
            "SELECT id, user_id, status, total FROM orders "
            "WHERE user_id = :uid AND shipping_address LIKE :pattern"
        ),
        {"uid": g.current_user.id, "pattern": f"%{q}%"},
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same search endpoint with bound :uid and :pattern.",
))

# --- Pair 6: bulk insert via string-built VALUES vs bound parameter list ---
CASES.append(Case(
    id="sqli_06_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/bulk", methods=["POST"])
@require_role("manager")
def bulk_create_orders():
    """Bulk-import orders from a JSON array."""
    items = request.get_json(silent=True) or []
    session = get_session()
    values = ", ".join(
        "({0}, '{1}', {2})".format(
            item.get("user_id", 0), item.get("status", "pending"), item.get("total", 0.0)
        )
        for item in items
    )
    if values:
        session.execute(text("INSERT INTO orders (user_id, status, total) VALUES " + values))
        session.commit()
    return jsonify({"imported": len(items)}), 201
''',
    vuln_markers=["VALUES \" + values"],
    description="Bulk insert building a VALUES clause from request JSON.",
))

CASES.append(Case(
    id="sqli_06_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/bulk", methods=["POST"])
@require_role("manager")
def bulk_create_orders():
    """Bulk-import orders from a JSON array."""
    items = request.get_json(silent=True) or []
    session = get_session()
    if items:
        session.execute(
            text("INSERT INTO orders (user_id, status, total) VALUES (:user_id, :status, :total)"),
            [
                {
                    "user_id": int(item.get("user_id", 0)),
                    "status": str(item.get("status", "pending")),
                    "total": float(item.get("total", 0.0)),
                }
                for item in items
            ],
        )
        session.commit()
    return jsonify({"imported": len(items)}), 201
''',
    description="Same bulk import using executemany-style bound parameters.",
))

# ===========================================================================
# AUTHORIZATION PAIRS (CWE-639 / CWE-862 / CWE-863)
# ===========================================================================

# --- Pair 1: IDOR on GET /orders/<id> --------------------------------------
CASES.append(Case(
    id="authz_01_vulnerable",
    category="authz",
    expected_verdict="vulnerable",
    cwe="CWE-639",
    file="app/routes/orders.py",
    append='''

@orders_bp.route("/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id: int):
    """Fetch a single order by id."""
    session = get_session()
    order = session.get(Order, order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(order.to_dict())
''',
    vuln_markers=["def get_order", "return jsonify(order.to_dict())"],
    description="Order fetched by user-controlled id without ownership check.",
))

CASES.append(Case(
    id="authz_01_safe",
    category="authz",
    expected_verdict="safe",
    cwe="CWE-639",
    file="app/routes/orders.py",
    append='''

@orders_bp.route("/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id: int):
    """Fetch a single order by id. Owner or admin only."""
    session = get_session()
    order = session.get(Order, order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    if not is_owner_or_admin(g.current_user, order.user_id):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(order.to_dict())
''',
    description="Same endpoint with is_owner_or_admin ownership validation.",
))

# --- Pair 2: DELETE /users/<id> without role check -------------------------
CASES.append(Case(
    id="authz_02_vulnerable",
    category="authz",
    expected_verdict="vulnerable",
    cwe="CWE-862",
    file="app/routes/users.py",
    append='''

@users_bp.route("/<int:user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id: int):
    """Delete a user account."""
    session = get_session()
    user = session.get(User, user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    session.delete(user)
    session.commit()
    return jsonify({"status": "deleted"})
''',
    vuln_markers=["def delete_user", "@require_auth"],
    description="Account deletion gated only on authentication, not the "
                "admin role required by policy.",
))

CASES.append(Case(
    id="authz_02_safe",
    category="authz",
    expected_verdict="safe",
    cwe="CWE-862",
    file="app/routes/users.py",
    append='''

@users_bp.route("/<int:user_id>", methods=["DELETE"])
@require_role("admin")
def delete_user(user_id: int):
    """Delete a user account. Admins only."""
    session = get_session()
    user = session.get(User, user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    session.delete(user)
    session.commit()
    return jsonify({"status": "deleted"})
''',
    description="Same endpoint protected with @require_role('admin').",
))

# --- Pair 3: privilege escalation via role update ---------------------------
CASES.append(Case(
    id="authz_03_vulnerable",
    category="authz",
    expected_verdict="vulnerable",
    cwe="CWE-863",
    file="app/routes/users.py",
    append='''

@users_bp.route("/<int:user_id>/role", methods=["PUT"])
@require_auth
def set_user_role(user_id: int):
    """Update a user's role."""
    payload = request.get_json(silent=True) or {}
    new_role = payload.get("role", "user")
    session = get_session()
    user = session.get(User, user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    user.role = new_role
    session.commit()
    return jsonify(user.to_dict())
''',
    vuln_markers=["def set_user_role", "user.role = new_role"],
    description="Any authenticated user can change roles (including their "
                "own) — privilege escalation.",
))

CASES.append(Case(
    id="authz_03_safe",
    category="authz",
    expected_verdict="safe",
    cwe="CWE-863",
    file="app/routes/users.py",
    append='''

@users_bp.route("/<int:user_id>/role", methods=["PUT"])
@require_role("admin")
def set_user_role(user_id: int):
    """Update a user's role. Admins only; self-promotion is forbidden."""
    if g.current_user.id == user_id:
        return jsonify({"error": "cannot change your own role"}), 403
    payload = request.get_json(silent=True) or {}
    new_role = payload.get("role", "user")
    if new_role not in ("user", "manager", "admin"):
        return jsonify({"error": "invalid role"}), 400
    session = get_session()
    user = session.get(User, user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    user.role = new_role
    session.commit()
    return jsonify(user.to_dict())
''',
    description="Role updates restricted to admins, self-promotion blocked, "
                "role value validated.",
))

# --- Pair 4: horizontal access to another user's orders --------------------
USERS_ADD_ORDER_IMPORT = (
    "from app.models import User, get_session",
    "from app.models import Order, User, get_session",
)

CASES.append(Case(
    id="authz_04_vulnerable",
    category="authz",
    expected_verdict="vulnerable",
    cwe="CWE-639",
    file="app/routes/users.py",
    replacements=[USERS_ADD_ORDER_IMPORT],
    append='''

@users_bp.route("/<int:user_id>/orders", methods=["GET"])
@require_auth
def user_orders(user_id: int):
    """List a user's orders."""
    session = get_session()
    orders = session.query(Order).filter(Order.user_id == user_id).all()
    return jsonify([o.to_dict() for o in orders])
''',
    vuln_markers=["def user_orders", "Order.user_id == user_id"],
    description="Any authenticated user can list any other user's orders.",
))

CASES.append(Case(
    id="authz_04_safe",
    category="authz",
    expected_verdict="safe",
    cwe="CWE-639",
    file="app/routes/users.py",
    replacements=[USERS_ADD_ORDER_IMPORT],
    append='''

@users_bp.route("/<int:user_id>/orders", methods=["GET"])
@require_auth
def user_orders(user_id: int):
    """List a user's orders. Owner or admin only."""
    if not is_owner_or_admin(g.current_user, user_id):
        return jsonify({"error": "forbidden"}), 403
    session = get_session()
    orders = session.query(Order).filter(Order.user_id == user_id).all()
    return jsonify([o.to_dict() for o in orders])
''',
    description="Order listing scoped to the owner or an admin.",
))

# --- Pair 5: admin export with debug-header bypass --------------------------
ADMIN_AUTHZ_VULN_IMPORTS = [
    ("from flask import Blueprint, jsonify",
     "from flask import Blueprint, g, jsonify, request"),
    ("from app.auth import require_role",
     "from app.auth import require_auth, require_role"),
]

CASES.append(Case(
    id="authz_05_vulnerable",
    category="authz",
    expected_verdict="vulnerable",
    cwe="CWE-863",
    file="app/routes/admin.py",
    replacements=ADMIN_AUTHZ_VULN_IMPORTS,
    append='''

@admin_bp.route("/export", methods=["GET"])
@require_auth
def export_data():
    """Export all users and orders as JSON (admin reporting)."""
    user = g.current_user
    if user.role != "admin" and request.headers.get("X-Internal-Debug") != "1":
        return jsonify({"error": "forbidden"}), 403
    session = get_session()
    return jsonify(
        {
            "users": [u.to_dict(include_email=True) for u in session.query(User).all()],
            "orders": [o.to_dict() for o in session.query(Order).all()],
        }
    )
''',
    vuln_markers=['X-Internal-Debug'],
    description="Admin export reachable by any user sending a debug header — "
                "forbidden alternative access path.",
))

CASES.append(Case(
    id="authz_05_safe",
    category="authz",
    expected_verdict="safe",
    cwe="CWE-863",
    file="app/routes/admin.py",
    append='''

@admin_bp.route("/export", methods=["GET"])
@require_role("admin")
def export_data():
    """Export all users and orders as JSON (admin reporting)."""
    session = get_session()
    return jsonify(
        {
            "users": [u.to_dict(include_email=True) for u in session.query(User).all()],
            "orders": [o.to_dict() for o in session.query(Order).all()],
        }
    )
''',
    description="Export guarded by @require_role('admin') with no bypass.",
))

# --- Pair 6: API key accepted without scope check ---------------------------
CASES.append(Case(
    id="authz_06_vulnerable",
    category="authz",
    expected_verdict="vulnerable",
    cwe="CWE-862",
    file="app/routes/orders.py",
    replacements=[(
        "from app.auth import is_owner_or_admin, require_auth, require_role",
        "from app.auth import get_api_key, is_owner_or_admin, require_auth, require_role",
    )],
    append='''

@orders_bp.route("/report", methods=["GET"])
def orders_report():
    """Aggregated order report for machine integrations."""
    key = get_api_key()
    if key is None:
        return jsonify({"error": "valid API key required"}), 401
    session = get_session()
    orders = session.query(Order).all()
    return jsonify(
        {
            "order_count": len(orders),
            "revenue": sum(o.total for o in orders),
            "orders": [o.to_dict() for o in orders],
        }
    )
''',
    vuln_markers=["def orders_report", "key = get_api_key()"],
    description="Report endpoint accepts ANY valid API key regardless of "
                "scope; policy requires reports:read.",
))

CASES.append(Case(
    id="authz_06_safe",
    category="authz",
    expected_verdict="safe",
    cwe="CWE-862",
    file="app/routes/orders.py",
    replacements=[(
        "from app.auth import is_owner_or_admin, require_auth, require_role",
        "from app.auth import is_owner_or_admin, require_api_key_scope, require_auth, require_role",
    )],
    append='''

@orders_bp.route("/report", methods=["GET"])
@require_api_key_scope("reports:read")
def orders_report():
    """Aggregated order report for machine integrations."""
    session = get_session()
    orders = session.query(Order).all()
    return jsonify(
        {
            "order_count": len(orders),
            "revenue": sum(o.total for o in orders),
            "orders": [o.to_dict() for o in orders],
        }
    )
''',
    description="Report endpoint enforces the reports:read API-key scope.",
))


# ---------------------------------------------------------------------------
# Generation machinery
# ---------------------------------------------------------------------------

def run(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stderr}")
    return result.stdout


def build_base_repo(tmp: Path) -> None:
    """Copy the benchmark app + docs into tmp and commit as the base."""
    shutil.copytree(BENCH / "app", tmp / "app")
    for doc in ("security-policy.md", "api-spec.md", "README.md"):
        shutil.copy(BENCH / doc, tmp / doc)
    run(["git", "init", "-q", "-b", "main"], tmp)
    run(["git", "config", "user.email", "bench@lgtm.local"], tmp)
    run(["git", "config", "user.name", "LGTM Bench"], tmp)
    run(["git", "add", "-A"], tmp)
    run(["git", "commit", "-q", "-m", "base"], tmp)


def apply_case(tmp: Path, case: Case) -> str:
    """Apply a case's edits in tmp and return the git diff."""
    target = tmp / case.file
    content = target.read_text(encoding="utf-8")
    for old, new in case.replacements:
        if old not in content:
            raise RuntimeError(f"{case.id}: replacement anchor not found: {old!r}")
        content = content.replace(old, new, 1)
    content = content.rstrip("\n") + "\n" + case.append.lstrip("\n")
    if not content.endswith("\n"):
        content += "\n"
    target.write_text(content, encoding="utf-8")
    diff = run(["git", "diff", "--no-color"], tmp)
    run(["git", "checkout", "-q", "--", "."], tmp)
    if not diff.strip():
        raise RuntimeError(f"{case.id}: produced an empty diff")
    return diff


def vulnerable_lines_from_patch(diff: str, markers: list[str]) -> list[int]:
    """New-file line numbers of added lines matching any marker substring."""
    lines: list[int] = []
    new_lineno = 0
    for raw in diff.splitlines():
        match = HUNK_RE.match(raw)
        if match:
            new_lineno = int(match.group(1))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            content = raw[1:]
            if any(marker in content for marker in markers):
                lines.append(new_lineno)
            new_lineno += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith(" ") or raw == "":
            new_lineno += 1
    return lines


def main() -> None:
    labels = {"cases": []}
    counts = {"sqli": 0, "authz": 0}
    with tempfile.TemporaryDirectory(prefix="lgtm-bench-") as tmpdir:
        tmp = Path(tmpdir)
        build_base_repo(tmp)
        for case in CASES:
            diff = apply_case(tmp, case)
            out_dir = BENCH / "cases" / case.category
            out_dir.mkdir(parents=True, exist_ok=True)
            patch_path = out_dir / case.patch_name
            patch_path.write_text(diff, encoding="utf-8")
            vuln_lines = (
                vulnerable_lines_from_patch(diff, case.vuln_markers)
                if case.vuln_markers
                else []
            )
            if case.expected_verdict == "vulnerable" and not vuln_lines:
                raise RuntimeError(f"{case.id}: no vulnerable lines matched markers")
            labels["cases"].append(
                {
                    "id": case.id,
                    "category": case.category,
                    "expected_verdict": case.expected_verdict,
                    "cwe": case.cwe,
                    "file": case.file,
                    "vulnerable_lines": vuln_lines,
                    "patch_file": f"cases/{case.category}/{case.patch_name}",
                    "description": case.description,
                }
            )
            counts[case.category] += 1
            print(f"  wrote {patch_path.relative_to(BENCH)} "
                  f"({len(vuln_lines)} labeled lines)")

    (BENCH / "labels.json").write_text(
        json.dumps(labels, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Generated {counts['sqli']} sqli + {counts['authz']} authz cases; "
          f"labels.json updated.")


if __name__ == "__main__":
    main()
