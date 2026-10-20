#!/usr/bin/env python3
"""Generate the 52 benchmark PR patches and labels.json.

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
HUNK_START_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)")


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
    origin: str = "custom"  # "custom" | "owasp-derived"
    context: int = 3  # unified diff context lines (git diff -U)
    delete_files: list[str] = field(default_factory=list)
    new_files: dict[str, str] = field(default_factory=dict)
    edits: list[dict] = field(default_factory=list)  # {"file", "replacements", "append"?}
    location_markers: list[dict] = field(default_factory=list)  # {"file", "old_markers", "new_markers"}
    diff_shape: str | None = None

    @property
    def patch_name(self) -> str:
        num = self.id.split("_")[1]
        variant = self.id.rsplit("_", 1)[1]
        return f"case_{num}_{variant}.patch"

    @property
    def split(self) -> str:
        """Alternate blocks of three pairs between dev and eval (1-3 dev,
        4-6 eval, 7-9 dev, 10-12 eval, ...), with pair 14 in eval. Both
        splits stay balanced because every pair contributes one vulnerable
        and one safe case."""
        num = int(self.id.split("_")[1])
        if num == 14:
            return "eval"
        return "dev" if ((num - 1) % 6) < 3 else "eval"


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
# OWASP-BENCHMARK-DERIVED SQLI PAIRS (CWE-89)
#
# Patterns adapted from the OWASP Benchmark SQLi taxonomy (source x
# propagation x sink) and translated from Java/servlet idioms to
# Python/Flask: header/cookie/body sources, propagation through variable
# chains and clause builders, DB-API / SQLAlchemy sinks.
# ===========================================================================

ORDERS_ADD_ENGINE_IMPORT = (
    "from app.models import Order, get_session",
    "from app.models import Order, get_engine, get_session",
)

# --- Pair 7: header source -> string concat -> DB-API cursor ---------------
CASES.append(Case(
    id="sqli_07_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    origin="owasp-derived",
    replacements=[ORDERS_ADD_ENGINE_IMPORT],
    append='''

@orders_bp.route("/export", methods=["GET"])
@require_role("manager")
def export_orders():
    """Export orders filtered by the X-Report-Filter header."""
    status_filter = request.headers.get("X-Report-Filter", "shipped")
    conn = get_engine().raw_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, user_id, status, total FROM orders WHERE status = '"
            + status_filter + "'"
        )
        rows = cursor.fetchall()
    finally:
        conn.close()
    return jsonify([list(r) for r in rows])
''',
    vuln_markers=["+ status_filter +"],
    description="OWASP-derived: request header concatenated into a DB-API "
                "cursor query.",
))

CASES.append(Case(
    id="sqli_07_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    origin="owasp-derived",
    replacements=[ORDERS_ADD_ENGINE_IMPORT],
    append='''

@orders_bp.route("/export", methods=["GET"])
@require_role("manager")
def export_orders():
    """Export orders filtered by the X-Report-Filter header."""
    status_filter = request.headers.get("X-Report-Filter", "shipped")
    conn = get_engine().raw_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, user_id, status, total FROM orders WHERE status = ?",
            (status_filter,),
        )
        rows = cursor.fetchall()
    finally:
        conn.close()
    return jsonify([list(r) for r in rows])
''',
    description="Same header-driven export with a DB-API placeholder.",
))

# --- Pair 8: cookie source -> f-string -> SQLAlchemy text ------------------
CASES.append(Case(
    id="sqli_08_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/users.py",
    origin="owasp-derived",
    replacements=[USERS_ADD_TEXT_IMPORT],
    append='''

@users_bp.route("/recent-search", methods=["GET"])
@require_auth
def recent_search():
    """Re-run the user's last search stored in a cookie."""
    last_search = request.cookies.get("last_search", "")
    session = get_session()
    rows = session.execute(
        text(f"SELECT id, username FROM users WHERE username LIKE '%{last_search}%'")
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["LIKE '%{last_search}%'"],
    description="OWASP-derived: cookie value interpolated into a LIKE query.",
))

CASES.append(Case(
    id="sqli_08_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/users.py",
    origin="owasp-derived",
    replacements=[USERS_ADD_TEXT_IMPORT],
    append='''

@users_bp.route("/recent-search", methods=["GET"])
@require_auth
def recent_search():
    """Re-run the user's last search stored in a cookie."""
    last_search = request.cookies.get("last_search", "")
    session = get_session()
    rows = session.execute(
        text("SELECT id, username FROM users WHERE username LIKE :pattern"),
        {"pattern": f"%{last_search}%"},
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same cookie-driven search with a bound :pattern parameter.",
))

# --- Pair 9: param -> propagation chain -> IN clause -----------------------
CASES.append(Case(
    id="sqli_09_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    origin="owasp-derived",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/batch-status", methods=["GET"])
@require_role("manager")
def batch_order_status():
    """Fetch the status of several orders by comma-separated ids."""
    raw_ids = request.args.get("ids", "")
    id_list = raw_ids.split(",")
    joined = ", ".join(id_list)
    session = get_session()
    rows = session.execute(
        text("SELECT id, status FROM orders WHERE id IN (" + joined + ")")
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=['IN (" + joined'],
    description="OWASP-derived: parameter propagated through split/join into "
                "an IN clause.",
))

CASES.append(Case(
    id="sqli_09_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    origin="owasp-derived",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/batch-status", methods=["GET"])
@require_role("manager")
def batch_order_status():
    """Fetch the status of several orders by comma-separated ids."""
    raw_ids = request.args.get("ids", "")
    try:
        id_list = [int(part) for part in raw_ids.split(",") if part.strip()]
    except ValueError:
        return jsonify({"error": "ids must be integers"}), 400
    if not id_list:
        return jsonify([])
    params = {f"id{i}": value for i, value in enumerate(id_list)}
    placeholders = ", ".join(":" + key for key in params)
    session = get_session()
    rows = session.execute(
        text("SELECT id, status FROM orders WHERE id IN (" + placeholders + ")"),
        params,
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same IN-clause lookup: ids validated as integers and bound "
                "as named parameters (clause assembly still trips SAST).",
))

# --- Pair 10: numeric-context LIMIT/OFFSET interpolation -------------------
CASES.append(Case(
    id="sqli_10_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/orders.py",
    origin="owasp-derived",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/paged", methods=["GET"])
@require_role("manager")
def paged_orders():
    """List orders with limit/offset pagination."""
    limit = request.args.get("limit", "20")
    offset = request.args.get("offset", "0")
    session = get_session()
    rows = session.execute(
        text(f"SELECT id, user_id, status, total FROM orders LIMIT {limit} OFFSET {offset}")
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["LIMIT {limit} OFFSET {offset}"],
    description="OWASP-derived: pagination parameters interpolated into a "
                "numeric SQL context.",
))

CASES.append(Case(
    id="sqli_10_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/orders.py",
    origin="owasp-derived",
    replacements=[ORDERS_ADD_TEXT_IMPORT],
    append='''

@orders_bp.route("/paged", methods=["GET"])
@require_role("manager")
def paged_orders():
    """List orders with limit/offset pagination."""
    try:
        limit = int(request.args.get("limit", "20"))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400
    session = get_session()
    rows = session.execute(
        text("SELECT id, user_id, status, total FROM orders LIMIT :limit OFFSET :offset"),
        {"limit": limit, "offset": offset},
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same pagination with int() validation and bound parameters.",
))

# --- Pair 11: JSON body source -> %-format -> exec_driver_sql --------------
CASES.append(Case(
    id="sqli_11_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/admin.py",
    origin="owasp-derived",
    replacements=ADMIN_SQLI_IMPORTS,
    append='''

@admin_bp.route("/purge-user", methods=["POST"])
@require_role("admin")
def purge_user_data():
    """Purge a departed user's orders (data-erasure request)."""
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    engine = get_engine()
    with engine.connect() as conn:
        conn.exec_driver_sql(
            "DELETE FROM orders WHERE user_id = "
            "(SELECT id FROM users WHERE username = '%s')" % username
        )
        conn.commit()
    return jsonify({"status": "purged"})
''',
    vuln_markers=["= '%s')\" % username"],
    description="OWASP-derived: JSON body value %-formatted into a driver "
                "SQL delete.",
))

CASES.append(Case(
    id="sqli_11_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/admin.py",
    origin="owasp-derived",
    replacements=ADMIN_SQLI_IMPORTS,
    append='''

@admin_bp.route("/purge-user", methods=["POST"])
@require_role("admin")
def purge_user_data():
    """Purge a departed user's orders (data-erasure request)."""
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    engine = get_engine()
    with engine.connect() as conn:
        conn.exec_driver_sql(
            "DELETE FROM orders WHERE user_id = "
            "(SELECT id FROM users WHERE username = ?)",
            (username,),
        )
        conn.commit()
    return jsonify({"status": "purged"})
''',
    description="Same purge using a driver-level placeholder parameter.",
))

# --- Pair 12: parameter map -> WHERE-clause builder -------------------------
CASES.append(Case(
    id="sqli_12_vulnerable",
    category="sqli",
    expected_verdict="vulnerable",
    cwe="CWE-89",
    file="app/routes/users.py",
    origin="owasp-derived",
    replacements=[USERS_ADD_TEXT_IMPORT],
    append='''

@users_bp.route("/filter", methods=["GET"])
@require_role("manager")
def filter_users():
    """Filter users by arbitrary field=value query parameters."""
    clauses = []
    for field, value in request.args.items():
        clauses.append(f"{field} = '{value}'")
    where = " AND ".join(clauses) or "1=1"
    session = get_session()
    rows = session.execute(
        text("SELECT id, username, role FROM users WHERE " + where)
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    vuln_markers=["f\"{field} = '{value}'\""],
    description="OWASP-derived: request parameter map folded into a WHERE "
                "clause (both identifiers and values attacker-controlled).",
))

CASES.append(Case(
    id="sqli_12_safe",
    category="sqli",
    expected_verdict="safe",
    cwe="CWE-89",
    file="app/routes/users.py",
    origin="owasp-derived",
    replacements=[USERS_ADD_TEXT_IMPORT],
    append='''

ALLOWED_FILTER_FIELDS = {"username", "role", "email"}


@users_bp.route("/filter", methods=["GET"])
@require_role("manager")
def filter_users():
    """Filter users by allowlisted field=value query parameters."""
    clauses = []
    params = {}
    for field, value in request.args.items():
        if field not in ALLOWED_FILTER_FIELDS:
            return jsonify({"error": "cannot filter on that field"}), 400
        clauses.append(f"{field} = :{field}")
        params[field] = value
    where = " AND ".join(clauses) or "1=1"
    session = get_session()
    rows = session.execute(
        text("SELECT id, username, role FROM users WHERE " + where),
        params,
    )
    return jsonify([dict(r._mapping) for r in rows])
''',
    description="Same filter: field names allowlisted, values bound as named "
                "parameters (clause assembly still trips SAST).",
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


def edit_file(tmp: Path, case_id: str, file: str,
              replacements: list[tuple[str, str]], append: str) -> None:
    target = tmp / file
    content = target.read_text(encoding="utf-8")
    for old, new in replacements:
        if old not in content:
            raise RuntimeError(f"{case_id}: replacement anchor not found: {old!r}")
        content = content.replace(old, new, 1)
    if append:
        content = content.rstrip("\n") + "\n" + append.lstrip("\n")
        if not content.endswith("\n"):
            content += "\n"
    target.write_text(content, encoding="utf-8")


def apply_case(tmp: Path, case: Case) -> str:
    """Apply a case's edits in tmp and return the git diff."""
    for rel in case.delete_files:
        (tmp / rel).unlink()
    for rel, content in case.new_files.items():
        path = tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    edit_file(tmp, case.id, case.file, case.replacements, case.append)
    for edit in case.edits:
        edit_file(tmp, case.id, edit["file"],
                  edit.get("replacements", []), edit.get("append", ""))
    if case.delete_files or case.new_files:
        # Untracked new files only appear in the diff once staged.
        run(["git", "add", "-A"], tmp)
        diff = run(["git", "diff", "--cached", "--no-color", "--no-renames",
                    f"-U{case.context}"], tmp)
        run(["git", "reset", "-q", "--hard"], tmp)
        run(["git", "clean", "-fdq"], tmp)
    else:
        diff = run(["git", "diff", "--no-color", f"-U{case.context}"], tmp)
        run(["git", "checkout", "-q", "--", "."], tmp)
    if not diff.strip():
        raise RuntimeError(f"{case.id}: produced an empty diff")
    return diff


def side_lines(diff: str, file: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """Removed (old-side) and added (new-side) lines of ``file`` as (line number, text)."""
    removed: list[tuple[int, str]] = []
    added: list[tuple[int, str]] = []
    selected = in_hunk = False
    old_no = new_no = 0
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            selected = raw == f"diff --git a/{file} b/{file}"
            in_hunk = False
            continue
        start = HUNK_START_RE.match(raw)
        if start:
            in_hunk = True
            old_no, new_no = int(start.group(1)), int(start.group(2))
            continue
        if not (selected and in_hunk):
            continue
        if raw.startswith("-"):
            removed.append((old_no, raw[1:]))
            old_no += 1
        elif raw.startswith("+"):
            added.append((new_no, raw[1:]))
            new_no += 1
        elif raw.startswith(" ") or raw == "":
            old_no += 1
            new_no += 1
    return removed, added


def marker_range(case_id: str, side: list[tuple[int, str]],
                 markers: list[str]) -> list[int] | None:
    if not markers:
        return None
    numbers: list[int] = []
    for marker in markers:
        matched = [number for number, text in side if marker in text]
        if not matched:
            raise RuntimeError(f"{case_id}: location marker not found: {marker}")
        numbers.extend(matched)
    return [min(numbers), max(numbers)]


def location_label(case_id: str, diff: str, location: dict) -> dict:
    removed, added = side_lines(diff, location["file"])
    return {
        "file": location["file"],
        "old_range": marker_range(case_id, removed, location.get("old_markers", [])),
        "new_range": marker_range(case_id, added, location.get("new_markers", [])),
    }


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
            vuln_locations = [
                location_label(case.id, diff, loc) for loc in case.location_markers
            ]
            if case.expected_verdict == "vulnerable" and not (vuln_lines or vuln_locations):
                raise RuntimeError(f"{case.id}: no vulnerable lines or locations matched markers")
            entry = {
                "id": case.id,
                "category": case.category,
                "split": case.split,
                "origin": case.origin,
                "expected_verdict": case.expected_verdict,
                "cwe": case.cwe,
                "file": case.file,
                "vulnerable_lines": vuln_lines,
                "patch_file": f"cases/{case.category}/{case.patch_name}",
                "description": case.description,
            }
            if case.diff_shape:
                entry["diff_shape"] = case.diff_shape
            if vuln_locations:
                entry["vulnerable_locations"] = vuln_locations
            labels["cases"].append(entry)
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
