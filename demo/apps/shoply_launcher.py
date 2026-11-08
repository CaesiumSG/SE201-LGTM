"""Run shoply from a workspace copy, with demo data, for the Workspace's App mode.

Usage: shoply_launcher.py <workspace dir> <data dir> <port>

The database lives in <data dir>, never in the workspace, and no bytecode is written there either
(PYTHONDONTWRITEBYTECODE), so running the app leaves the working tree untouched. The data is reset on
every start. One extra route, /__lgtm/routes, lists what the code in the workspace serves, so the
storefront shows only the features that exist.
"""

from __future__ import annotations

import os
import sys

workspace, data, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.makedirs(data, exist_ok=True)
db = os.path.join(data, "shoply.db")
if os.path.exists(db):
    os.remove(db)
os.chdir(data)                       # app.main creates sqlite:///shoply.db relative to the working directory
sys.path.insert(0, workspace)

from flask import jsonify  # noqa: E402

from app.main import app  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.models import Order, User, get_session  # noqa: E402

PEOPLE = [
    ("alice", "alice@shoply.test", "user"), ("bob", "bob@shoply.test", "user"), ("carol", "carol@shoply.test", "user"),
    ("dave", "dave@shoply.test", "user"), ("maria", "maria@shoply.test", "manager"), ("root", "root@shoply.test", "admin"),
]
ORDERS = [
    ("alice", "shipped", 42.50, "12 Orchard Road, Singapore 238826"),
    ("alice", "pending", 18.90, "12 Orchard Road, Singapore 238826"),
    ("bob", "delivered", 129.00, "7 Marina Boulevard #22-01, Singapore 018980"),
    ("bob", "pending", 64.20, "7 Marina Boulevard #22-01, Singapore 018980"),
    ("carol", "shipped", 15.75, "88 Tampines Ave 5, Singapore 529654"),
    ("dave", "delivered", 230.40, "3 Holland Village Way, Singapore 275749"),
]

s = get_session()
ids = {}
for name, email, role in PEOPLE:
    u = User(username=name, email=email, password_hash=hash_password("demo"), role=role)
    s.add(u)
    s.flush()
    ids[name] = u.id
for name, status, total, address in ORDERS:
    s.add(Order(user_id=ids[name], status=status, total=total, shipping_address=address))
s.commit()


@app.route("/__lgtm/routes")
def _lgtm_routes():
    return jsonify(sorted({f"{m} {r.rule}" for r in app.url_map.iter_rules() for m in r.methods if m in ("GET", "POST", "PUT", "DELETE")}))


app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
