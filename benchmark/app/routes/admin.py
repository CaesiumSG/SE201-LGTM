"""Admin panel endpoints.

Access rules (see security-policy.md §4 and api-spec.md):
- EVERY endpoint under /admin requires the admin role via
  @require_role("admin"). No exceptions, no alternative shortcuts.
"""

from __future__ import annotations

from flask import Blueprint, jsonify

from app.auth import require_role
from app.models import AuditLog, Order, User, get_session

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/stats", methods=["GET"])
@require_role("admin")
def stats():
    """Aggregate platform statistics."""
    session = get_session()
    return jsonify(
        {
            "users": session.query(User).count(),
            "orders": session.query(Order).count(),
            "audit_events": session.query(AuditLog).count(),
        }
    )


@admin_bp.route("/audit", methods=["GET"])
@require_role("admin")
def audit_log():
    """Most recent audit log entries."""
    session = get_session()
    events = (
        session.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    )
    return jsonify(
        [
            {"id": e.id, "user_id": e.user_id, "action": e.action}
            for e in events
        ]
    )
