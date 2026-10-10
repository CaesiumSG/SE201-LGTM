"""User management endpoints.

Access rules (see security-policy.md §2 and api-spec.md):
- Users may read and update ONLY their own profile; admins may access any.
- Listing all users requires the manager role or above.
- Deleting users and changing roles requires the admin role.
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from app.auth import is_owner_or_admin, require_auth, require_role
from app.models import User, get_session

users_bp = Blueprint("users", __name__)


@users_bp.route("", methods=["GET"])
@require_role("manager")
def list_users():
    """List all users. Managers and admins only."""
    session = get_session()
    users = session.query(User).order_by(User.id).all()
    return jsonify([u.to_dict() for u in users])


@users_bp.route("/<int:user_id>", methods=["GET"])
@require_auth
def get_user(user_id: int):
    """Fetch a user profile. Owner or admin only."""
    if not is_owner_or_admin(g.current_user, user_id):
        return jsonify({"error": "forbidden"}), 403
    session = get_session()
    user = session.get(User, user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(user.to_dict(include_email=True))


@users_bp.route("/<int:user_id>", methods=["PUT"])
@require_auth
def update_user(user_id: int):
    """Update profile fields (email, shipping preferences). Owner or admin."""
    if not is_owner_or_admin(g.current_user, user_id):
        return jsonify({"error": "forbidden"}), 403
    session = get_session()
    user = session.get(User, user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    payload = request.get_json(silent=True) or {}
    if "email" in payload:
        user.email = payload["email"]
    session.commit()
    return jsonify(user.to_dict(include_email=True))
