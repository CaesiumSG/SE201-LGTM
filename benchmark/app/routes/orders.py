"""Order endpoints.

Access rules (see security-policy.md §3 and api-spec.md):
- A user may create orders for themselves and view ONLY their own orders.
- Managers and admins may list all orders; only admins may delete orders.
- All database queries MUST use bound parameters (security-policy.md §5).
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from app.auth import is_owner_or_admin, require_auth, require_role
from app.models import Order, get_session

orders_bp = Blueprint("orders", __name__)


@orders_bp.route("", methods=["POST"])
@require_auth
def create_order():
    """Create an order for the authenticated user."""
    payload = request.get_json(silent=True) or {}
    session = get_session()
    order = Order(
        user_id=g.current_user.id,
        status="pending",
        total=float(payload.get("total", 0.0)),
        shipping_address=payload.get("shipping_address", ""),
    )
    session.add(order)
    session.commit()
    return jsonify(order.to_dict()), 201


@orders_bp.route("/mine", methods=["GET"])
@require_auth
def my_orders():
    """List the authenticated user's own orders."""
    session = get_session()
    orders = (
        session.query(Order)
        .filter(Order.user_id == g.current_user.id)
        .order_by(Order.created_at.desc())
        .all()
    )
    return jsonify([o.to_dict() for o in orders])


@orders_bp.route("/all", methods=["GET"])
@require_role("manager")
def all_orders():
    """List every order. Managers and admins only."""
    session = get_session()
    orders = session.query(Order).order_by(Order.created_at.desc()).all()
    return jsonify([o.to_dict() for o in orders])
