"""Authentication and authorization helpers for Shoply.

Every protected endpoint MUST use these decorators (see
security-policy.md). Token auth uses an opaque bearer token stored against
the user; API-key auth is for machine integrations and is scope-checked.
"""

from __future__ import annotations

import functools
import hashlib
import secrets

from flask import g, jsonify, request

from app.models import ApiKey, User, get_session

# In-memory token store: token -> user_id (reset on restart; fine for demo)
_TOKENS: dict[str, int] = {}

ROLE_RANK = {"user": 1, "manager": 2, "admin": 3}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def issue_token(user: User) -> str:
    token = secrets.token_hex(32)
    _TOKENS[token] = user.id
    return token


def get_current_user() -> User | None:
    """Resolve the user from the Authorization: Bearer <token> header."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[len("Bearer "):].strip()
    user_id = _TOKENS.get(token)
    if user_id is None:
        return None
    return get_session().get(User, user_id)


def get_api_key() -> ApiKey | None:
    """Resolve an API key from the X-Api-Key header."""
    raw = request.headers.get("X-Api-Key", "")
    if not raw:
        return None
    session = get_session()
    return session.query(ApiKey).filter(ApiKey.key == raw).first()


def require_auth(fn):
    """Reject the request unless a valid user token is presented."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return jsonify({"error": "authentication required"}), 401
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def require_role(minimum_role: str):
    """Require at least the given role (user < manager < admin)."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if user is None:
                return jsonify({"error": "authentication required"}), 401
            if ROLE_RANK.get(user.role, 0) < ROLE_RANK.get(minimum_role, 99):
                return jsonify({"error": "insufficient role"}), 403
            g.current_user = user
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_api_key_scope(required_scope: str):
    """Require an API key carrying exactly the given scope."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = get_api_key()
            if key is None:
                return jsonify({"error": "valid API key required"}), 401
            if key.scope != required_scope:
                return jsonify({"error": "API key lacks required scope"}), 403
            g.api_key = key
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def is_owner_or_admin(user: User, owner_id: int) -> bool:
    """Ownership check used for per-object access (orders, profiles)."""
    return user.id == owner_id or user.role == "admin"
