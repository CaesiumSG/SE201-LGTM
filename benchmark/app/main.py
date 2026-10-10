"""Shoply entry point: `python -m app.main` starts the dev server."""

from __future__ import annotations

from flask import jsonify, request

from app import create_app
from app.auth import hash_password, issue_token
from app.models import User, get_session

app = create_app()


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")
    session = get_session()
    user = session.query(User).filter(User.username == username).first()
    if user is None or user.password_hash != hash_password(password):
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": issue_token(user), "user": user.to_dict()})


if __name__ == "__main__":
    app.run(debug=False, port=5001)
