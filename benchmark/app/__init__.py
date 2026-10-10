"""Shoply — benchmark e-commerce API used to evaluate LGTM.

A small Flask application with token authentication, role-based access
control (admin / manager / user), and a mix of SQLAlchemy ORM and raw SQL.
"""

from flask import Flask

from app.models import init_db


def create_app(database_url: str = "sqlite:///shoply.db") -> Flask:
    app = Flask(__name__)
    app.config["DATABASE_URL"] = database_url
    init_db(database_url)

    from app.routes.users import users_bp
    from app.routes.orders import orders_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(users_bp, url_prefix="/users")
    app.register_blueprint(orders_bp, url_prefix="/orders")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    return app
