"""Shared Flask extension singletons."""
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")
login_manager = LoginManager()
# Must point at the login *page* (GET /login); "auth.login" is the POST-only
# JSON API and would 405 unauthenticated page visits instead of showing the form.
login_manager.login_view = "auth.login_page"
login_manager.login_message = "Please sign in to access WSA."
login_manager.login_message_category = "warn"
