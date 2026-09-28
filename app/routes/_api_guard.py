"""Shared guard for JSON API endpoints: return 401 JSON when not signed in."""
from functools import wraps

from flask import jsonify
from flask_login import current_user


def api_login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify(error="Authentication required. Please sign in."), 401
        return fn(*args, **kwargs)
    return wrapper
