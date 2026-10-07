"""Per-user data scoping for the JSON APIs.

Every list and detail query is limited to the account that owns the row, so a
new user starts with an empty workspace and can never see another account's
scans, findings, reports or network scans.

Rows created before accounts owned their data carry ``user_id IS NULL``. They
belong to nobody and stay invisible rather than being shared with everyone.
"""
from flask_login import current_user


def user_id():
    """The signed-in account's id, or ``None`` when unauthenticated."""
    row = getattr(current_user, "row", None)
    return row.id if row is not None else None


def owns(record, attr="user_id"):
    """True when ``record`` exists and belongs to the signed-in account."""
    return record is not None and getattr(record, attr, None) == user_id()
