"""Deleting a scan must not poison the next scan that reuses its id.

``DELETE /api/scans/<id>`` calls ``request_cancel()`` even when no worker is
running. The flag used to be stored unconditionally and was only ever cleared
by a worker thread, so it lingered -- and because SQLite reuses the primary key
of a deleted row, the next scan started by the user inherited the flag and was
cancelled before it did any work (``Scan cancelled by user``, zero findings).
"""
import time

from app.services import scanner


def _add_idle_scan(app, url="http://127.0.0.1:9"):
    """Insert a scan row that has no worker thread attached to it."""
    from app.extensions import db
    from app.models import Scan

    with app.app_context():
        scan = Scan(target_url=url, scan_type="quick", status="completed",
                    progress=100, options={}, current_step="done")
        db.session.add(scan)
        db.session.commit()
        return scan.id


def test_deleting_an_idle_scan_leaves_no_cancellation_flag(app, auth_client):
    """The regression: the flag outlives the scan it belonged to."""
    scan_id = _add_idle_scan(app)

    resp = auth_client.delete(f"/api/scans/{scan_id}")
    assert resp.status_code == 200, resp.get_data(as_text=True)

    assert scanner.is_cancelled(scan_id) is False, (
        "a cancellation flag was left behind for a scan with no worker")


def test_new_scan_is_not_cancelled_by_a_deleted_one(app, auth_client):
    """End to end: delete a scan, start another, and it must actually run."""
    deleted_id = _add_idle_scan(app)
    assert auth_client.delete(f"/api/scans/{deleted_id}").status_code == 200

    body = {"target_url": "http://127.0.0.1:9", "scan_type": "quick",
            "policy": "safe", "authorized": "true"}
    resp = auth_client.post("/api/scans", json=body)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    scan_id = resp.get_json()["scan"]["id"]

    # SQLite hands the freed primary key to the new row -- that is precisely
    # how the stale flag reached an unrelated scan.
    assert scan_id == deleted_id, "expected the deleted id to be reused"
    assert scanner.is_cancelled(scan_id) is False, (
        "the new scan started out already cancelled")

    deadline = time.time() + 60
    status = None
    while time.time() < deadline:
        status = auth_client.get(f"/api/scans/{scan_id}").get_json()["scan"]["status"]
        if status in ("completed", "failed", "cancelled"):
            break
        time.sleep(1)

    assert status != "cancelled", "a stale cancellation flag killed the new scan"
    auth_client.delete(f"/api/scans/{scan_id}")


def test_ip_scan_delete_leaves_no_cancellation_flag(app, auth_client):
    """The IP scanner keeps its own flag and had the same defect."""
    from app.extensions import db
    from app.models import IPScan

    with app.app_context():
        scan = IPScan(target="127.0.0.1", scan_profile="quick", status="completed",
                      scan_number=99, options={})
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    from app.routes import ip_scan as ip_scan_module
    assert auth_client.delete(f"/api/ip-scan/{scan_id}").status_code == 200
    assert scan_id not in ip_scan_module._cancelled, (
        "an IP-scan cancellation flag was left behind")
