"""Startup recovery for IP scans orphaned by a restart.

A scan only reaches a terminal state while its worker thread is alive. Stop the
server (Ctrl+C) or let the dev reloader restart it mid-scan and the row keeps
"running" forever: the page shows a phantom active scan, no results and no
reason. Startup must close those rows out, and the shutdown error itself must
be explained in operator terms rather than leaked from the stdlib.
"""
from app import _recover_interrupted_ip_scans
from app.models import IPScan, db


def _mk(target, status, user_id=3):
    return IPScan(target=target, scan_profile="quick", status=status,
                  progress=50, current_step="Scanning", user_id=user_id)


def test_interrupted_scans_are_failed_on_startup(app):
    with app.app_context():
        running = _mk("10.0.0.5", "running")
        pending = _mk("10.0.0.6", "pending")
        done = _mk("10.0.0.7", "completed")
        db.session.add_all([running, pending, done])
        db.session.commit()
        ids = (running.id, pending.id, done.id)

        assert _recover_interrupted_ip_scans(app) == 2

        state = {s.id: s for s in IPScan.query.all()}
        assert state[ids[0]].status == "failed"
        assert state[ids[1]].status == "failed"
        assert state[ids[2]].status == "completed"     # never touched
        for i in ids[:2]:
            row = state[i]
            assert "restarted" in row.error_message
            assert "Start the scan again" in row.error_message
            assert row.current_step == "Interrupted"
            assert row.completed_at is not None


def test_recovery_is_idempotent(app):
    with app.app_context():
        db.session.add(_mk("10.0.0.8", "running"))
        db.session.commit()

        assert _recover_interrupted_ip_scans(app) == 1
        assert _recover_interrupted_ip_scans(app) == 0


def test_worker_explains_the_interpreter_shutdown_error(app, monkeypatch):
    """'cannot schedule new futures' must not reach the operator verbatim."""
    from app.routes import ip_scan as ip_scan_routes

    with app.app_context():
        scan = _mk("8.8.8.8", "pending")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    def boom(*args, **kwargs):
        raise RuntimeError("cannot schedule new futures after interpreter shutdown")

    monkeypatch.setattr(ip_scan_routes.ip_scanner, "scan_network", boom)

    with app.app_context():
        ip_scan_routes._run_ip_scan(scan_id)
        scan = db.session.get(IPScan, scan_id)
        assert scan.status == "failed"
        assert "restarted" in scan.error_message
        assert "cannot schedule new futures" not in scan.error_message
        assert scan.completed_at is not None
