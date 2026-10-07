"""The Findings API must list network (IP scan) findings together with web ones.

Before the fix, ``/api/vulnerabilities`` only read the ``vulnerabilities`` table,
so findings produced by IP scans never appeared on the Findings page.
"""
import pytest


def _add_network_finding(app, ip="192.168.1.50", name="SMB Service Exposed"):
    """Insert a completed IP scan with one high-severity finding."""
    from app.extensions import db
    from app.models import IPScan, IPScanHost, IPScanVulnerability, User

    with app.app_context():
        owner = User.query.filter_by(email="emmy.bright@wsa.local").first()
        scan = IPScan(target=ip, scan_profile="quick", status="completed",
                      scan_number=1, vulnerabilities_count=1, high_count=1,
                      user_id=owner.id)
        db.session.add(scan)
        db.session.flush()

        host = IPScanHost(scan_id=scan.id, ip_address=ip)
        db.session.add(host)
        db.session.flush()

        vuln = IPScanVulnerability(
            scan_id=scan.id, host_id=host.id, name=name,
            vuln_type="insecure_services", severity="high", host_ip=ip,
            port=445, service="smb", recommendation="Disable SMBv1.")
        db.session.add(vuln)
        db.session.commit()
        return scan.id, vuln.id


def _add_web_finding(app, name="Missing CSP Header"):
    from app.extensions import db
    from app.models import Scan, User, Vulnerability

    with app.app_context():
        owner = User.query.filter_by(email="emmy.bright@wsa.local").first()
        scan = Scan(target_url="https://example.test", scan_type="quick",
                    status="completed", user_id=owner.id)
        db.session.add(scan)
        db.session.flush()
        vuln = Vulnerability(name=name, severity="medium", status="open",
                             scan_id=scan.id, target_url="https://example.test")
        db.session.add(vuln)
        db.session.commit()
        return vuln.id


def test_list_merges_network_and_web_findings(app, auth_client):
    _add_web_finding(app)
    _, net_id = _add_network_finding(app)

    data = auth_client.get("/api/vulnerabilities").get_json()
    sources = {v["source"] for v in data["vulnerabilities"]}
    assert {"web", "network"} <= sources
    assert data["count"] == len(data["vulnerabilities"])
    assert any(v["id"] == net_id and v["source"] == "network"
               for v in data["vulnerabilities"])


def test_network_finding_is_normalized_for_the_ui(app, auth_client):
    _, net_id = _add_network_finding(app)
    data = auth_client.get(f"/api/vulnerabilities?limit=1000").get_json()
    v = next(x for x in data["vulnerabilities"]
             if x["source"] == "network" and x["id"] == net_id)

    assert v["target_url"] == "192.168.1.50"
    assert v["url"] == "192.168.1.50:445"
    assert v["remediation"] == "Disable SMBv1."  # mapped from `recommendation`
    assert v["port"] == 445 and v["host_ip"] == "192.168.1.50"


def test_target_filter_and_target_list_include_network_targets(app, auth_client):
    _add_network_finding(app, ip="10.0.0.7")
    assert "10.0.0.7" in auth_client.get("/api/vulnerabilities/targets").get_json()["targets"]

    data = auth_client.get("/api/vulnerabilities?target=10.0.0.7").get_json()
    assert data["count"] == 1
    assert data["vulnerabilities"][0]["source"] == "network"


def test_severity_high_includes_network_high(app, auth_client):
    _add_network_finding(app)
    data = auth_client.get("/api/vulnerabilities?severity=high&limit=1000").get_json()
    assert any(v["source"] == "network" for v in data["vulnerabilities"])


def test_get_and_update_network_finding_by_source(app, auth_client):
    _, net_id = _add_network_finding(app)

    got = auth_client.get(f"/api/vulnerabilities/{net_id}?source=network").get_json()
    assert got["vulnerability"]["source"] == "network"

    resp = auth_client.patch(f"/api/vulnerabilities/{net_id}?source=network",
                             json={"status": "resolved", "notes": "ignored"})
    assert resp.status_code == 200
    assert resp.get_json()["vulnerability"]["status"] == "resolved"

    # the same numeric id on the web table is a different resource
    assert auth_client.get(f"/api/vulnerabilities/{net_id}").status_code == 404


def test_delete_network_finding_by_source(app, auth_client):
    _, net_id = _add_network_finding(app)
    assert auth_client.delete(f"/api/vulnerabilities/{net_id}?source=network").status_code == 200
    assert auth_client.get(f"/api/vulnerabilities/{net_id}?source=network").status_code == 404


def test_list_requires_authentication(client):
    assert client.get("/api/vulnerabilities").status_code == 401


def test_limit_keeps_the_newest_findings(app, auth_client):
    """Regression: the limit used to be applied per source table *before* the two
    lists were merged, and the database returned rows oldest-first -- so a small
    limit silently kept ancient findings and dropped every fresh scan result.
    """
    from datetime import datetime, timedelta

    from app.extensions import db
    from app.models import Scan, User, Vulnerability

    with app.app_context():
        owner = User.query.filter_by(email="emmy.bright@wsa.local").first()
        scan = Scan(target_url="https://ordered.test", scan_type="quick",
                    status="completed", user_id=owner.id)
        db.session.add(scan)
        db.session.flush()
        base = datetime(2026, 1, 1, 12, 0, 0)
        for i in range(30):
            db.session.add(Vulnerability(
                scan_id=scan.id,
                name="Finding %02d" % i, severity="low", status="open",
                target_url="https://ordered.test",
                created_at=base + timedelta(minutes=i)))
        db.session.commit()

    data = auth_client.get("/api/vulnerabilities?limit=5").get_json()
    names = [v["name"] for v in data["vulnerabilities"]]

    assert data["count"] == 5
    assert data["total"] == 30
    assert names == ["Finding 29", "Finding 28", "Finding 27",
                     "Finding 26", "Finding 25"], names
