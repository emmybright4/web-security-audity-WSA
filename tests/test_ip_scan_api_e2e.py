"""End-to-end IP scan through the real API.

Starts a scan on the machine's own loopback interface, waits for the worker to
finish and reads the results back - the exact path a user follows: without the
results endpoints working this is what "I scanned an IP but saw nothing" means.
"""
import time


def test_ip_scan_end_to_end(auth_client, app, default_user_id):
    """Start a real IP scan from the API and read the results back."""
    resp = auth_client.post("/api/ip-scan", json={
        "target": "127.0.0.1", "scan_profile": "quick", "authorized": "true",
    })
    assert resp.status_code == 201, resp.get_data(as_text=True)
    scan_id = resp.get_json()["scan"]["id"]

    status = "pending"
    detail = None
    deadline = time.time() + 90
    while time.time() < deadline:
        detail = auth_client.get(f"/api/ip-scan/{scan_id}").get_json()
        status = detail["scan"]["status"]
        if status in ("completed", "failed", "cancelled"):
            break
        time.sleep(1)

    assert status == "completed", detail["scan"].get("error_message")
    assert detail["hosts"], "no hosts returned"
    assert detail["hosts"][0]["status"] == "up"

    ports = auth_client.get(f"/api/ip-scan/{scan_id}/ports").get_json()["ports"]
    assert ports, "no open ports stored"

    hist = auth_client.get("/api/ip-scan/history").get_json()["scans"]
    assert scan_id in [s["id"] for s in hist]
