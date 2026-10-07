"""Host discovery must not require the classic web/SSH ports.

Regression: a host whose only open service was RDP (3389), a proxy (8080) or a
database was judged "down", so scanning "another IP" returned nothing even
though the host was reachable.
"""
from app.services.engines import ip_scanner


class _FakeSocket:
    def __init__(self, *args, **kwargs):
        pass

    def settimeout(self, _timeout):
        pass

    def connect_ex(self, address):
        _ip, port = address
        return 0 if port == self.open_port else 111

    def close(self):
        pass


def test_host_is_alive_when_only_rdp_is_open(monkeypatch):
    class RdpSocket(_FakeSocket):
        open_port = 3389

    monkeypatch.setattr(ip_scanner.socket, "socket", lambda *a, **k: RdpSocket())

    # 3389 is not one of the old four-port list (80/443/22/445).
    assert ip_scanner._is_host_alive("10.0.0.9", timeout=0.01) is True


def test_discovery_covers_services_beyond_the_web_ports():
    for port in (3389, 8080, 3306, 5432, 6379):
        assert port in ip_scanner.DISCOVERY_PORTS


# ------------------------------------------------------- scanning itself ---
# Regression: the parallel port-scan loop collected into `open_ports` before
# that list was created, so any host that really had an open port raised
# NameError. The worker thread then marked the whole scan failed and the UI
# showed no results at all - which is what "I scanned another IP and saw
# nothing" looked like. A host with an open port must come back as a result.

def _fake_socket_module(open_port):
    class HostSocket(_FakeSocket):
        pass

    HostSocket.open_port = open_port
    return HostSocket


def _stub_network(monkeypatch, open_port):
    """Patch every socket call the single-host scan makes."""
    host_socket = _fake_socket_module(open_port)
    monkeypatch.setattr(ip_scanner.socket, "socket", lambda *a, **k: host_socket())
    monkeypatch.setattr(ip_scanner.socket, "gethostbyaddr",
                        lambda *a, **k: ("scanned-host.local", [], []))


def test_scan_ip_target_reports_the_open_port(monkeypatch):
    _stub_network(monkeypatch, 8080)

    host, findings = ip_scanner.scan_ip_target("10.0.0.9", [8080], {})

    assert host["status"] == "up"
    assert host["open_ports"] == [8080]
    assert host["open_ports_count"] == 1
    assert [s["port"] for s in host["services"]] == [8080]


def test_scan_network_returns_the_host_it_found(monkeypatch):
    """The user-visible path: scan a single IP, get a host back."""
    _stub_network(monkeypatch, 8080)

    results, summary = ip_scanner.scan_network(
        "10.0.0.9", {"scan_profile": "quick"}, progress_cb=lambda p, l: None)

    assert [h["ip_address"] for h in results] == ["10.0.0.9"]
    assert results[0]["status"] == "up"
    assert summary["hosts_discovered"] == 1
    assert summary["open_ports"] == 1


def test_scan_network_reports_an_insecure_service(monkeypatch):
    """An open Telnet port must reach the results as a finding."""
    _stub_network(monkeypatch, 23)

    results, summary = ip_scanner.scan_network(
        "10.0.0.9", {"scan_profile": "quick"}, progress_cb=lambda p, l: None)

    names = [f["name"] for f in results[0]["findings"]]
    assert "Telnet Service Running (Insecure)" in names
    assert results[0]["risk_level"] == "high"
    assert summary["vulnerabilities"] >= 1


def test_scan_network_reports_a_filtered_host_as_not_found(monkeypatch):
    """A host that answers nothing is 'no hosts found' - never a crash."""
    _stub_network(monkeypatch, None)          # every port refused

    results, summary = ip_scanner.scan_network(
        "10.0.0.9", {"scan_profile": "quick"}, progress_cb=lambda p, l: None)

    assert results == []
    assert summary["hosts_discovered"] == 0
