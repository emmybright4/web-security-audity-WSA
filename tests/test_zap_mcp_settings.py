"""ZAP-MCP must be configurable from Settings, and empty means "off".

Regression: ``ZAP_MCP_URL`` was documented in the README and the Engine
Configuration table, but it was never read out of ``.env`` and had no Settings
field, so the ZAP-MCP card's Configuration button landed on the OWASP ZAP card
with nothing to fill in. Saving the field also has to mean something distinct
from "never saved": clearing it must switch the card back to native ZAP API
mode instead of silently resurrecting the old ``.env`` value.
"""


def test_mcp_url_is_loaded_from_env(app):
    from config import Config

    assert hasattr(Config, "ZAP_MCP_URL"), "ZAP_MCP_URL is documented but never loaded"


def test_settings_requires_sign_in(client):
    assert client.get("/api/settings").status_code == 401
    assert client.post("/api/settings/zap-mcp/test", json={}).status_code == 401


def test_saved_mcp_url_overrides_env_and_takes_effect(app, auth_client):
    resp = auth_client.put("/api/settings", json={"zap_mcp_url": "http://127.0.0.1:9999"})
    assert resp.status_code == 200, resp.get_data(as_text=True)

    assert app.config["ZAP_MCP_URL"] == "http://127.0.0.1:9999"

    settings = auth_client.get("/api/settings").get_json()["settings"]
    assert settings["zap_mcp_url"] == "http://127.0.0.1:9999"


def test_clearing_mcp_url_turns_the_endpoint_off(app, auth_client):
    """An empty saved value is explicit "native mode", not "fall back to .env"."""
    auth_client.put("/api/settings", json={"zap_mcp_url": "http://127.0.0.1:9999"})
    resp = auth_client.put("/api/settings", json={"zap_mcp_url": ""})
    assert resp.status_code == 200, resp.get_data(as_text=True)

    assert app.config["ZAP_MCP_URL"] == ""
    settings = auth_client.get("/api/settings").get_json()["settings"]
    assert settings["zap_mcp_url"] == ""


def test_mcp_url_defaults_to_env_when_never_saved(app, auth_client):
    settings = auth_client.get("/api/settings").get_json()["settings"]
    assert settings["zap_mcp_url"] == app.config.get("ZAP_MCP_URL", "")


def test_mcp_test_endpoint_probes_the_submitted_url(app, auth_client, monkeypatch):
    from app.services.engines import zap_mcp

    seen = {}

    def fake_availability(config):
        seen["url"] = (config.get("ZAP_MCP_URL") or "").strip()
        return True, "MCP endpoint reachable at " + seen["url"]

    monkeypatch.setattr(zap_mcp, "availability", fake_availability)

    resp = auth_client.post("/api/settings/zap-mcp/test",
                            json={"zap_mcp_url": "http://127.0.0.1:8090/"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    # trailing slash is normalised exactly like zap_api_url
    assert seen["url"] == "http://127.0.0.1:8090"


def test_mcp_test_endpoint_falls_back_to_the_saved_url(app, auth_client, monkeypatch):
    from app.services.engines import zap_mcp

    auth_client.put("/api/settings", json={"zap_mcp_url": "http://127.0.0.1:7777"})
    seen = {}
    monkeypatch.setattr(zap_mcp, "availability",
                        lambda config: seen.update(url=config.get("ZAP_MCP_URL")) or (True, "ok"))

    resp = auth_client.post("/api/settings/zap-mcp/test", json={})
    assert resp.status_code == 200
    assert seen["url"] == "http://127.0.0.1:7777"
