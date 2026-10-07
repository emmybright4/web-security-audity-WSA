"""AI / LLM must be configurable from Settings, and empty provider means "off".

Regression: the AI card's Configuration button landed on a table that merely
*listed* ``AI_PROVIDER`` / ``AI_API_KEY`` as ``.env`` variables, so the only way
to enable the assistant was to edit a file and restart WSA. Saving from Settings
must take effect immediately, the key must never be echoed back raw, and clearing
the provider must switch the layer off again rather than resurrecting the
``.env`` value.

``ping`` is deliberately not exercised against a real provider here: a test that
needed the network would be flaky and would spend someone's tokens. The route's
decision logic is covered by driving ``availability``/``ping`` instead.
"""


def test_ai_settings_require_sign_in(client):
    assert client.get("/api/settings").status_code == 401
    assert client.post("/api/settings/ai/test", json={}).status_code == 401


def test_ai_provider_and_key_take_effect_immediately(app, auth_client):
    resp = auth_client.put("/api/settings", json={"ai_provider": "OpenAI",
                                                  "ai_api_key": "sk-test-1234567890",
                                                  "ai_model": "gpt-4o"})
    assert resp.status_code == 200, resp.get_data(as_text=True)

    # stored provider is normalised, exactly like config.py does for .env
    assert app.config["AI_PROVIDER"] == "openai"
    assert app.config["AI_API_KEY"] == "sk-test-1234567890"
    assert app.config["AI_MODEL"] == "gpt-4o"

    from app.services.engines import ai_service
    ok, detail = ai_service.availability(app.config)
    assert ok, detail
    assert "openai" in detail and "gpt-4o" in detail


def test_ai_key_is_never_echoed_back(app, auth_client):
    auth_client.put("/api/settings", json={"ai_provider": "anthropic",
                                           "ai_api_key": "sk-ant-secret-abcdef"})
    settings = auth_client.get("/api/settings").get_json()["settings"]

    assert "ai_api_key" not in settings, "raw provider key must not leave the server"
    assert settings["ai_api_key_set"] is True
    assert settings["ai_api_key_masked"].endswith("ef")
    assert "sk-ant-secret" not in str(settings)


def test_saving_an_empty_key_keeps_the_stored_one(app, auth_client):
    auth_client.put("/api/settings", json={"ai_provider": "openai",
                                           "ai_api_key": "sk-original-key-1234"})
    auth_client.put("/api/settings", json={"ai_model": "gpt-4o-mini"})

    assert app.config["AI_API_KEY"] == "sk-original-key-1234"
    settings = auth_client.get("/api/settings").get_json()["settings"]
    assert settings["ai_api_key_set"] is True


def test_clearing_provider_turns_the_ai_layer_off(app, auth_client):
    """An empty saved provider is explicit "off", not "fall back to .env"."""
    auth_client.put("/api/settings", json={"ai_provider": "openai",
                                           "ai_api_key": "sk-test-1234567890"})
    resp = auth_client.put("/api/settings", json={"ai_provider": ""})
    assert resp.status_code == 200, resp.get_data(as_text=True)

    assert app.config["AI_PROVIDER"] == ""
    from app.services.engines import ai_service
    ok, detail = ai_service.availability(app.config)
    assert not ok
    assert "not configured" in detail


def test_saving_a_key_does_not_echo_it_back(auth_client):
    """The PUT response must not reintroduce what GET deliberately strips."""
    resp = auth_client.put("/api/settings", json={"ai_provider": "openai",
                                                  "ai_api_key": "sk-live-abcdefghij"})
    assert resp.status_code == 200
    echoed = resp.get_json().get("settings", {})
    assert "sk-live-abcdefghij" not in str(echoed)
    assert echoed.get("ai_api_key", "").endswith("ghij")


def test_ai_settings_default_to_env_when_never_saved(app, auth_client):
    settings = auth_client.get("/api/settings").get_json()["settings"]
    assert settings.get("ai_provider", "") == app.config.get("AI_PROVIDER", "")
    assert settings.get("ai_model", "") == app.config.get("AI_MODEL", "")
    assert settings.get("ai_base_url", "") == app.config.get("AI_BASE_URL", "")


def test_ai_test_endpoint_rejects_an_unknown_provider(auth_client):
    resp = auth_client.post("/api/settings/ai/test",
                            json={"ai_provider": "not-a-provider",
                                  "ai_api_key": "whatever"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is False
    assert "Unknown provider" in body["detail"]


def test_ai_test_endpoint_fails_fast_without_a_key(auth_client, monkeypatch):
    """availability() runs before any network call, so no request is made."""
    from app.services.engines import ai_service

    def explode(*a, **k):
        raise AssertionError("ping() must not run when availability() fails")

    monkeypatch.setattr(ai_service, "ping", explode)
    resp = auth_client.post("/api/settings/ai/test",
                            json={"ai_provider": "openai", "ai_api_key": ""})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is False
    assert "not configured" in body["detail"]


def test_ai_test_endpoint_reports_a_rejected_key(auth_client, monkeypatch):
    """ping() decides the answer; a rejected key must surface as a failure."""
    from app.services.engines import ai_service

    monkeypatch.setattr(
        ai_service, "ping",
        lambda config, timeout=20: (False, "openai rejected the API key (HTTP 401)."))
    resp = auth_client.post("/api/settings/ai/test",
                            json={"ai_provider": "openai", "ai_api_key": "sk-wrong"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is False
    assert "401" in body["detail"]


def test_custom_provider_requires_a_base_url(app, auth_client):
    from app.services.engines import ai_service

    auth_client.put("/api/settings", json={"ai_provider": "custom",
                                           "ai_api_key": "sk-test-1234567890"})
    ok, detail = ai_service.availability(app.config)
    assert not ok
    assert "AI_BASE_URL" in detail


def test_ping_uses_the_configured_timeout(monkeypatch):
    """The timeout argument must reach the HTTP call, not stay hardcoded at 90."""
    from app.services.engines import ai_service

    seen = {}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post(url, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return _Resp()

    monkeypatch.setattr(ai_service.requests, "post", fake_post)
    config = {"AI_PROVIDER": "openai", "AI_API_KEY": "sk-test", "AI_MODEL": ""}

    ok, detail = ai_service.ping(config, timeout=7)
    assert ok, detail
    assert seen["timeout"] == 7
