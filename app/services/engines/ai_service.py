"""Optional AI / LLM layer.

Providers: openai, anthropic, custom (OpenAI-compatible base URL).
When AI_API_KEY is not configured, every function raises AIError with a clear
message and the UI shows "AI integration is not configured."
"""
import logging

import requests

log = logging.getLogger("wsa.ai")


class AIError(Exception):
    pass


def availability(config):
    if not config.get("AI_PROVIDER") or not config.get("AI_API_KEY"):
        return False, "AI integration is not configured. Add your LLM provider settings to enable AI analysis."
    provider = config["AI_PROVIDER"]
    model = config.get("AI_MODEL") or ("gpt-4o-mini" if provider == "openai" else
                                       "claude-3-5-sonnet-latest" if provider == "anthropic" else "")
    if provider == "custom" and not config.get("AI_BASE_URL"):
        return False, "AI provider 'custom' requires AI_BASE_URL."
    return True, f"{provider} ({model or 'default model'})"


def ping(config, timeout=20):
    """Prove the configured provider + key actually work. Returns (ok, detail).

    Sends one minimal chat request; ``timeout`` is forwarded to the HTTP call
    so the Settings test button answers quickly instead of hanging on a bad key.
    """
    ok, detail = availability(config)
    if not ok:
        return False, detail
    provider = config["AI_PROVIDER"]
    key = config.get("AI_API_KEY", "")
    model = config.get("AI_MODEL") or ("gpt-4o-mini" if provider == "openai" else
                                       "claude-3-5-sonnet-latest" if provider == "anthropic" else
                                       "default")
    try:
        if provider == "anthropic":
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": model, "max_tokens": 1,
                      "messages": [{"role": "user", "content": "ping"}]},
                timeout=timeout)
        else:
            # openai + custom (OpenAI-compatible)
            base = (config.get("AI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
            resp = requests.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "max_tokens": 1,
                      "messages": [{"role": "user", "content": "ping"}]},
                timeout=timeout)
        resp.raise_for_status()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        return False, f"{provider} rejected the API key (HTTP {status})."
    except requests.RequestException as exc:
        return False, f"Could not reach {provider}: {exc}"
    return True, f"{provider} accepted the API key ({model})."


def _chat(config, system, user, max_tokens=1200):
    ok, detail = availability(config)
    if not ok:
        raise AIError(detail)
    provider = config["AI_PROVIDER"]
    key = config["AI_API_KEY"]
    model = config.get("AI_MODEL") or ("gpt-4o-mini" if provider == "openai" else
                                       "claude-3-5-sonnet-latest" if provider == "anthropic" else
                                       "default")

    if provider == "anthropic":
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": model, "max_tokens": max_tokens,
                  "system": system,
                  "messages": [{"role": "user", "content": user}]},
            timeout=90)
        resp.raise_for_status()
        data = resp.json()
        return "".join(part.get("text", "") for part in data.get("content", []))

    # openai + custom (OpenAI-compatible)
    base = (config.get("AI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    resp = requests.post(
        f"{base}/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": model,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": user}],
              "max_tokens": max_tokens},
        timeout=90)
    resp.raise_for_status()
    data = resp.json()
    return (data.get("choices") or [{}])[0].get("message", {}).get("content", "")


SYSTEM_PROMPT = (
    "You are WSA AI Assistant, a web security expert embedded in the WSA - Web Security Auditing "
    "platform. You analyze real scan findings from authorized security audits. Be concise, technical, "
    "and actionable. Use short paragraphs and bullet lists. Never invent findings that are not in the "
    "provided data."
)


def analyze_findings(config, findings, question=None):
    """Summarize/explain actual findings from the DB."""
    lines = []
    for f in findings[:60]:
        lines.append(f"- [{f['severity'].upper()}] {f['name']} (tool: {f['detected_by']}, "
                     f"url: {f.get('url') or f.get('target_url')})")
    payload = "\n".join(lines) or "No findings recorded yet."
    prompt = f"Here are the latest audit findings:\n\n{payload}\n\n"
    prompt += (question or "Summarize the security posture, prioritize the top risks, and give "
                           "the most important remediation steps.")
    return _chat(config, SYSTEM_PROMPT, prompt)
