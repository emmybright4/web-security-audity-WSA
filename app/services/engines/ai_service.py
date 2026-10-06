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
    provider = config.get("AI_PROVIDER")
    if not provider:
        return False, "AI integration is not configured. Add your LLM provider settings to enable AI analysis."

    if provider == "ollama":
        base = (config.get("AI_BASE_URL") or 'http://localhost:11434').rstrip("/")
        model = config.get("AI_MODEL") or "qwen2.5:3b"
        try:
            resp = requests.get(f"{base}/api/tags", timeout=3)
            resp.raise_for_status()
        except Exception:
            return False, f"Ollama not reachable at {base}. Is 'ollama serve' running?"
        return True, f"ollama ({model}, local)"
    
    
    provider = config["AI_PROVIDER"]
    model = config.get("AI_MODEL") or ("gpt-4o-mini" if provider == "openai" else
                                       "claude-3-5-sonnet-latest" if provider == "anthropic" else "")
    if provider == "custom" and not config.get("AI_BASE_URL"):
        return False, "AI provider 'custom' requires AI_BASE_URL."
    return True, f"{provider} ({model or 'default model'})"


def _chat(config, system, user, max_tokens=1200):
    ok, detail = availability(config)
    if not ok:
        raise AIError(detail)
    provider = config["AI_PROVIDER"]
    if provider == "ollama":
        base = (config.get("AI_BASE_URL") or "http://localhost:11434").rstrip("/")
        model = config.get("AI_MODEL") or "qwen2.5:3b"
        resp = requests.post(
            f"{base}/api/chat",
            json={"model": model, "stream": False,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}]},
            timeout=120)
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "")

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
