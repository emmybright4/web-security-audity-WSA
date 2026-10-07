"""Builds the system/user prompt pair sent to the LLM for enrichment."""
import json

SYSTEM_PROMPT = (
    "You are a security remediation assistant for WSA (Web Security Auditing). "
    "You write explanations for findings that a deterministic scanner has already "
    "detected and confirmed. Rules:\n"
    "- Use ONLY the finding data and knowledge context provided below.\n"
    "- NEVER invent, change, or imply a different severity, confidence, or CWE "
    "than what is given.\n"
    "- NEVER claim something is a vulnerability if it is not already flagged in "
    "the finding data.\n"
    "- Be concise: 1-3 short sentences per field.\n"
    "- Respond with ONLY a single JSON object, no markdown fences, no extra text, "
    'in exactly this shape: {"explanation": "...", "impact": "...", '
    '"remediation": "..."}'
)

_FALLBACK_CONTEXT = (
    "No pre-written reference material was found for this specific finding type. "
    "Rely only on the finding's own name, evidence, and description below."
)


def build_prompt(finding: dict, kb_entry: dict | None) -> tuple[str, str]:
    """Returns (system_prompt, user_prompt)."""
    context_text = kb_entry["context"] if kb_entry else _FALLBACK_CONTEXT
    wstg_ref = kb_entry.get("wstg_ref", "") if kb_entry else ""

    finding_summary = {
        "name": finding.get("name", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "cwe": finding.get("cwe", ""),
        "evidence": finding.get("evidence", ""),
        "description": finding.get("description", ""),
        "url": finding.get("url") or finding.get("target_url", ""),
    }

    user_prompt = (
        f"FINDING:\n{json.dumps(finding_summary, indent=2)}\n\n"
        f"KNOWLEDGE CONTEXT (reference: {wstg_ref or 'none'}):\n{context_text}\n\n"
        "Write the explanation, impact, and remediation JSON object now."
    )
    return SYSTEM_PROMPT, user_prompt