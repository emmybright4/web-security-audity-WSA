"""Nuclei template-based scanner integration (optional external binary).

If the `nuclei` binary is present in PATH (or NUCLEI_BIN), WSA runs it with
JSON output and converts results into findings. Otherwise it reports
'not configured' and is skipped.
"""
import json
import logging
import shutil
import subprocess

log = logging.getLogger("wsa.nuclei")

SEV_MAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low",
           "info": "informational", "informational": "informational"}


def availability(config):
    """Return (ok, version_or_error)."""
    bin_path = config.get("NUCLEI_BIN") or "nuclei"
    exe = shutil.which(bin_path)
    if not exe:
        return False, (f"Nuclei binary '{bin_path}' not found in PATH. "
                       "Install from https://github.com/projectdiscovery/nuclei "
                       "or set NUCLEI_BIN in .env")
    try:
        out = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=15)
        version = (out.stdout or out.stderr).strip().splitlines()[0][:60] if (out.stdout or out.stderr) else "unknown"
        return True, version
    except Exception as exc:
        return False, f"Nuclei found but failed to execute: {exc}"


def scan(config, target, options, progress_cb=None):
    """Run nuclei against target. Returns (findings, summary, error)."""
    findings, summary, error = [], {"engine": "nuclei", "templates": 0}, ""
    exe = shutil.which(config.get("NUCLEI_BIN") or "nuclei")
    if not exe:
        return findings, summary, "Nuclei not installed - skipped."

    if progress_cb:
        progress_cb(10, "[Nuclei] Updating templates (best effort)")
    try:
        subprocess.run([exe, "-update-templates"], capture_output=True, timeout=60)
    except Exception:
        pass

    severity = options.get("nuclei_severity", "low,medium,high,critical")
    cmd = [exe, "-u", target, "-json", "-silent", "-nc", "-s", severity, "-timeout", "10"]
    if progress_cb:
        progress_cb(25, "[Nuclei] Scanning with community templates")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return findings, summary, "Nuclei timed out after 10 minutes."
    except Exception as exc:
        return findings, summary, f"Nuclei failed to run: {exc}"

    raw = (proc.stdout or "").strip()
    count = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), "informational")
        findings.append({
            "name": item.get("name") or info.get("name") or item.get("template-id") or "Nuclei Finding",
            "severity": sev,
            "confidence": "firm",
            "description": info.get("description") or f"Detected by Nuclei template {item.get('template-id', '')}.",
            "evidence": f"Matcher: {item.get('matcher-name', '')}; URL: {item.get('url') or item.get('host', target)}",
            "remediation": (info.get("remediation") or
                            "Review the referenced Nuclei template for remediation guidance."),
            "url": item.get("url") or item.get("host") or target,
            "target_url": target,
            "detected_by": "Nuclei",
        })
        count += 1
        if progress_cb:
            progress_cb(min(95, 25 + count), f"[Nuclei] {count} finding(s) so far")

    summary["templates"] = count
    if count == 0 and proc.returncode not in (0,):
        error = (proc.stderr or "").strip()[:300]
    if progress_cb:
        progress_cb(100, f"[Nuclei] Complete - {count} finding(s)")
    return findings, summary, error
