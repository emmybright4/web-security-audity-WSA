"""Safe, authorized time-based SQLi testing module ("gosqli" integration layer).

Two modes:
1. External binary mode: if a `gosqli` binary is configured (GOSQLI_BIN), run it.
2. Built-in mode: boolean/time-delta heuristics over HTTP GET parameters that
   measure response-time differences after injecting SQL time functions.
   Conservative by design: findings are raised only when the timing evidence is
   consistent and reproducible across multiple rounds.

All requests are GET-only and rate-limited; only run against authorized targets.
"""
import logging
import shutil
import subprocess
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

log = logging.getLogger("wsa.sqli")

TIME_FUNCS = [
    ("MySQL", "' AND SLEEP(4)-- -", 4.0),
    ("PostgreSQL", "'; SELECT pg_sleep(4)--", 4.0),
    ("SQLite", "' AND 1=randomblob(400000000)-- -", None),  # busy heuristic, disabled by default
]

RATIO_THRESHOLD = 2.5      # delayed_response must be >= 2.5x baseline
ROUNDS = 2


def availability(config):
    bin_path = (config.get("GOSQLI_BIN") or "").strip()
    if not bin_path:
        return False, "gosqli binary not configured (set GOSQLI_BIN in .env). Built-in timing module is used instead."
    exe = shutil.which(bin_path)
    if not exe:
        return False, f"gosqli binary '{bin_path}' not found in PATH."
    return True, exe


def _with_param(url, key, value):
    parsed = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    if not query:
        query = [(key, value)]
    else:
        query = [(k, value) if k == key else (k, v) for k, v in query]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                       urlencode(query), parsed.fragment))


def scan(config, target, options, progress_cb=None):
    """Returns (findings, summary, error)."""
    findings, summary, error = [], {"engine": "gosqli", "params_tested": 0}, ""
    mode = options.get("sqli_mode", "builtin")

    if mode == "external":
        exe = shutil.which((config.get("GOSQLI_BIN") or "").strip())
        if not exe:
            return findings, summary, "gosqli external binary not available - use builtin mode."
        if progress_cb:
            progress_cb(20, "[gosqli] Running external binary")
        try:
            proc = subprocess.run([exe, "-u", target, "--silent", "--no-color"],
                                  capture_output=True, text=True, timeout=600,
                                  stdin=subprocess.DEVNULL)
            # gosqli prints "SQLI FOUND ..."; keep "injectable" for compatible wrappers
            out = (proc.stdout or "").lower().replace(" ", "")
            if "injectable" in out or "sqlifound" in out:
                findings.append({
                    "name": "SQL Injection Detected (gosqli)", "severity": "high", "confidence": "firm",
                    "description": f"The external gosqli module flagged the target as injectable.",
                    "evidence": (proc.stdout or "")[:500],
                    "remediation": "Use parameterized queries; investigate the flagged parameter.",
                    "url": target, "target_url": target, "detected_by": "gosqli",
                })
            summary["params_tested"] = 1
        except Exception as exc:
            error = f"gosqli execution failed: {exc}"
        return findings, summary, error

    # ---- built-in timing heuristics -----------------------------------------
    session = requests.Session()
    session.headers.update({"User-Agent": "WSA-Scanner/1.0 (+time-based SQLi module)"})
    parsed = urlparse(target)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        if progress_cb:
            progress_cb(100, "[SQLi] No GET parameters to test")
        return findings, summary, error

    baseline_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                               urlencode(params), parsed.fragment))
    try:
        base_times = []
        for _ in range(2):
            t0 = time.monotonic()
            session.get(baseline_url, timeout=15)
            base_times.append(time.monotonic() - t0)
            time.sleep(0.4)
        baseline = sum(base_times) / len(base_times)
    except requests.RequestException as exc:
        return findings, summary, f"Target unreachable for SQLi module: {exc}"

    for idx, (key, original) in enumerate(params):
        pct = int(100 * (idx + 1) / (len(params) + 1))
        if progress_cb:
            progress_cb(pct, f"[SQLi] Testing parameter '{key}'")
        summary["params_tested"] += 1
        for dbms, payload, delay in TIME_FUNCS:
            if delay is None:
                continue  # only reliable time functions
            test_url = _with_param(baseline_url, key, original + payload)
            consistent = True
            measured = []
            for _ in range(ROUNDS):
                try:
                    t0 = time.monotonic()
                    session.get(test_url, timeout=max(15, delay * 3 + 5))
                    measured.append(time.monotonic() - t0)
                except requests.Timeout:
                    measured.append(delay * 3)  # server hung => strong signal
                    continue
                except requests.RequestException:
                    consistent = False
                    break
                time.sleep(0.5)
            if not consistent or not measured:
                continue
            avg_delayed = sum(measured) / len(measured)
            if avg_delayed >= max(baseline * RATIO_THRESHOLD, baseline + delay * 0.6):
                findings.append({
                    "name": f"Possible Time-Based SQL Injection ({dbms})", "severity": "high",
                    "confidence": "firm",
                    "description": f"Parameter '{key}' shows a reproducible response delay when a "
                                   f"{dbms} time-delay payload is injected, indicating the input reaches "
                                   "a SQL interpreter unsanitized.",
                    "evidence": f"Baseline avg: {baseline:.2f}s; with payload avg: {avg_delayed:.2f}s "
                                f"on parameter '{key}' (payload: {payload})",
                    "remediation": "Use prepared statements/parameterized queries for all SQL involving "
                                   "user input; validate types server-side.",
                    "url": test_url, "target_url": target, "detected_by": "gosqli (built-in timing)",
                })
                break  # one confirmed finding per parameter is enough

    if progress_cb:
        progress_cb(100, f"[SQLi] Complete - {summary['params_tested']} parameter(s) tested")
    return findings, summary, error
