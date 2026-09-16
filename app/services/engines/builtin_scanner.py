"""WSA Built-in Scanner - passive web security analysis over plain HTTP.

Runs with zero external dependencies so the platform produces REAL findings
out of the box. Complements ZAP / Nuclei / Playwright engines.
"""
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

import requests

import logging
log = logging.getLogger("wsa.builtin")

USER_AGENT = "WSA-Scanner/1.0 (+Web Security Auditing)"
SUSPICIOUS_PARAMS = ("id", "user", "cat", "page", "item", "q", "search", "view", "product", "news")


def _new_session():
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def _add_finding(findings, **kw):
    kw.setdefault("detected_by", "WSA Built-in Scanner")
    findings.append(kw)


def _tls_certificate_check(session, hostname, port, findings, target):
    """Certificate inspection: expiry, self-signed, hostname mismatch."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                if not_after:
                    import datetime
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") \
                        .replace(tzinfo=datetime.timezone.utc)
                    days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                    if days_left < 0:
                        _add_finding(
                            findings, name="Expired TLS/SSL Certificate", severity="high",
                            confidence="certain",
                            description="The TLS certificate presented by the server has expired. "
                                        "Browsers warn visitors and traffic may be intercepted.",
                            evidence=f"Certificate expired {days_left * -1} day(s) ago (notAfter={not_after}).",
                            remediation="Renew the TLS certificate from your certificate authority and "
                                        "deploy it on the server.",
                            url=target)
                    elif days_left <= 21:
                        _add_finding(
                            findings, name="TLS Certificate Expiring Soon", severity="low",
                            confidence="certain",
                            description="The TLS certificate will expire within three weeks.",
                            evidence=f"Certificate expires in {days_left} day(s) (notAfter={not_after}).",
                            remediation="Schedule a certificate renewal before expiry.",
                            url=target)
    except ssl.SSLCertVerificationError as exc:
        _add_finding(
            findings, name="Invalid or Self-Signed TLS Certificate", severity="medium",
            confidence="firm",
            description="The TLS certificate could not be verified against trusted root authorities. "
                        "This is typical of self-signed or hostname-mismatched certificates.",
            evidence=str(exc.verify_message if hasattr(exc, "verify_message") else exc),
            remediation="Install a valid certificate from a trusted CA (e.g. Let's Encrypt).",
            url=target)
        return
    except Exception:
        pass  # non-TLS or unreachable; transport errors handled elsewhere


def scan(target, options, progress_cb=None):
    """Run the full built-in audit. Returns (findings, summary_dict)."""
    findings = []
    summary = {"requests_made": 0, "pages_crawled": 0, "checks_run": 0}

    def tick(pct, label):
        summary["checks_run"] += 1
        if progress_cb:
            try:
                progress_cb(min(99, int(pct)), label)
            except Exception:
                pass

    session = _new_session()
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    use_https = parsed.scheme == "https"
    port = parsed.port or (443 if use_https else 80)

    # 1) TLS checks ----------------------------------------------------------
    if use_https:
        progress_cb and progress_cb(5, "Inspecting TLS certificate")
        _tls_certificate_check(session, hostname, port, findings, target)
        summary["requests_made"] += 1
    tick(8, "TLS checks complete")

    # 2) Fetch homepage ------------------------------------------------------
    base_headers = {}
    if options.get("auth_enabled") and options.get("auth_username"):
        import base64
        token = base64.b64encode(
            f"{options.get('auth_username', '')}:{options.get('auth_password', '')}".encode()
        ).decode()
        base_headers["Authorization"] = f"Basic {token}"

    try:
        resp = session.get(target, headers=base_headers, timeout=12, allow_redirects=True)
        summary["requests_made"] += 1
        html = resp.text or ""
        final_url = resp.url
        status = resp.status_code
    except requests.exceptions.SSLError:
        # TLS issue already recorded; retry without verification to continue audit
        resp = session.get(target, headers=base_headers, timeout=12,
                           allow_redirects=True, verify=False)
        import urllib3
        urllib3.disable_warnings()
        html, final_url, status = resp.text or "", resp.url, resp.status_code
        summary["requests_made"] += 1
    except requests.RequestException as exc:
        _add_finding(
            findings, name="Target Unreachable", severity="high", confidence="certain",
            description="The scanner could not retrieve the target page.",
            evidence=f"{type(exc).__name__}: {exc}",
            remediation="Verify the target is online and reachable from the scanner host.",
            url=target)
        return findings, summary

    progress_cb and progress_cb(15, f"Fetched homepage (HTTP {status})")

    if status == 401:
        _add_finding(findings, name="HTTP Basic Authentication in Use", severity="informational",
                     confidence="certain",
                     description="The target is protected by HTTP Basic authentication.",
                     evidence="Server responded 401 with WWW-Authenticate header.",
                     remediation="Prefer modern session-based or token authentication over Basic auth over plain HTTP.",
                     url=target)
    if status >= 400:
        _add_finding(findings, name="Error Page Exposed at Root", severity="informational",
                     confidence="firm",
                     description="The root URL returned an HTTP error status.",
                     evidence=f"HTTP {status}", remediation="Review server configuration.", url=target)

    headers = resp.headers

    # 3) Security header audit ------------------------------------------------
    progress_cb and progress_cb(25, "Auditing security response headers")
    header_checks = [
        ("strict-transport-security", "Strict-Transport-Security (HSTS) Header Missing", "medium",
         "The site does not send the HSTS header, allowing protocol downgrade and cookie hijacking "
         "over HTTP.",
         "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy", "Content-Security-Policy Header Missing", "medium",
         "Without CSP the site is more exposed to cross-site scripting and content injection attacks.",
         "Add a Content-Security-Policy header restricting script/style/image sources."),
        ("x-content-type-options", "X-Content-Type-Options Header Missing", "low",
         "Browsers may MIME-sniff responses and execute uploaded content as scripts.",
         "Add: X-Content-Type-Options: nosniff"),
        ("x-frame-options", "Clickjacking Protection Missing (X-Frame-Options)", "medium",
         "The page can be framed by any site, enabling clickjacking. A frame-ancestors CSP "
         "directive is an acceptable modern alternative.",
         "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')."),
        ("referrer-policy", "Referrer-Policy Header Missing", "low",
         "Full URLs (potentially including tokens) may leak to third-party sites via the Referer header.",
         "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "Permissions-Policy Header Missing", "informational",
         "The site does not restrict powerful browser APIs (camera, geolocation, microphone).",
         "Add a Permissions-Policy header limiting sensitive features."),
    ]
    for hname, title, sev, desc, rem in header_checks:
        if hname == "strict-transport-security" and not use_https:
            continue  # HSTS is only meaningful over HTTPS
        if hname not in {k.lower() for k in headers}:
            _add_finding(findings, name=title, severity=sev, confidence="certain",
                         description=desc, evidence=f"Response is missing the '{hname}' header.",
                         remediation=rem, url=final_url)
    tick(35, "Security header audit complete")

    # 4) Server disclosure -----------------------------------------------------
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    if server and any(ch.isdigit() for ch in server):
        _add_finding(findings, name="Server Version Disclosure", severity="low", confidence="firm",
                     description="The Server header reveals a specific software version, helping "
                                 "attackers match known exploits.",
                     evidence=f"Server: {server}",
                     remediation="Suppress version details (ServerTokens Prod on Apache, "
                                 "server_tokens off on nginx).", url=final_url)
    if powered:
        _add_finding(findings, name="Technology Disclosure via X-Powered-By", severity="low",
                     confidence="firm",
                     description="The X-Powered-By header discloses the backend technology.",
                     evidence=f"X-Powered-By: {powered}",
                     remediation="Remove the X-Powered-By header.", url=final_url)

    # 5) Cookie flags ------------------------------------------------------------
    if resp.cookies is not None:
        for cookie in resp.cookies:
            flags = []
            if not cookie.has_nonstandard_attr("Secure"):
                flags.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("HttpOnly")
            if flags and use_https:
                _add_finding(findings, name=f"Cookie Missing {' and '.join(flags)} Flag(s)",
                             severity="medium" if "HttpOnly" in flags else "low",
                             confidence="certain",
                             description=f"Cookie '{cookie.name}' lacks security attributes, making it "
                                         "readable by scripts or sendable over plain HTTP.",
                             evidence=f"Set-Cookie for '{cookie.name}' missing: {', '.join(flags)}.",
                             remediation="Set Secure; HttpOnly; SameSite attributes on all cookies.",
                             url=final_url)

    # 6) Insecure form detection ---------------------------------------------------
    import re as _re
    forms = _re.findall(r"<form\b[^>]*>.*?</form>", html, _re.IGNORECASE | _re.DOTALL)
    progress_cb and progress_cb(45, "Analyzing page content and forms")
    for form in forms:
        action_m = _re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", form, _re.IGNORECASE)
        action = action_m.group(1) if action_m else ""
        form_url = urljoin(final_url, action or final_url)
        has_password = _re.search(r"type\s*=\s*[\"']?password", form, _re.IGNORECASE)
        if has_password and form_url.startswith("http://"):
            _add_finding(findings, name="Password Field Submitted over Plain HTTP", severity="high",
                         confidence="certain",
                         description="A login form transmits credentials without TLS encryption.",
                         evidence=f"Form action: {form_url}",
                         remediation="Serve the login page and POST target over HTTPS.",
                         url=form_url)
        if _re.search(r"method\s*=\s*[\"']?get[\"'\s>]", form, _re.IGNORECASE) and has_password:
            _add_finding(findings, name="Credentials Sent via GET", severity="medium",
                         confidence="firm",
                         description="A password form uses GET, leaking credentials into URLs, "
                                     "history and server logs.",
                         evidence=f"Form action: {form_url}",
                         remediation="Use POST with TLS for authentication forms.", url=form_url)
        if not _re.search(r"csrf|_token|authenticity", form, _re.IGNORECASE) and \
           _re.search(r"method\s*=\s*[\"']?post[\"'\s>]", form, _re.IGNORECASE):
            _add_finding(findings, name="Form Possibly Missing CSRF Protection", severity="medium",
                         confidence="tentative",
                         description="A POST form does not appear to include an anti-CSRF token.",
                         evidence=f"Form action: {form_url}",
                         remediation="Include a per-session CSRF token in state-changing forms.",
                         url=form_url)
    summary["pages_crawled"] += 1

    # 7) Information leakage in page source ------------------------------------------
    if _re.search(r"(?i)stack\s*trace|Traceback \(most recent call last\)|at [\w$.]+\([\w.]+:\d+\)",
                  html):
        _add_finding(findings, name="Stack Trace Disclosed in Response", severity="medium",
                     confidence="firm",
                     description="Error output containing internal paths or code was returned to the client.",
                     evidence="Traceback-like content found in HTML response.",
                     remediation="Disable debug mode; return generic error pages.", url=final_url)
    emails = set(_re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", html))
    leaked = {e for e in emails if not e.lower().endswith((".png", ".jpg", ".gif", ".webp"))}
    if len(leaked) >= 3:
        _add_finding(findings, name="Email Address Enumeration", severity="informational",
                     confidence="firm",
                     description="Multiple email addresses are exposed in the page source, useful "
                                 "for phishing reconnaissance.",
                     evidence=f"Found {len(leaked)} addresses, e.g. {sorted(leaked)[:3]}",
                     remediation="Avoid publishing personal emails; use role-based aliases.", url=final_url)
    if _re.search(r"(?i)(api[_-]?key|apikey|secret|password)\s*[:=]\s*[\"'][A-Za-z0-9+/=_-]{16,}[\"']",
                  html):
        _add_finding(findings, name="Possible Hardcoded Secret in Page Source", severity="high",
                     confidence="tentative",
                     description="A string resembling an API key or secret was found in served HTML.",
                     evidence="Key/secret-like assignment detected in page source.",
                     remediation="Remove secrets from client code; keep them server-side.",
                     url=final_url)

    # 8) Sensitive path probe ------------------------------------------------------------
    progress_cb and progress_cb(58, "Probing common sensitive paths")
    probes = {
        ".git/HEAD": ("Exposed Git Repository", "high",
                      "The .git directory is publicly accessible; source code and history can be "
                      "downloaded and the site may contain committed secrets.",
                      "Block .git in the web server and never deploy VCS metadata."),
        ".env": (".env Configuration File Exposed", "high",
                 "A dotEnv file is served publicly, potentially leaking database credentials and API keys.",
                 "Block .env; keep secrets outside the web root."),
        "backup.sql": ("Database Backup File Exposed", "high",
                       "A SQL backup appears publicly downloadable.",
                       "Delete backups from the web root and restrict access."),
        "phpinfo.php": ("phpinfo() Page Exposed", "medium",
                        "phpinfo reveals configuration, paths and environment variables.",
                        "Remove phpinfo pages from production."),
        "admin/": ("Admin Panel Publicly Reachable", "informational",
                   "A common administration path responded, verify it is protected by strong auth.",
                   "Protect admin areas with authentication, rate limiting and IP allow-lists."),
        "robots.txt": ("robots.txt Present", "informational",
                       "robots.txt was found. It can reveal hidden directory names to attackers.",
                       "Do not rely on robots.txt to hide sensitive paths; use authentication."),
        "sitemap.xml": ("Sitemap Present", "informational",
                        "A sitemap.xml was found; it enumerates the application surface.",
                        "Informational only - no action required."),
    }
    for path, (name, sev, desc, rem) in probes.items():
        try:
            pr = session.get(urljoin(target + "/", path), timeout=6, allow_redirects=False,
                             headers=base_headers)
            summary["requests_made"] += 1
        except requests.RequestException:
            continue
        if pr.status_code == 200:
            body = (pr.text or "")[:400].lower()
            if path == "robots.txt" and "user-agent" in body:
                _add_finding(findings, name=name, severity=sev, confidence="certain",
                             description="robots.txt was found. It can reveal hidden directory names "
                                         "to attackers.",
                             evidence=body.split("\n")[0][:120],
                             remediation="Do not rely on robots.txt to hide sensitive paths; use authentication.",
                             url=urljoin(target + "/", path))
            elif path == "sitemap.xml" and "<urlset" in body or "<sitemap" in body:
                _add_finding(findings, name=name, severity=sev, confidence="certain",
                             description="A sitemap.xml was found; use it to understand the app surface.",
                             evidence="sitemap.xml returned 200.",
                             remediation="Informational only.", url=urljoin(target + "/", path))
            elif path == "admin/" and ("login" in body or "<form" in body or "dashboard" in body):
                _add_finding(findings, name=name, severity=sev, confidence="firm",
                             description=desc, evidence=f"GET {path} returned 200 with login/dashboard content.",
                             remediation=rem, url=urljoin(target + "/", path))
            elif path in (".git/HEAD", ".env", "backup.sql", "phpinfo.php"):
                _add_finding(findings, name=name, severity=sev, confidence="firm",
                             description=desc, evidence=f"GET {path} returned HTTP 200.",
                             remediation=rem, url=urljoin(target + "/", path))
    tick(66, "Sensitive path probe complete")

    # 9) Light reflection-based XSS probe ------------------------------------------------
    progress_cb and progress_cb(72, "Running reflection checks")
    xss_payload = "<wsaprobe123>"
    try:
        pr = session.get(target, params={"wsa": xss_payload}, timeout=8)
        summary["requests_made"] += 1
        if xss_payload in (pr.text or ""):
            _add_finding(findings, name="Possible Reflected XSS (Unsanitized Reflection)", severity="high",
                         confidence="tentative",
                         description="A test string injected via the 'wsa' parameter was reflected in the "
                                     "response without encoding. This may indicate a cross-site scripting flaw.",
                         evidence=f"Parameter 'wsa={xss_payload}' reflected verbatim.",
                         remediation="HTML-encode all user input on output; add a restrictive CSP; "
                                     "use context-aware output escaping.",
                         url=target)
    except requests.RequestException:
        pass

    # 10) Error-based SQLi signature probe ------------------------------------------------
    progress_cb and progress_cb(80, "Checking SQL error signatures")
    sqli_probe = "1'"
    try:
        pr = session.get(target, params={"id": sqli_probe}, timeout=8)
        summary["requests_made"] += 1
        body = pr.text or ""
        signatures = [
            ("MySQL", r"SQL syntax.*MySQL|Warning.*mysql_.*"),
            ("PostgreSQL", r"PostgreSQL.*ERROR|Warning.*pg_.*"),
            ("MS SQL", r"Microsoft OLE DB Provider for SQL Server.*error|Unclosed quotation mark"),
            ("SQLite", r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite"),
            ("Oracle", r"ORA-\d{5}"),
        ]
        for dbms, pattern in signatures:
            if _re.search(pattern, body, _re.IGNORECASE):
                _add_finding(findings, name=f"SQL Error Message Disclosure ({dbms})", severity="medium",
                             confidence="firm",
                             description=f"A database error message from {dbms} was returned when a quote "
                                         "was injected into the 'id' parameter. Detailed DB errors confirm "
                                         "unsanitized input reaches the database and aid SQL injection.",
                             evidence=_re.search(pattern, body, _re.IGNORECASE).group(0)[:150],
                             remediation="Use parameterized queries/prepared statements; disable verbose "
                                         "DB errors in production.",
                             url=target)
                break
    except requests.RequestException:
        pass

    # 11) SQLi detail probe when id-like parameter exists ---------------------------------
    if any(p in (target.split("?", 1)[1] if "?" in target else "") for p in SUSPICIOUS_PARAMS):
        progress_cb and progress_cb(88, "Inspecting injectable-looking parameters")
        _add_finding(findings, name="Input Parameter Requires Manual SQLi Verification", severity="informational",
                     confidence="tentative",
                     description="The URL contains a parameter commonly targeted by SQL injection. "
                                 "Enable the Time-based SQLi module or run sqlmap for deep verification "
                                 "against this authorized target.",
                     evidence=f"Query string: {target.split('?', 1)[1][:200]}",
                     remediation="Use prepared statements for every DB touchpoint.",
                     url=target)

    progress_cb and progress_cb(100, "Built-in scan complete")
    return findings, summary
