"""The sensitive-path probe must prove a file is really served.

Regression: the probe used to treat any HTTP 200 as proof, so every SPA / CDN
/ CMS catch-all host (which answers 200 with a styled "page not found" body)
produced the same three high-severity "exposed .env / .git / backup.sql"
findings. Those inflated the dashboard with numbers that looked fabricated
because they repeated on every target.

Both directions are covered: a soft-404 host must yield nothing, and a host
that really serves the files must still be reported.
"""
import http.server
import threading

import pytest

from app.services.engines import builtin_scanner

EXPOSURE_NAMES = ("Exposed Git Repository", ".env Configuration File Exposed",
                  "Database Backup File Exposed", "phpinfo() Page Exposed")

REAL_FILES = {
    "/.git/HEAD": b"ref: refs/heads/main\n",
    "/.env": b"APP_KEY=base64:abc\nDB_HOST=10.0.0.5\n",
    "/backup.sql": b"-- mysqldump\nCREATE TABLE users (id INT);\n",
    "/phpinfo.php": b"<h1>phpinfo()</h1><p>PHP Version 8.1.2</p>",
}

SOFT_404_BODY = b"<html><body><h1>Page not found</h1><p>Sorry.</p></body></html>"


def _serve(handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


class _Soft404(http.server.BaseHTTPRequestHandler):
    """Answers 200 with an error page for every path, like a typical SPA/CDN."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(SOFT_404_BODY)))
        self.end_headers()
        self.wfile.write(SOFT_404_BODY)

    def log_message(self, *args):
        pass


class _RealFiles(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = REAL_FILES.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _exposures(findings):
    return [f for f in findings if f.get("name") in EXPOSURE_NAMES]


def test_soft_404_host_produces_no_exposure_findings():
    srv, url = _serve(_Soft404)
    try:
        findings, _ = builtin_scanner.scan(url, {}, progress_cb=None)
    finally:
        srv.shutdown()
    assert _exposures(findings) == [], \
        "a host that 404s everything with a 200 body must not be reported as exposed"


def test_real_exposed_files_are_still_reported_with_evidence():
    srv, url = _serve(_RealFiles)
    try:
        findings, _ = builtin_scanner.scan(url, {}, progress_cb=None)
    finally:
        srv.shutdown()
    hits = {f["name"]: f for f in _exposures(findings)}
    assert set(hits) == set(EXPOSURE_NAMES), f"missed a real exposure: {sorted(EXPOSURE_NAMES)}"
    for finding in hits.values():
        assert finding["confidence"] == "certain"
        assert finding["evidence"], "every exposure must quote what was actually served"


def test_env_evidence_never_contains_the_secret_value():
    srv, url = _serve(_RealFiles)
    try:
        findings, _ = builtin_scanner.scan(url, {}, progress_cb=None)
    finally:
        srv.shutdown()
    env = [f for f in _exposures(findings) if f["name"].startswith(".env")][0]
    assert "base64:abc" not in env["evidence"], "the report must not reprint the secret"
    assert "app_key" in env["evidence"]


@pytest.mark.parametrize("path,body,expected", [
    (".git/HEAD", "<html>Page not found</html>", None),
    (".git/HEAD", "ref: refs/heads/main\n", "served publicly"),
    (".env", "<html>login page with password field</html>", None),
    (".env", "DB_HOST=10.0.0.5\nDB_PASSWORD=hunter2\n", "served publicly"),
    (".env", "# just a comment\nAPP_ENV=prod\n", None),
    ("backup.sql", "<html>404</html>", None),
    ("backup.sql", "CREATE TABLE t (id INT);", "served publicly"),
    ("phpinfo.php", "<html>not found</html>", None),
    ("phpinfo.php", "phpinfo() - PHP Version 8.1", "served publicly"),
])
def test_file_signature_requires_real_content(path, body, expected):
    proof = builtin_scanner._file_signature(path, body)
    if expected is None:
        assert proof is None, f"unexpected proof for {path}: {proof!r}"
    else:
        assert proof and expected in proof
