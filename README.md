# WSA – Web Security Auditing

**Discover. Analyze. Secure.**

A complete, working web security auditing platform built with **Python + Flask** and a
blue-and-white cybersecurity SaaS dashboard (dark navy sidebar, clean white workspace).
Every value on the dashboard is computed live from the SQLite database — nothing is hardcoded.

---

## Features (all real, all wired to the backend)

| Area | What works |
|---|---|
| **Sign in & verification** | Email address + password, then a one-time code emailed to that address (hashed, expiring, attempt- and resend-limited) — the workspace opens only after the code is accepted |
| **Dashboard** | Live Total Scans / High / Medium / Low cards with trends + sparklines, Findings Overview donut, Vulnerability Trend line chart, Recent Scans with live progress — all from SQLite |
| **Live Findings chart** | Real-time category chart (1h / 24h / 30d) with minute-level buckets, a pulsing LIVE badge and glowing neon series — redraws the moment a scan finds something |
| **New Scan** | Full engine configuration (Playwright, ZAP, Nuclei, Time-based SQLi, AI assist), authentication, scan policy, authorization confirmation, template saving |
| **Scan Templates** | Save reusable configs, launch a scan directly from a template |
| **Target Management** | Aggregated per-target stats (scans, findings by severity) from real records |
| **Vulnerabilities** | Search / filter by severity, target, scan / sort / view details / update status & notes |
| **Reports** | Real PDF generation (ReportLab): executive summary, severity breakdown, findings, remediation. View & download from history |
| **AI Assistant** | Chat over actual findings. Fails honestly when no LLM is configured |
| **Tools & Integrations** | Real availability checks with versions, status badges (Connected / Not configured / Error) |
| **Settings** | Persisted preferences + engine configuration reference |
| **Live updates** | Flask-SocketIO events (scan started / progress / new finding / completed) with automatic polling fallback |

## Built-in Scanner (zero setup)

WSA ships with its own passive scanner so the platform produces **real findings immediately**,
with no external tools required:

- TLS certificate checks (expired, expiring soon, self-signed / invalid)
- Security header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Server / technology version disclosure
- Cookie flags (Secure, HttpOnly)
- Insecure form detection (password over HTTP, credentials via GET, missing CSRF token)
- Stack traces & email enumeration & hardcoded-secret patterns in page source
- Sensitive path probes (.git, .env, backup files, phpinfo, admin panels, robots.txt, sitemap)
- Reflection-based XSS probe and SQL error signature checks

Optional engines add more depth when installed (see below).

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (optional) configure environment
copy .env.example .env     # Windows
# cp .env.example .env     # Linux/macOS

# 3. Run
python run.py
```

Open **http://127.0.0.1:5000** — the database (wsa.db) is created automatically on first run.

The dashboard starts at **0** with the message *"No scans performed yet. Start your first
authorized audit."* — by design. Run a scan and watch every statistic, chart and table update live.

## Sign-in & Email Verification

Signing in is two steps, always:

1. Enter your **email address and password**.
2. WSA emails a **6-digit, single-use code** to that address; enter it and the workspace opens.

The code is generated with `secrets`, stored only as a salted hash, expires after
`OTP_EXPIRATION_MINUTES`, locks after `OTP_MAX_ATTEMPTS` wrong guesses and can only be re-sent
after `OTP_RESEND_COOLDOWN_SECONDS`. Sign-up proves the email address through the same pipeline,
and password reset reuses it. If email delivery fails, the sign-in is **refused with the
reason** — it never silently falls back to password-only.

**Point it at a real inbox** (any SMTP provider) in `.env`:

```bash
LOGIN_OTP_ENABLED=true        # default; set false for password-only sign-in
MAIL_SERVER=smtp.gmail.com    # Gmail example
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=you@gmail.com
MAIL_PASSWORD=your-16-character-app-password   # Gmail app password, not your login password
MAIL_SENDER=you@gmail.com
MAIL_SENDER_NAME=WSA - Web Security Auditing
```

**No mail server yet?** Set `MAIL_FILE_DELIVERY=true` for local development: each message is
written to `instance/mail/<timestamp>.eml` instead of being sent, so you can open the newest file
and read the code. Production must use SMTP — file delivery writes codes to disk in clear text.

### The verification email never arrives

WSA never pretends to have sent a code. Check the **delivery mode** first:

```bash
python _mail_check.py                  # mode, mailbox path, newest code
python _mail_check.py you@gmail.com    # send a real test message and report the result
```

* **"file delivery - messages are NOT emailed"** — `.env` has `MAIL_FILE_DELIVERY=true`
  without a `MAIL_SERVER`, so every message is a file in `instance/mail/`. Open the newest
  `<timestamp>.eml` there (the `/verify` page also prints that path). This is the intended
  offline development mode; the code never reaches an inbox by design.
* **"not configured"** — set `MAIL_SERVER` (and credentials) in `.env`; sign-up and sign-in
  then refuse with that reason instead of pretending.
* **Real SMTP** — set `MAIL_SERVER=/PORT/USE_TLS/USERNAME/PASSWORD/SENDER`. A configured
  `MAIL_SERVER` always wins over file delivery. With Gmail: turn on 2-Step Verification, create
  an **App Password**, then `MAIL_USERNAME=you@gmail.com`, `MAIL_PASSWORD=<16-char app password>`,
  `MAIL_SENDER=you@gmail.com`.
* Addresses like `emmy.bright@wsa.local` can never receive real mail — register an account with
  an address you can open.
* Already stuck on an unverified account? Sign in with its password: WSA emails a fresh code and
  sends you to the verification page (a sign-up code that expired is no longer a dead end).

### Turning verification off (password-only sign-in)

Offline deployments often have no mail server at all. One master switch in `.env` covers it:

```bash
EMAIL_VERIFICATION_ENABLED=false   # no verification emails at all
LOGIN_OTP_ENABLED=false            # (optional) keep sign-up verification, drop the sign-in code
```

With the master switch off, WSA sends no verification email at all: sign-up creates the account
and signs it straight in, sign-in asks only for the email address and password, and **no SMTP
server is needed**. The shipped default is `true`, where an account must prove its address once
(at sign-up, or with a fresh code requested at sign-in) and each sign-in then needs a code too.

## Testing It (30-second demo)

```bash
# serve a local test target in a second terminal
python -m http.server 8765
```

Then in the UI: **New Scan** → `http://127.0.0.1:8765` → authorize → **Start Scan**.
Watch live progress, then see findings appear on the dashboard and in
**Vulnerabilities**; generate a PDF in **Reports**.

## Optional Engine Integration

All external tools are **optional**. Unconfigured tools show **"Not configured"** — never a fake status.

| Tool | Enable it | Used for |
|---|---|---|
| **OWASP ZAP** | Install+run ZAP, set `ZAP_API_URL` (e.g. `http://127.0.0.1:8080`) and `ZAP_API_KEY` in `.env` | Spider + active scanning |
| **ZAP-MCP** | Set `ZAP_MCP_URL` to a ZAP-MCP server | AI-assisted ZAP workflows (falls back to native ZAP API mode) |
| **Playwright** | `pip install playwright && playwright install chromium` | JavaScript-rendered crawling |
| **Nuclei** | Install the binary, set `NUCLEI_BIN` if not in PATH | Template-based scanning |
| **gosqli** | Set `GOSQLI_BIN` to the binary; the built-in time-based SQLi module always works | SQL injection testing |
| **AI / LLM** | Set `AI_PROVIDER` (`openai`/`anthropic`/`custom`), `AI_API_KEY`, optional `AI_MODEL`, `AI_BASE_URL` | Vulnerability explanations & summaries |

## Configuration (.env)

See `.env.example` for every variable: Flask secret, database URL, sign-in verification
(`LOGIN_OTP_ENABLED`, OTP length/expiry/attempts/cooldown), SMTP delivery (`MAIL_*`), ZAP,
Playwright, Nuclei, gosqli, AI provider, polling fallback interval, worker pool size.

## Architecture

```
run.py                      # entrypoint (Socket.IO server)
config.py                   # env-driven configuration
app/
  __init__.py               # app factory, blueprint registration, seeding
  extensions.py             # db / migrate / socketio singletons
  models.py                 # User, Scan, Vulnerability, Report, ToolIntegration, ScanTemplate, Setting
  events.py                 # Socket.IO handlers
  utils.py                  # URL validation & helpers
  routes/                   # main (pages) + dashboard, scans, vulnerabilities,
                            # reports, ai, tools, templates, targets, settings (APIs)
  services/
    scanner.py              # background orchestrator (threading worker, cancellation, live events)
    report_service.py       # ReportLab PDF generation
    tool_checker.py         # real tool availability checks
    engines/                # builtin_scanner, zap_service, playwright_service,
                            # nuclei_service, sqli_service, zap_mcp, ai_service
  templates/                # base + 10 pages + error pages
  static/                   # wsa.css design system, wsa.js live-update runtime
reports/                    # generated PDFs
wsa.db                      # SQLite database (auto-created)
```

## Notes for the Project Defense

- **Live updates:** open the dashboard in one tab and start a scan from another — stats, charts and
  the recent-scans table update in realtime via Socket.IO (green "Live · realtime" badge).
  If WebSockets are blocked, the badge switches to "Live · polling" automatically.
- **Honest states:** failed scans show the real error; unconfigured tools show "Not configured";
  an empty database shows zeros and a call-to-action — never demo numbers.
- **Authorization gate:** scans are rejected server-side unless the authorization box is checked,
  and URL validation runs before any request is made.
- **WSA v1.0.0 — Built for a safer web.**
