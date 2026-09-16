# WSA – Web Security Auditing

**Discover. Analyze. Secure.**

A complete, working web security auditing platform built with **Python + Flask** and a
blue-and-white cybersecurity SaaS dashboard (dark navy sidebar, clean white workspace).
Every value on the dashboard is computed live from the SQLite database — nothing is hardcoded.

---

## Features (all real, all wired to the backend)

| Area | What works |
|---|---|
| **Dashboard** | Live Total Scans / High / Medium / Low cards with trends + sparklines, Findings Overview donut, Vulnerability Trend line chart, Recent Scans with live progress — all from SQLite |
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

See `.env.example` for every variable: Flask secret, database URL, ZAP, Playwright,
Nuclei, gosqli, AI provider, polling fallback interval, worker pool size.

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
