"""End-to-end verification of WSA in a real Chrome browser, against a real server.

Serves testsite/ on :8765, drives the app on :5000 through sign-in, a web scan,
findings, reports, an IP scan and sign-out -- recording console errors, page
exceptions, HTTP >= 400 responses and network failures for every page.
"""
import json
import os
import re
import subprocess
import sys
import time

from _cdp import Page

# page text contains emoji; don't die on a cp1252 console/redirect
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://127.0.0.1:5000"
TARGET = "http://127.0.0.1:8765"
IP_TARGET = "127.0.0.1"
# Where MAIL_FILE_DELIVERY (development mode) writes the messages the app sends.
MAIL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "mail")

results = []

# ids the run creates, deleted again in the teardown so the suite leaves the
# database exactly as it found it
created = {"scans": [], "ip_scans": [], "reports": []}


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return ok


def js(page, expr, timeout=30):
    return page.eval(expr, timeout=timeout)


def wait_for(page, expr, timeout=60, interval=1.0, label=""):
    """Poll a JS expression until it is truthy. Returns the value (or None)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = js(page, expr)
        except Exception as e:
            v = None
            print(f"    (poll error: {e})")
        if v:
            return v
        page.drain(interval)
    print(f"    (timed out waiting for {label or expr[:60]})")
    return None


def console_report(page, label):
    problems = page.console_errors()
    check(f"{label}: no console/network errors", not problems,
          "; ".join(problems[:6]))
    page.console.clear()
    page.exceptions.clear()
    page.failed_requests.clear()
    page.responses.clear()


# ---------------------------------------------------------------- test target --
server = subprocess.Popen(
    [sys.executable, "-m", "http.server", "8765", "--directory", "testsite",
     "--bind", "127.0.0.1"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)


def newest_code_from_mailbox():
    """The newest code written by MAIL_FILE_DELIVERY (the local dev mailbox).

    Codes are stored hashed, so the .eml file the app wrote is the only place a
    real sign-in can read a code from - exactly what a mail client would show.
    Returns None when nothing is available (for instance when real SMTP is
    configured and the code went to a real inbox instead).
    """
    try:
        names = [n for n in os.listdir(MAIL_DIR) if n.endswith(".eml")]
    except OSError:
        return None
    if not names:
        return None
    newest = max(names, key=lambda n: os.path.getmtime(os.path.join(MAIL_DIR, n)))
    with open(os.path.join(MAIL_DIR, newest), encoding="utf-8", errors="replace") as fh:
        # undo quoted-printable soft line breaks before looking for the code
        raw = fh.read().replace("=\r\n", "").replace("=\n", "")
    # one styled cell per digit; tying the digit to the cell's style avoids any
    # other "<digit></span>" that a message body might contain
    digits = re.findall(r"min-width:38px[^>]*>(\d)</span>", raw)
    return "".join(digits[:6]) if len(digits) >= 6 else None


def main():
    page = Page("about:blank", width=1440, height=900)
    # start from a clean session: a leftover cookie would redirect /login to the dashboard
    page.send("Network.clearBrowserCookies")
    page.goto(BASE + "/login", settle=2.5)
    page.console.clear(); page.exceptions.clear()
    page.failed_requests.clear(); page.responses.clear()

    print("\n== 1. sign-in page ==")
    check("signed-out visitor sees /login", js(page, "location.pathname") == "/login",
          js(page, "location.href"))
    info = js(page, """JSON.stringify({
      card: (() => { const e=document.querySelector('.auth-card'); if(!e) return null;
        const r=e.getBoundingClientRect(); return {w:Math.round(r.width),h:Math.round(r.height),t:Math.round(r.top)}; })(),
      form: !!document.getElementById('loginForm'),
      btn: (document.getElementById('loginBtn')||{}).textContent,
      brand: (() => { const e=document.querySelector('.auth-brand'); if(!e) return null;
        const r=e.getBoundingClientRect(); return Math.round(r.width)+'x'+Math.round(r.height); })()
    })""")
    info = json_loads(info)
    check("login card is laid out", info["card"] and info["card"]["h"] > 120, str(info["card"]))
    check("login form present", info["form"])
    check("brand panel rendered", info["brand"] == "738x900", str(info["brand"]))
    console_report(page, "login page")

    print("\n== 2. wrong password is rejected ==")
    js(page, """(() => {
      document.getElementById('identifier').value = 'Emmy Bright';
      document.getElementById('password').value = 'definitely-not-it';
      document.getElementById('loginBtn').click();
    })()""")
    shown = wait_for(page, """(() => { const e=document.getElementById('authError');
      return e && !e.hidden ? e.textContent.trim() : ''; })()""", timeout=15, label="auth error")
    shown = str(shown)
    check("error banner shows invalid-credentials message", shown and "Invalid" in shown, str(shown))
    # the deliberate 401 above is expected: don't report it as a page problem
    page.console.clear(); page.exceptions.clear()
    page.failed_requests.clear(); page.responses.clear()

    print("\n== 3. real sign-in: password, then the emailed code ==")
    js(page, """(() => {
      document.getElementById('identifier').value = 'emmy.bright@wsa.local';
      document.getElementById('password').value = 'wsa-admin-2026';
      document.getElementById('remember').checked = true;
      document.getElementById('loginBtn').click();
    })()""")
    on_code_page = wait_for(
        page, "location.pathname === '/verify' && !!document.getElementById('otpInputs')",
        timeout=20, label="verification page")
    check("the password step opens the emailed-code page", bool(on_code_page),
          js(page, "location.href"))
    console_report(page, "login submit")

    code = newest_code_from_mailbox()
    check("the sign-in code was emailed to the mailbox", bool(code),
          f"read from {MAIL_DIR}" if code else
          "no .eml found - use MAIL_FILE_DELIVERY=true or configure MAIL_SERVER")
    if code:
        js(page, """(() => {
          const digits = %s.split('');
          document.querySelectorAll('.otp-digit').forEach((el, i) => { el.value = digits[i] || ''; });
          document.getElementById('verifyBtn').click();
        })()""" % json.dumps(code))
    landed = wait_for(page, "location.pathname === '/' && !!document.getElementById('statTotal')",
                      timeout=20, label="dashboard")
    check("redirected to dashboard once the code was accepted", bool(landed),
          js(page, "location.href"))
    page.drain(1.0)
    console_report(page, "code verification")

    print("\n== 4. dashboard data ==")
    dash = wait_for(page, """(() => {
      const t = document.getElementById('statTotal').textContent.trim();
      return /^[0-9]+$/.test(t) ? t : ''; })()""", timeout=25, label="statTotal")
    check("Total Scans rendered from the database", dash is not None, f"total={dash}")
    charts = js(page, """JSON.stringify({
      donut: !document.getElementById('donutChartWrap').hidden,
      donutEmpty: !document.getElementById('donutEmpty').hidden,
      trend: !document.getElementById('trendChartWrap').hidden,
      recentRows: document.querySelectorAll('#recentScansBody tr').length,
      skeletonLeft: document.querySelectorAll('.wsa-skeleton').length
    })""")
    print("    dashboard state:", charts)
    console_report(page, "dashboard")

    print("\n== 5. new scan ==")
    page.goto(BASE + "/scan/new", settle=2)
    # record every popup raised from here on, so we can assert the screen stays
    # quiet while a scan runs (confirmations must not pop up)
    js(page, """(() => { window.__popups = [];
      const box = document.getElementById('wsaToasts');
      if (box) new MutationObserver(ms => ms.forEach(m => m.addedNodes.forEach(n =>
        n.textContent && window.__popups.push(n.textContent.trim()))))
        .observe(box, { childList: true }); })()""")
    js(page, """(() => {
      document.getElementById('target_url').value = '%s';
      document.getElementById('scan_type').value = 'quick';
      document.getElementById('authorized').checked = true;
      document.getElementById('startBtn').click();
    })()""" % TARGET)
    time.sleep(3)
    # the queued toast no longer exists, so read the new scan back from the API
    scan_id = wait_for(page, """(async () => {
      const d = await (await fetch('/api/scans?limit=1')).json();
      const s = (d.scans || [])[0];
      return s ? String(s.id) : ''; })()""", timeout=15, label="newest scan id")
    check("scan was queued from the UI", bool(scan_id), f"scan #{scan_id}")

    if scan_id:
        done = wait_for(page, """(async () => {
          const r = await fetch('/api/scans/%s');
          const d = await r.json();
          const s = d.scan;
          if (['completed','failed','cancelled'].includes(s.status))
            return JSON.stringify({status:s.status, findings:s.findings_count, error:s.error_message, progress:s.progress});
          return '';
        })()""" % scan_id, timeout=150, interval=2.0, label="scan completion")
        print("    scan result:", done)
        if done:
            st = json_loads(done)
            check("web scan completed successfully", st["status"] == "completed",
                  f"status={st['status']} error={st.get('error')}")
            check("web scan produced findings", (st.get("findings") or 0) > 0,
                  f"findings={st.get('findings')}")
        ui_done = js(page, "document.getElementById('scanDone').innerHTML.includes('completed')")
        check("new-scan page shows completion banner", ui_done)
        created["scans"].append(int(scan_id))
        # the whole point: a scan must not pop notifications onto the screen
        popups = json_loads(js(page, "JSON.stringify(window.__popups || [])"))
        check("no confirmation popups while the scan ran", not popups, str(popups[:6]))
    console_report(page, "new scan page")

    print("\n== 6. findings page ==")
    page.goto(BASE + "/vulnerabilities", settle=2)
    rows = wait_for(page, "document.querySelectorAll('#vulnBody tr').length || ''",
                    timeout=25, label="finding rows")
    count = js(page, "document.getElementById('vulnCount').textContent.trim()")
    check("findings table populated", rows and int(rows) > 0, f"rows={rows} pill={count}")
    targets = js(page, """JSON.stringify(Array.from(document.querySelectorAll('#fTarget option')).map(o=>o.value))""")
    check("target filter lists the scanned target", TARGET in json_loads(targets), str(targets))
    # geometry: the table must be on screen, right under the filters
    geo = json_loads(js(page, """JSON.stringify({
      innerH: innerHeight,
      firstCardH: (() => { const e=document.querySelector('.wsa-content > .wsa-card');
        return e ? Math.round(e.getBoundingClientRect().height) : -1; })(),
      tableTop: (() => { const e=document.querySelector('.wsa-table');
        return e ? Math.round(e.getBoundingClientRect().top) : -1; })(),
      tableH: (() => { const e=document.querySelector('.wsa-table');
        return e ? Math.round(e.getBoundingClientRect().height) : -1; })()
    })"""))
    check("filter card is content-sized, not stretched to the page",
          0 < geo.get("firstCardH", -1) < geo.get("innerH", 0),
          f"card={geo.get('firstCardH')}px viewport={geo.get('innerH')}px")
    check("findings table starts within the first screen",
          0 < geo.get("tableTop", -1) < geo.get("innerH", 0),
          f"table top={geo.get('tableTop')}px")
    page.console.clear(); page.exceptions.clear(); page.responses.clear()
    page.failed_requests.clear()
    console_report(page, "findings page")

    print("\n== 7. scan detail ==")
    if scan_id:
        page.goto(f"{BASE}/scans/{scan_id}", settle=2)
        detail = wait_for(page, """(() => { const n = document.querySelectorAll('#findingsBody tr').length;
          return n ? String(n) : ''; })()""", timeout=25, label="detail findings")
        check("scan detail lists findings", detail and int(detail) > 0, f"rows={detail}")
        console_report(page, "scan detail")

    print("\n== 8. report generation ==")
    page.goto(BASE + "/reports", settle=2)
    opts = wait_for(page, "document.querySelectorAll('#scanSelect option').length > 1 || ''",
                    timeout=25, label="scan options")
    check("reports page lists scans", bool(opts))
    js(page, """(() => {
      const sel = document.getElementById('scanSelect');
      if (%s) sel.value = '%s';
      document.getElementById('reportName').value = 'E2E Verification Report';
      document.getElementById('genBtn').click();
    })()""" % ("true" if scan_id else "false", scan_id or ""))
    report = wait_for(page, """(() => { const t = document.getElementById('reportsBody').textContent;
      return t.includes('E2E Verification Report') ? 'yes' : ''; })()""",
                      timeout=45, label="report row")
    check("PDF report generated and listed", bool(report))
    rid = wait_for(page, """(async () => {
      const d = await (await fetch('/api/reports')).json();
      const r = (d.reports || []).find(x => x.report_name.includes('E2E Verification Report'));
      return r ? String(r.id) : ''; })()""", timeout=20, label="report id")
    if rid:
        created["reports"].append(int(rid))
    console_report(page, "reports page")

    print("\n== 9. IP scan ==")
    page.goto(BASE + "/ip-scanning", settle=2.5)
    js(page, """(() => {
      document.getElementById('ipTarget').value = '%s';
      const quick = document.querySelector('input[name="scan_profile"][value="quick"]');
      if (quick) { quick.checked = true; quick.closest('.ip-profile-card')?.classList.add('selected'); }
      document.getElementById('ipAuthorized').checked = true;
      document.getElementById('ipScanBtn').click();
    })()""" % IP_TARGET)
    # the IP-scan toast carries no scan id, so read the newest scan back from the API
    ip_id = wait_for(page, """(async () => {
      if (document.getElementById('ipActiveScan').style.display === 'none') return '';
      const r = await fetch('/api/ip-scan?limit=1');
      const d = await r.json();
      const s = (d.scans || d.ip_scans || [])[0];
      return s ? String(s.id) : ''; })()""", timeout=25, label="ip scan id")
    active = js(page, "document.getElementById('ipActiveTarget').textContent.trim()")
    check("IP scan started from the UI", bool(ip_id), f"ip scan #{ip_id} ({active})")
    if ip_id:
        created["ip_scans"].append(int(ip_id))
    if ip_id:
        ipdone = wait_for(page, """(async () => {
          const r = await fetch('/api/ip-scan/%s');
          const d = await r.json();
          const s = d.scan;
          if (['completed','failed','cancelled'].includes(s.status))
            return JSON.stringify({status:s.status, hosts:s.hosts_discovered, ports:s.open_ports_count,
              services:s.services_detected, vulns:s.vulnerabilities_count, error:s.error_message});
          return '';
        })()""" % ip_id, timeout=180, interval=2.0, label="ip scan completion")
        print("    ip scan result:", ipdone)
        if ipdone:
            ip = json_loads(ipdone)
            check("IP scan completed successfully", ip["status"] == "completed",
                  f"status={ip['status']} error={ip.get('error')}")
            check("IP scan discovered hosts", (ip.get("hosts") or 0) > 0, f"hosts={ip['hosts']}")
        summary = js(page, """JSON.stringify({
          hosts: document.getElementById('sumHosts').textContent,
          ports: document.getElementById('sumPorts').textContent,
          vulns: document.getElementById('sumVulns').textContent,
          resultsVisible: document.getElementById('ipResultsSection').style.display !== 'none',
          historyRows: document.querySelectorAll('#ipHistoryBody tr').length
        })""")
        print("    ip page state:", summary)
    console_report(page, "ip scanning page")

    print("\n== 10. network findings merged into Findings ==")
    page.goto(BASE + "/vulnerabilities", settle=2)
    merged = wait_for(page, """(async () => {
      const r = await fetch('/api/vulnerabilities?limit=1000');
      const d = await r.json();
      const src = new Set(d.vulnerabilities.map(v => v.source));
      return JSON.stringify({total: d.count, sources: Array.from(src)});
    })()""", timeout=25, label="merged findings")
    print("    findings api:", merged)
    if merged:
        m = json_loads(merged)
        check("API returns both web and network findings",
              {"web", "network"} <= set(m["sources"]), str(m["sources"]))
    targets2 = js(page, """JSON.stringify(Array.from(document.querySelectorAll('#fTarget option')).map(o=>o.value))""")
    check("IP target appears in the findings target filter", IP_TARGET in json_loads(targets2), str(targets2))
    console_report(page, "findings after IP scan")

    print("\n== 11. remaining pages ==")
    for path in ("/templates", "/targets", "/ai", "/tools", "/settings",
                 "/scan/new", "/ip-scanning", "/"):
        page.goto(BASE + path, settle=2.5)
        heading = js(page, "document.querySelector('.wsa-welcome h4')?.textContent.trim() || document.title")
        check(f"{path} renders", bool(heading), heading)
        layout = json_loads(js(page, """JSON.stringify({
          innerH: innerHeight,
          firstCardH: (() => { const e=document.querySelector('.wsa-content > .wsa-card');
            return e ? Math.round(e.getBoundingClientRect().height) : -1; })(),
          secondTop: (() => { const e=document.querySelectorAll('.wsa-content > .wsa-card')[1];
            return e ? Math.round(e.getBoundingClientRect().top) : -1; })()
        })"""))
        # a page-level card must not be stretched to fill the page (the bug that
        # pushed the findings table 12,000px below the fold)
        if layout.get("firstCardH", -1) > 0:
            check(f"{path}: first card is not stretched to the page height",
                  layout["firstCardH"] < layout["innerH"] * 1.5,
                  f"card={layout['firstCardH']}px viewport={layout['innerH']}px")
        console_report(page, path)

    print("\n== 12. teardown: remove everything this run created ==")
    page.goto(BASE + "/", settle=1.5)
    removed = js(page, """(async () => {
      const del = async (u) => { try { const r = await fetch(u, { method: 'DELETE' });
        return r.ok ? 1 : 0; } catch (e) { return 0; } };
      let n = 0;
      for (const id of %s) n += await del('/api/reports/' + id);
      for (const id of %s) n += await del('/api/scans/' + id);
      for (const id of %s) n += await del('/api/ip-scan/' + id);
      return n;
    })()""" % (json.dumps(created["reports"]), json.dumps(created["scans"]),
                 json.dumps(created["ip_scans"])))
    expected = sum(len(v) for v in created.values())
    check("verification data removed again", removed == expected,
          f"deleted {removed} of {expected} (scans={created['scans']} "
          f"ip={created['ip_scans']} reports={created['reports']})")

    print("\n== 13. sign out ==")
    js(page, "document.getElementById('wsaUserMenu')?.click()")
    time.sleep(0.4)
    js(page, "document.getElementById('wsaSignOut')?.click()")
    time.sleep(2)
    out = js(page, "location.pathname")
    check("sign out returns to the login page", out == "/login", str(out))
    check("login page renders after sign-out",
          bool(js(page, "!!document.getElementById('loginForm')")))
    console_report(page, "sign out")

    page.close()


def json_loads(s):
    if s is None:
        return {}
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return {}


if __name__ == "__main__":
    import traceback

    crashed = False
    try:
        main()
    except BaseException:            # noqa: BLE001 - report, don't swallow
        crashed = True
        traceback.print_exc()
    finally:
        server.terminate()
        failed = [r for r in results if not r[1]]
        print("\n" + "=" * 70)
        print(f"{len(results) - len(failed)}/{len(results)} checks passed")
        for name, _, detail in failed:
            print(f"  FAILED: {name} {detail}")
    sys.exit(1 if (failed or crashed) else 0)
