"""Playwright-powered JavaScript-aware crawler.

Discovers links/forms via a real browser engine, capturing JS-rendered URLs and
page metadata. Optional engine: the scan runs fine without it installed.
"""
import logging
from urllib.parse import urljoin, urlparse

log = logging.getLogger("wsa.playwright")


def availability():
    """Return (ok, version_or_error)."""
    try:
        from importlib.metadata import version
        ver = version("playwright")
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                path = p.chromium.executable_path
                import os
                if not os.path.exists(path):
                    return False, "Playwright installed but browsers missing. Run: playwright install chromium"
        except Exception as exc:
            return False, f"Playwright browsers not ready: {exc}"
        return True, ver
    except Exception:
        return False, "playwright package not installed. Run: pip install playwright && playwright install chromium"


def crawl(target, options, progress_cb=None):
    """Crawl target with headless Chromium.

    Returns (urls_found, pages_meta, findings, error_message).
    """
    urls, pages_meta, findings, error = {target}, [], [], ""
    max_pages = int(options.get("max_pages", 12))
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return list(urls), pages_meta, findings, f"Playwright unavailable: {exc}"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True,
                                          user_agent="WSA-Scanner/1.0 (+Playwright)")
            page = context.new_page()
            base_host = urlparse(target).hostname or ""
            queue, seen = [target], set()
            i = 0
            while queue and len(seen) < max_pages:
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                i += 1
                if progress_cb:
                    progress_cb(min(95, int(100 * len(seen) / max_pages)),
                                f"[Playwright] Crawling page {i}: {url[:80]}")
                try:
                    resp = page.goto(url, timeout=20000, wait_until="networkidle")
                except Exception:
                    try:
                        resp = page.goto(url, timeout=20000, wait_until="domcontentloaded")
                    except Exception as exc:
                        log.debug("skip %s: %s", url, exc)
                        continue
                status = resp.status if resp else 0
                title = ""
                try:
                    title = page.title()
                except Exception:
                    pass
                pages_meta.append({"url": url, "status": status, "title": title})

                # security-relevant page checks
                content = page.content() or ""
                if "Traceback (most recent call last)" in content:
                    findings.append({
                        "name": "Stack Trace Disclosed (JS-rendered page)", "severity": "medium",
                        "confidence": "firm",
                        "description": "A server-side traceback rendered on a JS-rendered page.",
                        "evidence": f"URL: {url}",
                        "remediation": "Disable debug mode in production.",
                        "url": url, "target_url": target, "detected_by": "Playwright Crawler",
                    })

                # collect same-host links
                for anchor in page.query_selector_all("a[href]"):
                    href = anchor.get_attribute("href") or ""
                    absolute = urljoin(url, href.split("#")[0])
                    parsed = urlparse(absolute)
                    if parsed.scheme in ("http", "https") and (parsed.hostname or "") == base_host:
                        if absolute not in seen:
                            queue.append(absolute)
                            urls.add(absolute)
            browser.close()
    except Exception as exc:
        error = f"Playwright crawl failed: {exc}"
        log.warning(error)
    return list(urls), pages_meta, findings, error
