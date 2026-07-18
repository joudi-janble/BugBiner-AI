"""Headless-browser DOM XSS detector (Playwright/Chromium).

HTTP-only scanners miss DOM-based XSS because the sink executes in JavaScript after the
page loads (e.g. `document.write(location.hash)`, `innerHTML = params.q`). This drives a
real Chromium, injects a unique payload into every DOM source (query params + fragment),
and confirms execution by catching the resulting `alert()` dialog with our marker — the
same way you'd verify by hand. Confirmed = real code execution, not reflection.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

_AVAILABLE = None


def available() -> bool:
    """True if Playwright + a browser are importable/installed."""
    global _AVAILABLE
    if _AVAILABLE is None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            _AVAILABLE = True
        except Exception:
            _AVAILABLE = False
    return _AVAILABLE


_MARKER = "zqdomxss31337"
_PAYLOADS = [
    f"\"><img src=x onerror=alert('{_MARKER}')>",
    f"<img src=x onerror=alert('{_MARKER}')>",
    f"'-alert('{_MARKER}')-'",
    f"\";alert('{_MARKER}');//",
    f"javascript:alert('{_MARKER}')",
]


class DomXSSScanner:
    """Context manager that keeps one Chromium instance hot across many scan_url() calls."""

    def __init__(self, headless: bool = True):
        self._pw = None
        self._browser = None
        self._headless = headless

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self._headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
        return self

    def __exit__(self, *exc):
        try:
            self._browser.close()
        except Exception:
            pass
        try:
            self._pw.stop()
        except Exception:
            pass

    def scan_url(self, url: str, cookies: dict | None = None, timeout_ms: int = 8000):
        """Inject DOM-XSS payloads into params + fragment; return a finding dict or None."""
        pr = urlparse(url)
        existing = dict(parse_qsl(pr.query, keep_blank_values=True))
        for pl in _PAYLOADS:
            test_qs = {k: pl for k in existing} or {"q": pl}
            test_url = urlunparse(pr._replace(query=urlencode(test_qs, safe="'\"<>()"))) + "#" + pl
            sink = self._load_and_watch(test_url, cookies, timeout_ms)
            if sink:
                return {"url": test_url, "marker": _MARKER, "payload": pl, "sink": sink}
        return None

    def _load_and_watch(self, url: str, cookies, timeout_ms: int):
        ctx = self._browser.new_context(ignore_https_errors=True)
        if cookies:
            try:
                host = urlparse(url).hostname
                ctx.add_cookies([{"name": k, "value": str(v), "domain": host, "path": "/"}
                                 for k, v in cookies.items()])
            except Exception:
                pass
        page = ctx.new_page()
        fired = {"v": None}

        def on_dialog(d):
            if _MARKER in (d.message or ""):
                fired["v"] = "dialog:" + (d.type or "alert")
            try:
                d.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)
        try:
            page.goto(url, wait_until="load", timeout=timeout_ms)
            page.wait_for_timeout(1200)   # let async DOM sinks fire
        except Exception:
            pass
        try:
            ctx.close()
        except Exception:
            pass
        return fired["v"]


# ═══════════════════════════════════════════════════════════════════════════════
# SPA Crawler — renders JavaScript, clicks, discovers API calls
# ═══════════════════════════════════════════════════════════════════════════════
class SPACrawler:
    """Headless browser crawler for SPAs (React/Angular/Vue).
    
    Discovers:
      - Client-side routes
      - API calls (XHR/fetch intercepted)
      - Hidden links and buttons
      - Form actions
    """

    def __init__(self, headless=True):
        self._pw = None
        self._browser = None
        self._headless = headless
        self.discovered_urls = set()
        self.discovered_apis = set()
        self.discovered_forms = []

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self._headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
        return self

    def __exit__(self, *exc):
        try:
            self._browser.close()
        except Exception:
            pass
        try:
            self._pw.stop()
        except Exception:
            pass

    def crawl(self, start_url: str, max_pages=15, timeout_ms=15000) -> dict:
        """Crawl an SPA, discover routes and API calls."""
        self.discovered_urls.add(start_url)
        queue = [start_url]
        visited = set()
        api_patterns = re.compile(r"/(api|graphql|v1|v2|rest|service|backend|rpc)/", re.I)

        while queue and len(visited) < max_pages:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            try:
                ctx = self._browser.new_context(ignore_https_errors=True,
                                                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
                page = ctx.new_page()

                # Intercept API calls
                def _on_request(req):
                    rurl = req.url
                    if api_patterns.search(rurl):
                        self.discovered_apis.add(rurl)
                    # Discover new URLs from navigation
                    if rurl.startswith("http") and rurl not in visited:
                        self.discovered_urls.add(rurl)

                page.on("request", _on_request)

                page.goto(current, wait_until="load", timeout=timeout_ms)
                page.wait_for_timeout(2000)

                # Click all visible links and buttons to discover routes
                selectors = ["a[href]", "button", "[role=button]", ".nav-link", ".menu-item"]
                for sel in selectors:
                    try:
                        elements = page.query_selector_all(sel)
                        for el in elements[:5]:  # max 5 per selector
                            try:
                                href = el.get_attribute("href") or ""
                                if href and href.startswith("/"):
                                    full = start_url.rstrip("/") + href
                                    if full not in visited:
                                        queue.append(full)
                            except Exception:
                                pass
                            try:
                                el.click(timeout=2000)
                                page.wait_for_timeout(1000)
                            except Exception:
                                pass
                    except Exception:
                        pass

                # Extract form actions
                forms = page.query_selector_all("form")
                for form in forms:
                    try:
                        action = form.get_attribute("action") or ""
                        method = form.get_attribute("method") or "GET"
                        inputs = []
                        for inp in form.query_selector_all("input, select, textarea"):
                            n = inp.get_attribute("name") or ""
                            t = inp.get_attribute("type") or "text"
                            if n:
                                inputs.append({"name": n, "type": t})
                        self.discovered_forms.append({
                            "action": action,
                            "method": method.upper(),
                            "inputs": inputs,
                            "page": current,
                        })
                    except Exception:
                        pass

                ctx.close()
            except Exception:
                try:
                    ctx.close()
                except Exception:
                    pass

        return {
            "urls": list(self.discovered_urls),
            "apis": list(self.discovered_apis),
            "forms": self.discovered_forms,
            "crawled": len(visited),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Screenshot Diff — captures before/after, compares with pixel diff
# ═══════════════════════════════════════════════════════════════════════════════
class ScreenshotDiff:
    """Take before/after screenshots and compute a diff score."""

    def __init__(self, output_dir="reports/screenshots"):
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def compare(self, url: str, payload_func, label="test", timeout_ms=12000) -> dict:
        """Take screenshot before and after applying payload_func.
        
        payload_func: callable that modifies the URL/page state.
        Returns: {"diff_pct": float, "before": path, "after": path, "diff": path}
        """
        from playwright.sync_api import sync_playwright
        result = {"diff_pct": 0, "before": "", "after": "", "diff": ""}
        before_path = os.path.join(self._output_dir, f"{label}_before.png")
        after_path = os.path.join(self._output_dir, f"{label}_after.png")

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context(ignore_https_errors=True,
                                      viewport={"width": 1280, "height": 800})
            page = ctx.new_page()

            # Before
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                page.wait_for_timeout(1000)
                page.screenshot(path=before_path, full_page=True)
            except Exception:
                pass

            # Apply payload
            try:
                payload_func(page)
                page.wait_for_timeout(2000)
                page.screenshot(path=after_path, full_page=True)
            except Exception:
                pass

            ctx.close()
            browser.close()

        # Pixel diff using PIL
        try:
            from PIL import Image, ImageChops
            if os.path.exists(before_path) and os.path.exists(after_path):
                im1 = Image.open(before_path)
                im2 = Image.open(after_path)
                diff = ImageChops.difference(im1.convert("RGB"), im2.convert("RGB"))
                diff_path = os.path.join(self._output_dir, f"{label}_diff.png")
                diff.save(diff_path)
                # Calculate diff percentage
                diff_pixels = sum(1 for p in diff.getdata() if any(c != 0 for c in p))
                total_pixels = im1.width * im1.height
                result["diff_pct"] = round(diff_pixels / total_pixels * 100, 2) if total_pixels else 0
                result["before"] = before_path
                result["after"] = after_path
                result["diff"] = diff_path
        except Exception:
            pass

        return result


if __name__ == "__main__":
    print("playwright available:", available())
    print("SPACrawler available")
    print("ScreenshotDiff available")
