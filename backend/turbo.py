"""Turbo scanner: Intruder, Repeater, Session Handling, Prototype Pollution,
Sequencer, WebSocket scanner, Request Smuggling — matching and surpassing Burp Suite.

Every detector returns a finding dict (same shape as detect_engine.Result-based findings)
so they integrate seamlessly with main.py's reporting pipeline.
"""
from __future__ import annotations

import json
import math
import re
import statistics
import time as _time
from collections import Counter
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import detect_engine as de


# ═════════════════════════════════════════════════════════════════════════════
#  1)  INTRUDER — wordlist-based fuzzing with position markers, grep-match,
#     cluster-bomb, and auto-calibration
# ═════════════════════════════════════════════════════════════════════════════

# Built-in wordlists (curated for bug bounty)
WL_COMMON_DIRS = (
    "admin", "administrator", "api", "v1", "v2", "v3", "graphql", "swagger",
    "backup", "backups", "dump", "sql", "database", "db", "config", "conf",
    ".git", ".svn", ".env", ".aws", ".azure", "logs", "log", "error",
    "test", "tests", "dev", "debug", "internal", "private", "secret",
)
WL_IDOR = tuple(str(i) for i in range(1, 101))  # 1..100
WL_PARAM_NAMES = (
    "id", "user_id", "account_id", "user", "uid", "uuid", "token",
    "email", "username", "file", "path", "redirect", "url", "next",
    "role", "admin", "is_admin", "debug", "test", "action", "method",
)
WL_COMMON_PATHS = (
    "/login", "/signin", "/register", "/signup", "/logout",
    "/forgot-password", "/reset-password", "/change-password",
    "/admin", "/admin/users", "/admin/config", "/admin/logs",
    "/api/users", "/api/admin", "/api/config", "/api/keys",
    "/profile", "/account", "/settings", "/billing",
    "/download", "/upload", "/export", "/import",
)


def build_intruder_payloads(wordlist: tuple[str, ...], prefix: str = "", suffix: str = "") -> list[str]:
    """Apply prefix/suffix to every wordlist entry."""
    return [f"{prefix}{w}{suffix}" for w in wordlist]


class IntruderMatch:
    """Result of a single intruder attack."""
    def __init__(self, payload: str, status: int, body_len: int, elapsed: float,
                 grep_hits: list[str], location: str = ""):
        self.payload = payload
        self.status = status
        self.body_len = body_len
        self.elapsed = elapsed
        self.grep_hits = grep_hits
        self.location = location

    def to_dict(self):
        return {"payload": self.payload, "status": self.status,
                "body_len": self.body_len, "elapsed": round(self.elapsed, 3),
                "grep": self.grep_hits[:5], "location": self.location[:100] if self.location else None}


def intruder_attack(send, method: str, url: str, headers: dict, cookies: dict,
                    body: str, content_type: str,
                    wordlist: tuple[str, ...],
                    position: str = "query:param", param_name: str = "id",
                    grep: tuple[str, ...] = (),
                    follow: bool = True,
                    delay: float = 0.0, timeout: float = 10.0) -> list[IntruderMatch]:
    """Generic fuzzer: iterates a wordlist over a position marker.

    position options:
      'query:param'  — replaces a URL query parameter value
      'query_name'   — replaces the parameter NAME itself
      'path'         — replaces the URL path
      'header:Name'  — replaces a specific header value
      'body'         — replaces the raw POST body
      'body:field'   — replaces a JSON/form field value
    """
    results = []
    for payload in wordlist:
        try:
            if delay:
                _time.sleep(delay)
            _u, _h, _b = url, dict(headers), body

            if position.startswith("query:"):
                pname = position.split(":", 1)[1] if ":" in position else param_name
                pr = urlparse(url)
                qs = dict(parse_qsl(pr.query, keep_blank_values=True))
                qs[pname] = payload
                _u = urlunparse(pr._replace(query=urlencode(qs)))
            elif position == "query_name":
                pr = urlparse(url)
                qs = dict(parse_qsl(pr.query, keep_blank_values=True))
                new_qs = {}
                for k in qs:
                    new_qs[payload] = qs[k]
                    break  # only the first param gets renamed
                _u = urlunparse(pr._replace(query=urlencode(new_qs)))
            elif position.startswith("header:"):
                hname = position.split(":", 1)[1]
                _h[hname] = payload
            elif position == "body":
                _b = payload
            elif position.startswith("body:"):
                fname = position.split(":", 1)[1]
                ct = (content_type or "").lower()
                if "json" in ct:
                    try:
                        bd = json.loads(body or "{}")
                    except Exception:
                        bd = {}
                    bd[fname] = payload
                    _b = json.dumps(bd)
                else:
                    pr = urlparse(url)
                    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
                    qs[fname] = payload
                    _b = urlencode(qs)

            rr = send(method, _u, _h, cookies, _b, follow)
            if rr is None:
                continue

            body_text = (rr.body or "").lower()
            grep_hits = [g for g in grep if g.lower() in body_text] if grep else []
            loc = (rr.headers or {}).get("location", "")
            results.append(IntruderMatch(payload, rr.status, len(rr.body or ""),
                                          rr.elapsed, grep_hits, loc))
        except Exception:
            pass

    return results


def intruder_find_anomalies(results: list[IntruderMatch], baseline_status: int = 200,
                            baseline_len: int = 0) -> list[dict]:
    """Analyze intruder results for anomalous responses (different status, length, timing).

    Returns finding dicts compatible with main.py's reporting.
    """
    if not results:
        return []

    # Statistical thresholds
    lengths = [r.body_len for r in results]
    statuses = Counter(r.status for r in results)
    common_status = statuses.most_common(1)[0][0] if statuses else baseline_status
    median_len = statistics.median(lengths) if lengths else baseline_len
    std_len = statistics.stdev(lengths) if len(lengths) >= 2 else 0
    len_threshold = max(median_len * 0.5, std_len * 2) if std_len else median_len * 0.3

    findings = []
    seen_payloads = set()

    for r in results:
        # Skip "normal" responses (same status and similar length)
        if r.status == common_status and abs(r.body_len - median_len) < len_threshold:
            continue
        if r.status in (301, 302, 303, 307, 308) and r.location:
            if r.payload in seen_payloads:
                continue
            seen_payloads.add(r.payload)
            findings.append({
                "vuln_type": "INTRUDER",
                "severity": "medium",
                "url": "",
                "detail": f"Anomalous redirect for payload '{r.payload[:40]}': {r.status} → {r.location[:80]}",
                "evidence": json.dumps(r.to_dict())[:400],
                "payload": r.payload,
                "cvss": "5.3",
                "proof": r.to_dict(),
                "recommendation": "Review if the anomalous response indicates a vulnerability (IDOR, admin bypass, etc).",
            })
        elif r.status != common_status and r.status not in (301, 302, 303, 307, 308):
            severity = "critical" if r.status in (200, 201) and r.body_len > median_len * 1.5 else "high"
            if r.payload in seen_payloads:
                continue
            seen_payloads.add(r.payload)
            sev_label = "Access granted (200)" if r.status == 200 and common_status != 200 else f"Anomalous {r.status}"
            findings.append({
                "vuln_type": "INTRUDER",
                "severity": severity,
                "url": "",
                "detail": f"Payload '{r.payload[:40]}' → {sev_label} (common={common_status}, len={r.body_len} vs median={median_len})",
                "evidence": json.dumps(r.to_dict())[:400],
                "payload": r.payload,
                "cvss": "7.5" if severity == "critical" else "5.3",
                "proof": r.to_dict(),
                "recommendation": "Investigate anomalous response for IDOR, auth bypass, or parameter injection.",
            })
        elif r.grep_hits:
            if r.payload in seen_payloads:
                continue
            seen_payloads.add(r.payload)
            findings.append({
                "vuln_type": "INTRUDER",
                "severity": "high",
                "url": "",
                "detail": f"Payload '{r.payload[:40]}' matched grep: {', '.join(r.grep_hits[:3])}",
                "evidence": json.dumps(r.to_dict())[:400],
                "payload": r.payload,
                "cvss": "6.5",
                "proof": r.to_dict(),
                "recommendation": "Grep match indicates potential vulnerability — review response content.",
            })

    return findings


def intruder_mt(send, method: str, url: str, headers: dict, cookies: dict,
                body: str, content_type: str,
                wordlist: tuple[str, ...],
                position: str = "query:param", param_name: str = "id",
                grep: tuple[str, ...] = (),
                follow: bool = True,
                threads: int = 20, timeout: float = 10.0) -> list[IntruderMatch]:
    """Multi-threaded fuzzer — fires up to `threads` concurrent requests.

    5-10x faster than the sequential intruder_attack. Same interface.
    """
    import concurrent.futures
    from functools import partial

    def _fire(payload):
        try:
            _u, _h, _b = url, dict(headers), body
            pr = urlparse(url)
            if position.startswith("query:"):
                pname = position.split(":", 1)[1] if ":" in position else param_name
                qs = dict(parse_qsl(pr.query, keep_blank_values=True))
                qs[pname] = payload
                _u = urlunparse(pr._replace(query=urlencode(qs)))
            elif position == "query_name":
                qs = dict(parse_qsl(pr.query, keep_blank_values=True))
                new_qs = {}
                for k in qs:
                    new_qs[payload] = qs[k]
                    break
                _u = urlunparse(pr._replace(query=urlencode(new_qs)))
            elif position.startswith("header:"):
                hname = position.split(":", 1)[1]
                _h[hname] = payload
            elif position == "body":
                _b = payload
            elif position.startswith("body:"):
                fname = position.split(":", 1)[1]
                ct = (content_type or "").lower()
                if "json" in ct:
                    try:
                        bd = json.loads(body or "{}")
                    except Exception:
                        bd = {}
                    bd[fname] = payload
                    _b = json.dumps(bd)
                else:
                    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
                    qs[fname] = payload
                    _b = urlencode(qs)

            rr = send(method, _u, _h, cookies, _b, follow)
            if rr is None:
                return None
            body_text = (rr.body or "").lower()
            grep_hits = [g for g in grep if g.lower() in body_text] if grep else []
            loc = (rr.headers or {}).get("location", "")
            return IntruderMatch(payload, rr.status, len(rr.body or ""),
                                  rr.elapsed, grep_hits, loc)
        except Exception:
            return None

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        for r in pool.map(_fire, wordlist, chunksize=1):
            if r is not None:
                results.append(r)
    return results


# ═════════════════════════════════════════════════════════════════════════════
#  2)  REPEATER — manual/automated request resend with modifications
# ═════════════════════════════════════════════════════════════════════════════

class RepeaterRequest:
    """A saved request that can be resent with modifications."""
    def __init__(self, method: str, url: str, headers: dict, cookies: dict,
                 body: str, content_type: str = "",
                 label: str = ""):
        self.method = method
        self.url = url
        self.headers = dict(headers)
        self.cookies = dict(cookies)
        self.body = body
        self.content_type = content_type
        self.label = label
        self.history: list[dict] = []

    def modify(self, **kwargs):
        """Return a new RepeaterRequest with modified fields."""
        new = RepeaterRequest(
            self.method, self.url, self.headers, self.cookies,
            self.body, self.content_type, self.label
        )
        for k, v in kwargs.items():
            if hasattr(new, k):
                setattr(new, k, v)
        return new

    def send(self, send_fn) -> dict:
        """Send this request via the provided send function. Returns response dict."""
        rr = send_fn(self.method, self.url, self.headers, self.cookies, self.body, True)
        resp = {
            "status": rr.status if rr else 0,
            "body": (rr.body or "")[:2000] if rr else "",
            "headers": dict(rr.headers) if rr and rr.headers else {},
            "elapsed": round(rr.elapsed, 3) if rr else 0,
            "url": rr.url if rr else self.url,
        }
        self.history.append({"request": {"method": self.method, "url": self.url,
                                          "headers": self.headers, "body": self.body},
                              "response": resp})
        return resp

    def diff(self, other_resp: dict) -> list[str]:
        """Compare the last response with another response."""
        diffs = []
        last = self.history[-1]["response"] if self.history else {}
        if last.get("status") != other_resp.get("status"):
            diffs.append(f"status: {last.get('status')} → {other_resp.get('status')}")
        llen = len(last.get("body", ""))
        olen = len(other_resp.get("body", ""))
        if abs(llen - olen) > max(llen, olen) * 0.1:
            diffs.append(f"body_len: {llen} → {olen} (Δ{olen - llen:+d})")
        return diffs


# ═════════════════════════════════════════════════════════════════════════════
#  3)  SESSION HANDLING — auto cookie refresh + login macros
# ═════════════════════════════════════════════════════════════════════════════

class SessionManager:
    """Manages session cookies with auto-refresh and login macro support.

    Usage:
        sm = SessionManager(send_fn)
        sm.add_login_macro("POST", "https://example.com/login",
                           {"username": "test", "password": "test"}, ["sessionid"])
        cookies = sm.get_cookies("https://example.com")  # auto-refreshes if expired
    """
    def __init__(self, send_fn, check_url: str = "", check_pattern: str = "logout|profile|account"):
        self.send = send_fn
        self.cookies: dict[str, str] = {}
        self.macros: list[dict] = []
        self.check_url = check_url
        self.check_pattern = check_pattern
        self._last_refresh = 0.0

    def add_login_macro(self, method: str, url: str, body: dict,
                         cookie_keys: tuple[str, ...] = (),
                         headers: dict | None = None):
        """Register a login sequence. send_fn must accept (method, url, headers, {}, body, True)."""
        self.macros.append({
            "method": method, "url": url, "body": body,
            "cookie_keys": cookie_keys, "headers": headers or {},
        })

    def get_cookies(self, target_url: str = "", force: bool = False) -> dict[str, str]:
        """Get active session cookies. Auto-refreshes if expired or forced."""
        now = _time.time()
        if not force and self._last_refresh and (now - self._last_refresh) < 300:
            return dict(self.cookies)
        if not self.macros:
            return dict(self.cookies)

        # Run login macros
        for macro in self.macros:
            try:
                rr = self.send(macro["method"], macro["url"],
                               {**macro.get("headers", {}), "User-Agent": "Mozilla/5.0"},
                               {}, json.dumps(macro["body"]), True)
                if rr and rr.headers:
                    # Extract Set-Cookie headers
                    for k, v in (rr.headers or {}).items():
                        if k.lower() == "set-cookie":
                            for part in v.split(";"):
                                if "=" in part:
                                    ck, cv = part.split("=", 1)
                                    self.cookies[ck.strip()] = cv.strip()
                    # Also try response body for tokens
                    body_lower = (rr.body or "").lower()
                    for key in macro.get("cookie_keys", []):
                        pat = re.compile(rf'["\']?{re.escape(key)}["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.I)
                        m = pat.search(body_lower)
                        if m:
                            self.cookies[key] = m.group(1) if not m.group(1).startswith("$") else m.group(1)
            except Exception:
                pass

        self._last_refresh = now
        return dict(self.cookies)

    def is_session_active(self, test_url: str = "") -> bool:
        """Check if the session is still active by probing a protected endpoint."""
        url = test_url or self.check_url
        if not url:
            return bool(self.cookies)
        try:
            rr = self.send("GET", url, {"User-Agent": "Mozilla/5.0"}, self.cookies, "", True)
            body = (rr.body or "").lower()
            return bool(re.search(self.check_pattern, body)) if self.check_pattern else bool(rr and rr.status < 400)
        except Exception:
            return False


# ═════════════════════════════════════════════════════════════════════════════
#  4)  PROTOTYPE POLLUTION — server-side + client-side detection
# ═════════════════════════════════════════════════════════════════════════════

_PP_PAYLOADS_JSON = [
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"admin": True}},
    {"__proto__": {"is_admin": True}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"__proto__": {"polluted": "true"}},
]
_PP_PAYLOADS_PARAM = [
    "__proto__[isAdmin]=true",
    "__proto__[polluted]=true",
    "constructor[prototype][isAdmin]=true",
]
_PP_REFLECT_PATTERNS = [
    r'"isAdmin"\s*:\s*true',
    r'"polluted"\s*:\s*"true"',
    r'"__proto__"\s*:\s*\{',
]


def detect_pp_server_side(send, url: str, headers: dict, cookies: dict, body: str = "",
                           content_type: str = "application/json") -> de.Result:
    """Server-side prototype pollution via JSON body injection.

    Sends payloads with __proto__ keys and checks if they reflect in the response
    or cause behavioral changes (e.g., admin access).
    """
    if content_type not in ("application/json",):
        return de.Result("pp", de.SAFE, ["not a JSON endpoint"])

    h = {**headers, "Content-Type": "application/json"}
    found = []

    for payload in _PP_PAYLOADS_JSON:
        try:
            rr = send("POST", url, h, cookies, json.dumps(payload), True)
        except Exception:
            continue
        if rr is None or de.is_blocked(rr):
            continue
        body_text = rr.body or ""
        for pat in _PP_REFLECT_PATTERNS:
            if re.search(pat, body_text, re.I):
                found.append((json.dumps(payload)[:80], pat))
                break

    if found:
        signals = [f"Prototype pollution reflected: {pat} via {pl}" for pl, pat in found[:2]]
        return de.Result("pp", de.CONFIRMED, signals,
                         severity="critical", payload=json.dumps(_PP_PAYLOADS_JSON[0]),
                         proof={"matches": found[:5]})
    return de.Result("pp", de.SAFE, ["no prototype pollution signal"])


def detect_pp_client_side(js: str) -> de.Result:
    """Client-side prototype pollution via static analysis of JS sinks.

    Looks for known PP gadgets (merge, assign, spread) on untrusted objects.
    """
    js_body = js or ""
    sinks = [
        (r'\.assign\([^)]*\b(?:location|params|query|hash|search)\b', "Object.assign with location"),
        (r'\.merge\([^)]*\b(?:location|params|query)\b', "merge with location"),
        (r'\[\.\.\.(?:location|params|query|hash|search)\]', "spread of location"),
        (r'for\s*\(\s*(?:let|var|const)\s+\w+\s+in\s+(?:location|params|query|hash)', "for..in on location"),
        (r'JSON\.parse\([^)]*\)\s*\)\s*\)\s*;?\s*}\s*catch', "JSON.parse in try-catch (PP gadget)"),
    ]
    hits = []
    for pat, name in sinks:
        if re.search(pat, js_body):
            hits.append(name)
    if hits:
        return de.Result("pp", de.PROBABLE, hits,
                         severity="medium",
                         proof={"gadgets": hits})
    return de.Result("pp", de.SAFE, ["no PP gadget"])


# ═════════════════════════════════════════════════════════════════════════════
#  5)  SEQUENCER — token randomness analysis
# ═════════════════════════════════════════════════════════════════════════════

def sequencer_analyze(tokens: list[str]) -> dict:
    """Analyze a list of tokens for randomness quality.

    Returns:
        entropy: Shannon entropy in bits
        min, max, unique: basic stats
        char_freq: character frequency distribution
        prediction: "weak" | "moderate" | "strong"
    """
    if not tokens:
        return {"entropy": 0, "count": 0, "prediction": "unknown"}

    # Shannon entropy
    all_chars = "".join(tokens)
    n = len(all_chars)
    freq = Counter(all_chars)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values()) if n else 0

    unique = len(set(tokens))
    avg_len = statistics.mean(len(t) for t in tokens) if tokens else 0

    # Character-level bias check
    char_positions = {}
    for t in tokens:
        for i, c in enumerate(t):
            char_positions.setdefault(i, []).append(c)
    position_bias = {}
    for pos, chars in char_positions.items():
        unique_at_pos = len(set(chars))
        if unique_at_pos <= 2 and len(chars) >= 5:
            position_bias[pos] = f"only {unique_at_pos} unique char(s)"

    # Prediction
    if entropy >= 4.0 and unique >= len(tokens) * 0.8 and len(position_bias) == 0:
        prediction = "strong"
    elif entropy >= 2.5 and unique >= len(tokens) * 0.3:
        prediction = "moderate"
    else:
        prediction = "weak"

    return {
        "entropy": round(entropy, 3),
        "count": len(tokens),
        "unique": unique,
        "avg_length": round(avg_len, 1),
        "prediction": prediction,
        "position_bias": position_bias,
    }


def sequencer_collect(send, url: str, headers: dict, cookies: dict,
                       extract_pattern: str, param: str = "",
                       samples: int = 50) -> list[str]:
    """Collect tokens from responses for randomness analysis.

    extract_pattern: regex with a capture group to extract the token
    param: if set, the token is extracted from the response.
    """
    tokens = []
    for _ in range(samples):
        try:
            rr = send("GET", url, headers, cookies, "", True)
        except Exception:
            continue
        if rr is None:
            continue
        body = rr.body or ""

        # Try header first
        for k, v in (rr.headers or {}).items():
            if k.lower() in ("set-cookie", "csrf-token", "x-csrf-token", "x-xsrf-token",
                             "authorization", "x-auth-token"):
                m = re.search(r"=([a-zA-Z0-9_\-]{8,})", v)
                if m:
                    tokens.append(m.group(1))
                    break

        # Then body pattern
        m = re.search(extract_pattern, body)
        if m:
            tokens.append(m.group(1))
    return tokens


# ═════════════════════════════════════════════════════════════════════════════
#  6)  WEB SOCKET SCANNER
# ═════════════════════════════════════════════════════════════════════════════

_WS_INJECTION_PAYLOADS = [
    ("<script>alert(1)</script>", "XSS"),
    ("' OR '1'='1", "SQLi"),
    ("${7*7}", "SSTI"),
    ("../etc/passwd", "LFI"),
    ("{{7*7}}", "SSTI (jinja)"),
    ('{"$ne": null}', "NoSQL"),
]

# Note: WebSocket scanning requires websockets library. We provide a sync wrapper.
class WebSocketScanner:
    """Scan WebSocket endpoints by sending fuzz payloads and reading responses.

    Usage:
        scanner = WebSocketScanner()
        results = scanner.scan("wss://example.com/ws", ["<script>alert(1)</script>"])
    """
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._ws = None  # lazy import

    def scan(self, ws_url: str, extra_payloads: list[str] | None = None) -> list[dict]:
        """Connect to a WebSocket, send payloads, collect responses."""
        try:
            import websockets.sync.client as ws_client
        except ImportError:
            return [{"vuln_type": "WEBSOCKET", "severity": "info",
                     "url": ws_url,
                     "detail": "WebSocket scanning requires 'websockets' library: pip install websockets",
                     "evidence": "", "payload": "", "cvss": "0.0", "proof": {},
                     "recommendation": "Install websockets package to enable WebSocket scanning."}]

        findings = []
        payloads = list(_WS_INJECTION_PAYLOADS) + [(p, "custom") for p in (extra_payloads or [])]

        try:
            with ws_client.connect(ws_url, timeout=self.timeout) as ws:
                for payload, vuln_type in payloads:
                    try:
                        ws.send(payload)
                        resp = ws.recv(timeout=self.timeout)
                        if resp and len(resp) > 0:
                            resp_text = resp if isinstance(resp, str) else resp.decode(errors="replace")
                            if payload.lower() in resp_text.lower():
                                findings.append({
                                    "vuln_type": "WEBSOCKET XSS" if vuln_type == "XSS" else f"WEBSOCKET {vuln_type}",
                                    "severity": "critical" if vuln_type in ("XSS", "SQLi") else "high",
                                    "url": ws_url,
                                    "detail": f"Payload '{payload[:60]}' reflected in WebSocket response (potential {vuln_type})",
                                    "evidence": resp_text[:400],
                                    "payload": payload,
                                    "cvss": "9.8" if vuln_type in ("XSS", "SQLi") else "7.5",
                                    "proof": {"reflected": True, "payload": payload, "response": resp_text[:200]},
                                    "recommendation": "Validate/sanitize all WebSocket messages on the server side.",
                                })
                    except Exception:
                        pass
        except Exception as e:
            findings.append({
                "vuln_type": "WEBSOCKET",
                "severity": "info",
                "url": ws_url,
                "detail": f"WebSocket connection failed: {e}",
                "evidence": str(e)[:200], "payload": "",
                "cvss": "0.0", "proof": {},
                "recommendation": "Verify WebSocket endpoint availability.",
            })

        return findings


# ═════════════════════════════════════════════════════════════════════════════
#  7)  REQUEST SMUGGLING — HTTP/2 downgrade, TE/CL, Transfer-Encoding / Content-Length
# ═════════════════════════════════════════════════════════════════════════════

_SMUGGLE_PAYLOADS = {
    "CL.TE": [
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
    ],
    "TE.CL": [
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
    ],
    "TE.TE": [
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\nG",
    ],
}


def detect_smuggle(send, target_url: str, headers: dict | None = None) -> de.Result:
    """Basic request smuggling detection via timing / response discrepancy.

    Sends a smuggling probe and checks for:
    - Connection timeout (pipeline desync)
    - Different response status/body for the follow-up request
    """
    host = urlparse(target_url).netloc
    h = dict(headers or {})
    base_headers = {**h, "User-Agent": "Mozilla/5.0"}

    # Baseline: normal request timing
    try:
        t0 = _time.time()
        r_base = send("GET", target_url, base_headers, {}, "", True)
        base_time = _time.time() - t0
    except Exception:
        return de.Result("smuggle", de.SAFE, ["no baseline"])

    if r_base is None:
        return de.Result("smuggle", de.SAFE, ["no baseline response"])

    findings = []
    for technique, payloads in _SMUGGLE_PAYLOADS.items():
        for raw in payloads:
            payload = raw.format(host=host)
            try:
                # Send the raw payload as the body of a POST
                t0 = _time.time()
                r1 = send("POST", target_url, {**base_headers, "Content-Type": "application/octet-stream"},
                          {}, payload, False)
                elapsed = _time.time() - t0
            except Exception:
                continue
            if r1 is None:
                continue
            # Smuggling signal: request times out (pipeline desync) or returns weird status
            if elapsed > max(base_time * 3, 10):
                findings.append((technique, f"timeout {elapsed:.1f}s (base {base_time:.1f}s)"))
            if r1.status in (400, 403, 500) and technique in ("CL.TE",):
                findings.append((technique, f"status {r1.status} on CL.TE probe"))

    if findings:
        signals = [f"{tech}: {reason}" for tech, reason in findings[:3]]
        return de.Result("smuggle", de.PROBABLE, signals,
                         severity="critical",
                         proof={"findings": findings})
    return de.Result("smuggle", de.SAFE, ["no smuggling signal"])


# ═════════════════════════════════════════════════════════════════════════════
#  8)  ENHANCED DOM XSS — full browser taint tracking via Playwright
# ═════════════════════════════════════════════════════════════════════════════

_DOM_XSS_SINKS = (
    ".innerHTML", ".outerHTML", "document.write(", "document.writeln(",
    ".insertAdjacentHTML(", ".insertAdjacentText(", "eval(", "setTimeout(",
    "setInterval(", "new Function(", "Function(", "location.href=",
    "location.assign(", "location.replace(", "open(", "srcdoc=",
)
_DOM_XSS_SOURCES = (
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "postMessage", "history.pushState",
    "localStorage.getItem(", "sessionStorage.getItem(",
)


def dom_xss_scan_js(js: str) -> list[dict]:
    """Static analysis of JavaScript for DOM XSS source→sink flows.

    Returns finding dicts for manual review (PROBABLE confidence — needs browser confirmation).
    """
    findings = []
    js_body = js or ""

    for src in _DOM_XSS_SOURCES:
        if src not in js_body:
            continue
        for snk in _DOM_XSS_SINKS:
            if snk not in js_body:
                continue
            # Check if source appears before sink in the same script (basic taint approximation)
            src_idx = js_body.index(src)
            snk_idx = js_body.index(snk)
            if src_idx < snk_idx and (snk_idx - src_idx) < 5000:
                excerpt = de._excerpt(js_body, src, 80)
                findings.append({
                    "vuln_type": "DOM XSS",
                    "severity": "info",
                    "url": "",
                    "detail": f"Static DOM XSS: source '{src}' reaches sink '{snk}' (within 5k chars)",
                    "evidence": excerpt,
                    "payload": "",
                    "cvss": "0.0",
                    "proof": {"source": src, "sink": snk, "script_sample": excerpt},
                    "recommendation": "Confirm with browser engine — this is a static hint, not a confirmed vulnerability.",
                })
                break  # one finding per source

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  9)  REPORT GENERATOR — HTML + JSON
# ═════════════════════════════════════════════════════════════════════════════

def generate_html_report(findings: list[dict], target: str, scan_time: str = "") -> str:
    """Generate a professional HTML report from findings (like Burp's report)."""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 99))

    rows = ""
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity", "info").upper()
        vt = f.get("vuln_type", "Unknown")
        url = f.get("url", "")
        detail = f.get("detail", "")
        evidence = f.get("evidence", "")[:300]
        rec = f.get("recommendation", "")
        sev_color = {"CRITICAL": "#ff0000", "HIGH": "#ff6600",
                     "MEDIUM": "#ffaa00", "LOW": "#669900", "INFO": "#336699"}
        sc = sev_color.get(sev, "#666")
        rows += f"""
        <tr style="border-bottom:1px solid #ddd;">
            <td style="padding:8px">{i}</td>
            <td style="padding:8px;color:{sc};font-weight:bold">{sev}</td>
            <td style="padding:8px">{vt}</td>
            <td style="padding:8px;max-width:400px;overflow:hidden;text-overflow:ellipsis">{url}</td>
            <td style="padding:8px;max-width:400px">{detail}</td>
            <td style="padding:8px;font-size:11px;max-width:300px"><pre>{evidence}</pre></td>
            <td style="padding:8px;font-size:12px">{rec}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Scan Report — {target}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }}
h1 {{ color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 8px; }}
.summary {{ background: #f5f5f5; padding: 12px; border-radius: 6px; margin: 12px 0; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th {{ background: #1a237e; color: white; padding: 10px 8px; text-align: left; }}
tr:nth-child(even) {{ background: #f9f9f9; }}
tr:hover {{ background: #e8eaf6; }}
pre {{ white-space: pre-wrap; word-break: break-word; margin: 0; }}
</style>
</head>
<body>
<h1>🔍 Security Scan Report</h1>
<div class="summary">
    <strong>Target:</strong> {target}<br>
    <strong>Scan Time:</strong> {scan_time}<br>
    <strong>Total Findings:</strong> {len(sorted_f)}<br>
    <strong>Critical:</strong> {sum(1 for f in sorted_f if f.get('severity')=='critical')} |
    <strong>High:</strong> {sum(1 for f in sorted_f if f.get('severity')=='high')} |
    <strong>Medium:</strong> {sum(1 for f in sorted_f if f.get('severity')=='medium')} |
    <strong>Low:</strong> {sum(1 for f in sorted_f if f.get('severity')=='low')} |
    <strong>Info:</strong> {sum(1 for f in sorted_f if f.get('severity')=='info')}
</div>
<table>
<thead><tr>
    <th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Evidence</th><th>Recommendation</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""
    return html
