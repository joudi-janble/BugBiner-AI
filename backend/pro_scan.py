"""Runtime glue that runs the detectors_pro checks during a live scan and returns findings
in the EXACT dict shape main.py already emits, plus any out-of-band (OAST) injections to
correlate at scan end. One blocking entry point — call it via run_in_executor like
de.scan_all_points, then emit the returned findings.

Design goals (same as the rest of the engine):
  * never raise into the scan loop (every hook is guarded),
  * only surface confirmed/probable results,
  * be cheap: host-level checks run once per host, JS mining only on JS, OOB is capped.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import detectors_pro as dpro
import detect_engine as de
import detect_extras as dx

_CVSS = {"critical": "9.5", "high": "7.5", "medium": "5.3", "low": "3.1", "info": "0.0"}
_REC = {
    "access-control": "Enforce server-side authorization on every object/endpoint (deny by default).",
    "jwt": "Verify signatures; reject alg:none/alg-confusion; use a long random secret; set exp.",
    "graphql": "Disable introspection in production; cap query depth/complexity; disable batching if unused.",
    "nosql": "Use typed/parameterized queries; reject operator objects ($ne/$gt) in user input.",
    "mass-assignment": "Bind only an explicit allow-list of fields (DTO); never bind privileged props.",
    "info-disclosure": "Remove exposed VCS/secret files from the web root; rotate any leaked secret.",
    "secret-exposure": "Rotate the leaked credential and remove it from client-served assets.",
    "subdomain-takeover": "Remove the dangling DNS record or reclaim the resource.",
    "csrf": "Require an anti-CSRF token and SameSite=Lax/Strict on state-changing requests.",
    "clickjacking": "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    "rate-limit": "Throttle / lock-out auth-sensitive endpoints (login, OTP, reset).",
    "xss": "Encode output per context; avoid dangerous DOM sinks on untrusted sources.",
}


def _finding(res, url):
    sev = res.severity or "medium"
    return {
        "vuln_type": res.vuln.upper().replace("-", " "),
        "severity": sev,
        "url": res.url or url,
        "detail": "; ".join(res.signals[:4]) or res.vuln,
        "evidence": (res.evidence or "")[:600],
        "payload": res.payload or "",
        "cvss": _CVSS.get(sev, ""),
        "proof": res.proof or {},
        "recommendation": _REC.get(res.vuln, ""),
    }


def _confirmedish(res):
    return res is not None and res.confidence in (de.CONFIRMED, de.PROBABLE)


def run_url_checks(send, url, *, status=0, page_headers=None, cookies=None,
                   allowed=frozenset(), host_first_seen=False, is_js=False,
                   new_oob=None, ua="Mozilla/5.0", max_oob=12) -> dict:
    """send(method,url,headers,cookies,body,follow)->de.Resp (blocking).
       new_oob()->(token, host) | (None,'') registers an OAST correlation id.
    Returns {"findings":[dict...], "oob_pending":[(token,vtype,url,detail)...]}."""
    findings, oob_pending = [], {}
    cookies = cookies or {}
    H = {"User-Agent": ua}
    pr = urlparse(url)
    base = f"{pr.scheme}://{pr.netloc}"

    def _add(res):
        if _confirmedish(res):
            findings.append(_finding(res, url))

    # ── 1) 403 / authorization bypass (only when the origin actually denies) ──
    try:
        if status in (401, 403):
            _add(dpro.detect_403_bypass(send, "GET", url, H, cookies))
    except Exception:
        pass

    # ── 3) CORS misconfiguration (passive + active) ──
    try:
        _add(dx.detect_cors(send, url, page_headers or {}))
    except Exception:
        pass

    # ── 4) Open redirect (passive) ──
    try:
        _add(dx.detect_open_redirect(send, url, page_headers=page_headers or {}))
    except Exception:
        pass

    # ── 5) Clickjacking on the document (once per host, real HTML response only) ──
    if host_first_seen:
        try:
            ph = page_headers or {}
            hl = {k.lower(): v for k, v in ph.items()}
            if "content-type" not in hl:        # crawler omits headers → fetch the real ones
                rr = send("GET", url, H, cookies, "", True)
                if rr is not None and not de.is_blocked(rr):
                    ph = rr.headers or {}
                    hl = {k.lower(): v for k, v in ph.items()}
            if "html" in str(hl.get("content-type", "")).lower():
                _add(dpro.detect_clickjacking(ph, sensitive=True))
                # Also run upgraded version
                _body = (rr.body or "") if rr else ""
                _add(dx.detect_clickjacking_ext(ph, _body))
        except Exception:
            pass

    # ── 6) TLS / HSTS (passive, once per host) ──
    if host_first_seen:
        try:
            _add(dx.detect_tls_weak(page_headers or {}, _uparse.urlparse(url).scheme, url))
        except Exception:
            pass

    # ── 7) JWT audit on session cookies (upgraded) ──
    try:
        for ck, cv in cookies.items():
            if str(cv).count(".") == 2:
                jr = dx.detect_jwt_full(cv, url)
                if _confirmedish(jr):
                    f = _finding(jr, url)
                    f["detail"] = f"JWT in cookie '{ck}': " + f["detail"]
                    findings.append(f)
                break
    except Exception:
        pass

    # ── 9) Host-level: exposed VCS/.env + GraphQL introspection + extras ──
    if host_first_seen:
        def _fetch(path):
            return send("GET", f"{base}/{path}", H, cookies, "", True)
        try:
            for r in dpro.detect_exposed_vcs(_fetch):
                findings.append(_finding(r, base + "/" + (r.proof or {}).get("path", "")))
        except Exception:
            pass
        # Path/File discovery (DirBuster-style)
        try:
            for _pf in de.discover_paths(_fetch, base, max_findings=15):
                findings.append(_pf)
        except Exception:
            pass

        # Host Header Injection
        try:
            _add(dx.detect_host_header_injection(send, url))
        except Exception:
            pass

        # Cache Poisoning
        try:
            _add(dx.detect_cache_poisoning(send, url))
        except Exception:
            pass

        # File Upload Bypass
        try:
            _add(dx.detect_file_upload_bypass(send, base))
        except Exception:
            pass

        # GraphQL endpoints (upgraded)
        gql_paths = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query", "/api"]
        if pr.path and pr.path.rstrip("/").endswith("graphql"):
            gql_paths.insert(0, pr.path)
        seen_gql = False
        for gp in gql_paths:
            if seen_gql:
                break
            gurl = base + gp

            def _post(body, _gurl=gurl):
                return send("POST", _gurl, {**H, "Content-Type": "application/json"}, cookies, body, True)
            try:
                gr = dpro.detect_graphql(_post) or dx.detect_graphql_ext(_post)
            except Exception:
                gr = None
            if _confirmedish(gr):
                seen_gql = True
                findings.append(_finding(gr, gurl))

    # ── 5) JS secret + endpoint mining (only on JS assets) ──
    if is_js:
        try:
            r = send("GET", url, H, cookies, "", True)
            body = (r.body or "") if r else ""
            for sr in dpro.mine_js_secrets(body):
                findings.append(_finding(sr, url))
            _add(dpro.scan_dom_sinks(body))   # static DOM source→sink (confirm via browser engine)
            eps = dpro.mine_js_endpoints(body)
            if eps:
                interesting = [e for e in eps if any(k in e.lower() for k in
                              ("admin", "api", "internal", "token", "secret", "key", "debug",
                               "graphql", "upload", "user", "account", "v1", "v2"))][:15]
                if interesting:
                    findings.append({
                        "vuln_type": "INFO DISCLOSURE", "severity": "info", "url": url,
                        "detail": f"{len(eps)} endpoints mined from JS; notable: " + ", ".join(interesting[:8]),
                        "evidence": ", ".join(interesting), "payload": "", "cvss": "0.0",
                        "proof": {"endpoints": interesting},
                        "recommendation": "Review exposed endpoints for missing authorization / hidden functionality.",
                    })
        except Exception:
            pass

    # ── 6) Out-of-band (blind) — Collaborator-Everywhere headers + blind CMDi/LFI in params ──
    if callable(new_oob) and any(t in allowed for t in ("ssrf", "cmdi", "lfi", "xxe")):
        spent = [0]

        def _tok():
            if spent[0] >= max_oob:
                return None, ""
            spent[0] += 1
            return new_oob()

        params = parse_qsl(pr.query, keep_blank_values=True)

        # (a) SSRF/host via injected request headers (the missing Collaborator-Everywhere vector)
        if "ssrf" in allowed:
            tok, host = _tok()
            if tok:
                hh = dict(H)
                for hk, hv in dpro.oob_payloads(host)["headers"].items():
                    hh[hk] = hv
                try:
                    send("GET", url, hh, cookies, "", True)
                    oob_pending[tok] = (tok, "SSRF (header)", url,
                                        "injected OAST host into forwarding headers (X-Forwarded-For/True-Client-IP/Referer)")
                except Exception:
                    pass

        # (b) blind CMDi in each param (interactsh linkage that was missing)
        if "cmdi" in allowed and params:
            for pk, _pv in params[:4]:
                tok, host = _tok()
                if not tok:
                    break
                pl = dpro.oob_payloads(host)["cmdi"][0]
                q = dict(params); q[pk] = pl
                ourl = urlunparse(pr._replace(query=urlencode(q)))
                try:
                    send("GET", ourl, H, cookies, "", True)
                    oob_pending[tok] = (tok, "CMDi (blind)", ourl, f"blind OS-command OOB via param '{pk}'")
                except Exception:
                    pass

        # (c) blind LFI/SSRF wrapper in each param
        if ("lfi" in allowed or "ssrf" in allowed) and params:
            for pk, _pv in params[:3]:
                tok, host = _tok()
                if not tok:
                    break
                pl = dpro.oob_payloads(host)["ssrf"][0]
                q = dict(params); q[pk] = pl
                ourl = urlunparse(pr._replace(query=urlencode(q)))
                try:
                    send("GET", ourl, H, cookies, "", True)
                    oob_pending[tok] = (tok, "SSRF (param)", ourl, f"blind SSRF OOB via param '{pk}'")
                except Exception:
                    pass

    return {"findings": findings, "oob_pending": list(oob_pending.values())}


def run_form_checks(send_fields, send_op=None, url="") -> list:
    """Body-level API checks for a JSON/form endpoint:
       send_fields(extra:dict)->Resp merges extra keys into the body (mass assignment).
       send_op(value)->Resp places `value` (maybe an operator object) at a JSON leaf (NoSQL).
    Returns finding dicts."""
    out = []
    try:
        r = dpro.detect_mass_assignment(send_fields)
        if _confirmedish(r):
            out.append(_finding(r, url))
    except Exception:
        pass
    if send_op is not None:
        try:
            r = dpro.detect_nosql_operator(send_op)
            if _confirmedish(r):
                out.append(_finding(r, url))
        except Exception:
            pass
    return out


def run_access_control(victim_send, attacker_send=None, anon_send=None,
                       attacker_own_send=None, url="") -> list:
    """Two-identity authorization check (IDOR/BOLA). Returns finding dicts (confirmed/probable)."""
    out = []
    try:
        r = dpro.detect_access_control(victim_send, attacker_send, anon_send, attacker_own_send)
        if _confirmedish(r):
            out.append(_finding(r, url))
    except Exception:
        pass
    return out
