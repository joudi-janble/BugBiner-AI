# BugBîner AI — Vulnerability catalog + update engine
# Author: Joudi Janble
#
# The catalog is DATA, not code: new vulnerability classes and their metadata can be
# merged in without touching the scanner. The Settings screen exposes a "Update"
# button that:
#   1. fetches an optional remote catalog JSON (config: vuln_catalog_url),
#   2. refreshes the local cache of the CISA Known Exploited Vulnerabilities feed,
# then reports exactly what changed.

from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CATALOG_PATH = os.path.join(BASE_DIR, "vuln_catalog.json")
KEV_PATH = os.path.join(BASE_DIR, "data", "kev_cache.json")
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

CACHE = {"mtime": None, "data": None}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def load() -> dict:
    try:
        mtime = os.path.getmtime(CATALOG_PATH)
        if CACHE["data"] is not None and CACHE["mtime"] == mtime:
            return CACHE["data"]
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("catalog root must be an object")
        data.setdefault("entries", [])
        data.setdefault("version", "0")
        CACHE["data"], CACHE["mtime"] = data, mtime
        return data
    except Exception:
        return {"version": "0", "last_updated": "", "entries": []}


def save(data: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(CATALOG_PATH), exist_ok=True)
        tmp = CATALOG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CATALOG_PATH)
        CACHE["data"], CACHE["mtime"] = None, None
        return True
    except Exception:
        return False


def entries(enabled_only: bool = True) -> list[dict]:
    data = load()
    out = []
    for e in data.get("entries") or []:
        if not isinstance(e, dict) or not e.get("id"):
            continue
        if enabled_only and e.get("enabled") is False:
            continue
        out.append(e)
    return out


def known_ids() -> set[str]:
    return {e["id"] for e in entries()}


def public() -> dict:
    data = load()
    return {
        "version": data.get("version") or "0",
        "last_updated": data.get("last_updated") or "",
        "source": data.get("source") or "",
        "count": len(entries()),
        "entries": [{
            "id": e["id"],
            "label": e.get("label") or e["id"],
            "group": e.get("group") or "Other",
            "severity": e.get("severity") or "medium",
            "engine": e.get("engine") or "",
            "description": e.get("description") or "",
        } for e in entries()],
        "kev": kev_summary(),
    }


# ── Canonicalisation: map any human/AI name to the catalog id ─────────────────
def canon(value: str) -> str:
    n = _norm(value)
    if not n:
        return ""
    for e in entries(enabled_only=False):
        if _norm(e.get("id")) == n or _norm(e.get("label")) == n:
            return e["id"]
        for a in e.get("aliases") or []:
            if _norm(a) == n:
                return e["id"]
    # common free-form variants
    table = {
        "crosssitescripting": "xss", "sqlinjection": "sqli", "nosqlinjection": "nosql",
        "serversidetemplateinjection": "ssti", "commandinjection": "cmdi",
        "remotecodeexecution": "cmdi", "rce": "cmdi", "localfileinclusion": "lfi",
        "pathtraversal": "lfi", "directorytraversal": "lfi",
        "xmlexternalentity": "xxe", "ldapinjection": "ldapi", "xpathinjection": "xpathi",
        "crlfinjection": "crlf", "responsesplitting": "crlf",
        "httpparameterpollution": "hpp", "insecuredeserialization": "deserialization",
        "typejuggling": "type_juggling", "serversiderequestforgery": "ssrf",
        "openredirect": "open_redirect", "hostheaderinjection": "host_header",
        "cachepoisoning": "cache_poison", "webcachepoisoning": "cache_poison",
        "requestsmuggling": "request_smuggling", "httpsmuggling": "request_smuggling",
        "prototypepollution": "prototype_pollution", "fileupload": "file_upload",
        "unrestrictedfileupload": "file_upload", "websocketsecurity": "websocket",
        "domxss": "dom_xss", "dombasedxss": "dom_xss",
        "crosssiterequestforgery": "csrf", "clickjacking": "clickjacking",
        "corsmisconfiguration": "cors", "insecuredirectobjectreference": "idor",
        "brokenobjectlevelauthorization": "idor", "bola": "idor",
        "brokenaccesscontrol": "access_control", "authorizationbypass": "access_control",
        "jsonwebtoken": "jwt", "graphqlintrospection": "graphql",
        "massassignment": "mass_assignment", "bopla": "mass_assignment",
        "missingratelimit": "rate_limit", "ratelimiting": "rate_limit",
        "bruteforce": "rate_limit", "informationdisclosure": "info_disclosure",
        "secretexposure": "secret_exposure", "apikeyexposure": "secret_exposure",
        "subdomaintakeover": "subdomain_takeover",
        "missingsecurityheaders": "security_headers", "securityheaders": "security_headers",
        "weaktls": "tls", "hsts": "tls", "ssltls": "tls",
        "racecondition": "race_condition", "toctou": "race_condition",
        "businesslogic": "business_logic", "logicflaw": "business_logic",
        "promptinjection": "prompt_injection", "llmpromptinjection": "prompt_injection",
    }
    return table.get(n, n)


# ── Remote catalog merge ──────────────────────────────────────────────────────
def _fetch_json(url: str, timeout: int = 25) -> dict:
    req = urllib.request.Request(url, headers={
        "User-Agent": "BugBiner-AI/v1 (+vulnerability-catalog-update)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _merge_entries(local: dict, remote: dict) -> tuple[int, int]:
    """Merge remote entries. Returns (added, updated)."""
    by_id = {e.get("id"): e for e in local.get("entries") or [] if isinstance(e, dict)}
    added = updated = 0
    for e in remote.get("entries") or []:
        if not isinstance(e, dict) or not e.get("id"):
            continue
        cur = by_id.get(e["id"])
        if cur is None:
            by_id[e["id"]] = e
            added += 1
        else:
            changed = False
            for k in ("label", "group", "severity", "description", "engine", "aliases"):
                if e.get(k) and e.get(k) != cur.get(k):
                    cur[k] = e[k]
                    changed = True
            if changed:
                updated += 1
    local["entries"] = list(by_id.values())
    return added, updated


def update(remote_url: str = "") -> dict:
    """Refresh the catalog from a remote JSON (optional) + CISA KEV cache."""
    out = {"ok": True, "added": 0, "updated": 0, "kev_count": 0,
           "version": load().get("version"), "messages": []}
    data = load()

    if remote_url:
        try:
            remote = _fetch_json(remote_url)
            if not isinstance(remote, dict) or not isinstance(remote.get("entries"), list):
                raise ValueError("remote catalog has no 'entries' list")
            added, updated = _merge_entries(data, remote)
            out["added"], out["updated"] = added, updated
            if remote.get("version"):
                data["version"] = str(remote["version"])
            data["source"] = remote_url
            out["messages"].append(f"Remote catalog: +{added} new, {updated} updated.")
        except Exception as e:
            out["messages"].append(f"Remote catalog unavailable: {e}")

    # CISA KEV feed → cache for "recent exploited vulnerabilities"
    try:
        kev = _fetch_json(KEV_URL, timeout=45)
        vulns = kev.get("vulnerabilities") or []
        os.makedirs(os.path.dirname(KEV_PATH), exist_ok=True)
        with open(KEV_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "fetched": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "catalogVersion": kev.get("catalogVersion"),
                "count": len(vulns),
                "vulnerabilities": vulns,
            }, f, ensure_ascii=False)
        out["kev_count"] = len(vulns)
        out["messages"].append(f"CISA KEV: {len(vulns)} known-exploited CVEs cached.")
    except Exception as e:
        out["messages"].append(f"CISA KEV feed unavailable (offline is fine): {e}")

    data["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if save(data):
        out["version"] = data.get("version")
    else:
        out["ok"] = False
        out["messages"].append("Could not write the catalog file.")
    out["count"] = len(entries())
    return out


def kev_summary(limit: int = 12) -> dict:
    try:
        with open(KEV_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        vulns = data.get("vulnerabilities") or []
        recent = sorted(vulns, key=lambda v: v.get("dateAdded") or "", reverse=True)[:limit]
        return {
            "available": True,
            "count": len(vulns),
            "fetched": data.get("fetched") or "",
            "recent": [{
                "cve": v.get("cveID") or "",
                "vendor": v.get("vendorProject") or "",
                "product": v.get("product") or "",
                "name": v.get("vulnerabilityName") or "",
                "date": v.get("dateAdded") or "",
                "ransomware": v.get("knownRansomwareCampaignUse") or "",
            } for v in recent],
        }
    except Exception:
        return {"available": False, "count": 0, "fetched": "", "recent": []}
