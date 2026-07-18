"""AI Analysis Engine — Ollama-classified finding validation + business logic detection.

Analyzes each finding with qwen2.5:7b to determine:
  1. Is this a TRUE vulnerability or a FALSE POSITIVE?
  2. What is the confidence level (0-100%)?
  3. What is the exploitation impact?
  4. Business logic flaws in multi-step flows.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.request
import urllib.error

_OLLAMA_URL = "http://localhost:11434/api/generate"
_MODEL = "qwen2.5:7b"


_SYSTEM_PROMPT = (
    "You are a senior offensive security researcher and bug bounty hunter with 10+ years experience. "
    "You specialise in web vulnerabilities: XSS, SQLi, IDOR, SSRF, CORS, CSP, path traversal, "
    "open redirect, header injection, and business-logic flaws. "
    "Your job is to classify findings as TRUE POSITIVE or FALSE POSITIVE with high precision. "
    "False positives are common — scanner heuristics often fire on benign patterns. "
    "Be sceptical: only mark real=true when evidence is convincing. "
    "Your output MUST be a single JSON object, no markdown, no extra text."
)


def _ask_ollama(prompt: str, max_retries=1) -> str:
    """Send a prompt to Ollama and return the response text."""
    for attempt in range(max_retries):
        try:
            data = json.dumps({
                "model": _MODEL,
                "system": _SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 1500, "num_ctx": 4096, "num_gpu": 99},
            }).encode()
            req = urllib.request.Request(_OLLAMA_URL, data=data,
                                          headers={"Content-Type": "application/json"},
                                          method="POST")
            with urllib.request.urlopen(req, timeout=35) as resp:
                result = json.loads(resp.read().decode())
                return (result.get("response") or "").strip()
        except Exception as e:
            logging.warning(f"Ollama attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                return ""
    return ""


def analyze_finding(finding: dict) -> dict:
    """Analyze a single finding with Ollama. Returns enriched finding dict."""
    vt       = finding.get("vuln_type", "")
    url      = finding.get("url", "")
    detail   = finding.get("detail", "")[:400]
    evidence = (finding.get("evidence") or "")[:600]
    payload  = (finding.get("payload") or "")[:200]
    severity = finding.get("severity", "")
    method   = finding.get("method", "GET")

    prompt = f"""Analyze this web vulnerability finding and decide if it is a TRUE POSITIVE or FALSE POSITIVE.

FINDING:
  Type     : {vt}
  Severity : {severity}
  Method   : {method}
  URL      : {url}
  Signal   : {detail}
  Payload  : {payload}
  Evidence : {evidence}

CONSIDERATIONS:
- For XSS: is the payload actually reflected unencoded in the HTML/JS context?
- For SQLi: is there a timing difference, error message, or data leak?
- For CORS: does ACAO reflect untrusted origin AND allow credentials?
- For SSRF: is an internal response actually returned?
- For headers: is the header truly absent or mismatched, not just present with weak value?
- For open redirect: does the Location header point to an external attacker-controlled domain?

Output ONLY this JSON object (no markdown, no explanation before or after):
{{
  "real": true or false,
  "confidence": integer 0-100,
  "reason": "2-3 sentences explaining your verdict with specific evidence references",
  "exploitability": "none|low|medium|high|critical",
  "attack_scenario": "concrete one-sentence attack scenario if real, else empty string",
  "impact": "specific impact on the application or user",
  "remediation": "concise fix recommendation"
}}"""

    raw = _ask_ollama(prompt)
    if not raw:
        finding["ai_analysis"] = {"real": True, "confidence": 50,
                                  "reason": "AI unavailable", "exploitability": "unknown"}
        return finding

    try:
        # Extract JSON from response
        m = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
        if not m:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            ai = json.loads(m.group())
        else:
            ai = json.loads(raw)
        finding["ai_analysis"] = {
            "real":            ai.get("real", True),
            "confidence":      int(ai.get("confidence", 50)),
            "reason":          ai.get("reason", ""),
            "exploitability":  ai.get("exploitability", "unknown"),
            "attack_scenario": ai.get("attack_scenario", ""),
            "impact":          ai.get("impact", ""),
            "remediation":     ai.get("remediation", ""),
        }
        # Mark as false positive if AI is highly confident it's not real
        if not ai.get("real", True) and int(ai.get("confidence", 0)) >= 80:
            if finding.get("severity") not in ("info",):
                finding["ai_filtered"] = True
                finding["detail"] = "[AI: FALSE POSITIVE] " + finding.get("detail", "")
    except Exception as e:
        # Retry with a minimal prompt to rescue incomplete/malformed JSON
        _short_p = (
            f'Is this a real vulnerability? Type="{vt}", URL="{url[:80]}", '
            f'signal="{(detail or evidence)[:150]}". '
            f'Reply ONLY valid JSON: {{"real":true,"confidence":75,"reason":"brief verdict"}}'
        )
        _raw2 = _ask_ollama(_short_p)
        try:
            _m2 = re.search(r"\{[^{}]*\}", _raw2 or "", re.DOTALL)
            if _m2:
                _ai2 = json.loads(_m2.group())
                finding["ai_analysis"] = {
                    "real": bool(_ai2.get("real", True)),
                    "confidence": int(_ai2.get("confidence", 60)),
                    "reason": _ai2.get("reason", ""),
                    "exploitability": "unknown",
                    "attack_scenario": "", "impact": "", "remediation": "",
                }
                return finding
        except Exception:
            pass
        finding["ai_analysis"] = {"real": True, "confidence": 50, "reason": f"AI parse error: {e}"}
    return finding


def analyze_business_logic(url: str, action: str, body_before: str, body_after: str,
                           status_before: int, status_after: int) -> dict:
    """Analyze a business-logic transition for anomalies."""
    prompt = f"""You are a web application security expert. Analyze this business operation:

URL: {url}
ACTION: {action}
BEFORE - Status: {status_before}, Body snippet: {body_before[:500]}
AFTER  - Status: {status_after}, Body snippet: {body_after[:500]}

Is there a business logic vulnerability? Examples:
- Privilege escalation (user can access admin functions)
- Race condition (unexpected state change)
- Parameter tampering (price/quantity modification reflected)
- IDOR (access to other users' data)
- Missing authorization step

Answer JSON:
{{
  "vulnerable": true/false,
  "type": "privilege-escalation/idor/race-condition/parameter-tampering/none",
  "confidence": 0-100,
  "evidence": "what specifically looks wrong"
}}"""
    raw = _ask_ollama(prompt)
    if not raw:
        return {"vulnerable": False, "type": "none", "confidence": 0}
    try:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return json.loads(m.group()) if m else {"vulnerable": False, "type": "none", "confidence": 0}
    except Exception:
        return {"vulnerable": False, "type": "none", "confidence": 0}


def generate_exploit(finding: dict) -> str:
    """Generate a PoC exploit command/script for a confirmed vulnerability."""
    vt = finding.get("vuln_type", "").lower()
    url = finding.get("url", "")
    payload = finding.get("payload", "")
    detail = finding.get("detail", "")
    proof = finding.get("proof", {})

    if "sqli" in vt or "sql injection" in vt:
        return f"""# SQLi PoC — run with: curl -X GET '{url.replace("'", "'\\''")}'
# Or use sqlmap:
# sqlmap -u '{url.split('?')[0]}' --data='{url.split('?')[1] if '?' in url else ''}' --batch --risk=3 --level=5
echo "[SQLi] Test with:"
curl -sk '{url}' -H 'User-Agent: Mozilla/5.0' | head -50"""
    elif "xss" in vt:
        return f"""# XSS PoC — save as poc.html and open in browser
<html><body><script>
window.open('{url.replace("'", "\\'")}')
</script></body></html>
echo "[XSS] Open poc.html in browser to verify"
echo "PoC saved to: reports/poc_{vt}.html" """
    elif "ssrf" in vt:
        oob = proof.get("ssrf_oob", {}).get("oob") or proof.get("oob_url", "")
        return f"# SSRF PoC\ncurl -sk '{url}' -H 'User-Agent: Mozilla/5.0'\necho 'Check OOB callback at: {oob}'"
    elif "cmdi" in vt or "command injection" in vt:
        return f"# Command Injection PoC\ncurl -sk '{url}' -H 'User-Agent: Mozilla/5.0'\necho 'Verify time delay or OOB callback'"
    elif "xxe" in vt:
        return f"""# XXE PoC
curl -sk -X POST '{url}' \\
  -H 'Content-Type: application/xml' \\
  -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'"""
    elif "open" in vt and "redirect" in vt:
        loc = proof.get("redirect_x", {}).get("location", url)
        return f"# Open Redirect PoC\ncurl -sk -I '{loc.replace('evil.com', 'attacker.com')}'"
    else:
        return f"# {vt} PoC\ncurl -sk '{url}' -H 'User-Agent: Mozilla/5.0'\necho 'Review response manually'"


def analyze_all_findings(findings: list, batch_size=5) -> list:
    """Batch-analyze all findings with AI. Returns enriched findings."""
    enriched = []
    for i, f in enumerate(findings):
        if i >= batch_size:
            enriched.append(f)
            continue
        try:
            enriched.append(analyze_finding(f))
        except Exception:
            enriched.append(f)

    # Generate exploits for confirmed real findings
    for f in enriched:
        ai = f.get("ai_analysis", {})
        if ai.get("real") and ai.get("exploitability", "unknown") in ("high", "critical"):
            try:
                f["exploit_poc"] = generate_exploit(f)
            except Exception:
                pass
    return enriched
