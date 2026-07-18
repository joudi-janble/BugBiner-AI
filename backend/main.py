# BugBîner AI — FastAPI Server
# Real-time WebSocket exploit streaming
# Author: Joudi Janble

import asyncio
import functools
import json
import logging
import os
import re
import sys
import urllib.parse as _uparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

sys.path.insert(0, os.path.dirname(__file__))
from config import load_config, save_config

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
# Shared adaptive detection engine (same logic for deep scan and runtime)
sys.path.insert(0, BASE_DIR)
try:
    import detect_engine as de
except Exception:
    de = None
try:
    import oast as _oast_mod            # OAST/interactsh client for blind (out-of-band) vulns
except Exception:
    _oast_mod = None
try:
    import browser_engine as _browser_mod   # Playwright DOM-XSS detector
except Exception:
    _browser_mod = None
try:
    import detectors_pro as _dpro_mod        # high-value detectors (access-control/JWT/GraphQL/…)
except Exception:
    _dpro_mod = None
try:
    import pro_scan as ps                    # runtime glue that runs the pro detectors
except Exception:
    ps = None
try:
    import turbo as _turbo                   # Burp-class advanced modules (Intruder, Repeater, Session, PP, Sequencer, WS, Smuggling, DOM XSS, Report)
except Exception:
    _turbo = None
# interactsh-client binary (downloaded into ../tools); OAST is enabled only if present
_OAST_EXE = os.path.join(BASE_DIR, "..", "tools", "interactsh-client.exe")

_PROJ_ROOT = os.path.normpath(os.path.join(BASE_DIR, ".."))
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Dedicated thread pool for the scanner's BLOCKING HTTP work (detect_engine.scan_all_points).
# These calls hold a thread for many seconds. If they ran on asyncio's DEFAULT executor they
# would starve it — and aiohttp resolves DNS (getaddrinfo) on that same default executor, so the
# chat's connection to Ollama would time out during a heavy scan. Keeping scan work on its own
# pool leaves the default executor free, so chat (and all async I/O) stays responsive mid-scan.
_DET_POOL = ThreadPoolExecutor(max_workers=24, thread_name_prefix="det")
# Playwright's sync API is thread-affine: the browser MUST be created and used on the same
# thread. A dedicated single-worker pool guarantees every DOM op runs on that one thread.
_DOM_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dom")

# Single local model only: qwen2.5:7b via Ollama (no cloud providers)


app = FastAPI(title="BugBîner AI", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Single model (qwen2.5:7b) serves both scanning and chat via parallel channels (OLLAMA_NUM_PARALLEL) ──
# Chat and scan both send to the same model but in parallel execution slots, so neither blocks the other.


@app.on_event("startup")
async def _warmup_ollama():
    """Warm up the model in the background — does not block server startup (serves requests immediately)."""
    async def _do_warm():
        import aiohttp as _ah
        cfg = load_config()
        base = cfg.get("ollama_base", "http://localhost:11434")
        models = [m for m in [cfg.get("ollama_model") or "qwen2.5:7b", cfg.get("vision_model")] if m]
        seen = set(); models = [m for m in models if not (m in seen or seen.add(m))]
        for model in models:
            try:
                async with _ah.ClientSession() as s:
                    await s.post(f"{base}/api/generate",
                        json={"model": model, "prompt": "hi", "keep_alive": "30m",
                              "stream": False, "options": {"num_ctx": 4096}},
                        timeout=_ah.ClientTimeout(total=120))
                logging.info(f"Ollama {model} warmed up")
            except Exception as e:
                logging.warning(f"Ollama warmup {model} failed: {e}")
    # Run it as a background task so the server starts accepting requests immediately
    asyncio.create_task(_do_warm())

# ── Config endpoints ──────────────────────────────────────────────────────────
@app.get("/api/config")
async def get_config():
    cfg = load_config()
    return {
        "ollama_enabled":   cfg.get("ollama_enabled", True),
        "ollama_base":      cfg.get("ollama_base", "http://localhost:11434"),
        "ollama_model":     cfg.get("ollama_model", "qwen2.5:7b"),
        "vision_model":     cfg.get("vision_model", ""),
    }


@app.post("/api/config")
async def update_config(request: Request):
    body = await request.json()
    save_config({k: v for k, v in body.items() if v is not None})
    return {"status": "saved"}


# ── Projects endpoints ─────────────────────────────────────────────────────────
_SKIP_DIRS = {"backend", "frontend", "reports", ".venv", ".git", "__pycache__",
               "node_modules", ".mypy_cache", ".pytest_cache", "dist", "build"}

@app.get("/api/projects")
async def list_projects():
    """List all project/target folders in the workspace root."""
    projects = []
    try:
        for entry in os.scandir(_PROJ_ROOT):
            if not entry.is_dir():
                continue
            if entry.name.startswith('.') or entry.name in _SKIP_DIRS:
                continue
            try:
                file_count = sum(1 for f in os.scandir(entry.path) if f.is_file())
            except Exception:
                file_count = 0
            projects.append({
                "name":       entry.name,
                "path":       entry.path,
                "file_count": file_count,
                "modified":   int(entry.stat().st_mtime),
            })
    except Exception:
        pass
    return sorted(projects, key=lambda x: x["modified"], reverse=True)


@app.get("/api/projects/{name:path}")
async def get_project(name: str):
    """List files/folders inside a project (max 2 levels deep)."""
    safe = re.sub(r'[^\w\.\-]', '', name)
    if not safe:
        return JSONResponse({"error": "Invalid name"}, status_code=400)
    proj_path = os.path.join(_PROJ_ROOT, safe)
    if not os.path.isdir(proj_path):
        return JSONResponse({"error": "Not found"}, status_code=404)

    def _scan(path, depth=0):
        items = []
        try:
            for entry in sorted(os.scandir(path), key=lambda e: (e.is_file(), e.name)):
                if entry.name.startswith('.') or entry.name == '__pycache__':
                    continue
                item = {"name": entry.name, "path": entry.path, "is_dir": entry.is_dir()}
                if entry.is_dir() and depth < 1:
                    item["children"] = _scan(entry.path, depth + 1)
                elif entry.is_file():
                    item["size"]     = entry.stat().st_size
                    item["modified"] = int(entry.stat().st_mtime)
                items.append(item)
        except Exception:
            pass
        return items

    return {"name": safe, "path": proj_path, "files": _scan(proj_path)}


@app.get("/api/browse")
async def browse_filesystem(path: str = ""):
    """Browse any folder on the local filesystem. Empty path returns drives list."""
    import string as _str
    # Return available drives if no path given
    if not path:
        drives = [f"{d}:\\" for d in _str.ascii_uppercase if os.path.exists(f"{d}:\\")]
        return {"path": "", "parent": None, "drives": drives, "items": []}

    abs_path = os.path.normpath(path)
    if not os.path.isdir(abs_path):
        return JSONResponse({"error": "Not a directory"}, status_code=404)

    # Compute parent path
    parent = str(os.path.dirname(abs_path))
    if parent == abs_path:   # at drive root
        parent = None

    items = []
    try:
        entries = sorted(os.scandir(abs_path), key=lambda e: (e.is_file(), e.name.lower()))
        for entry in entries:
            if entry.name.startswith('.') or entry.name in ('$Recycle.Bin', 'System Volume Information'):
                continue
            try:
                item = {"name": entry.name, "path": entry.path, "is_dir": entry.is_dir()}
                if entry.is_file():
                    item["size"] = entry.stat().st_size
                items.append(item)
            except PermissionError:
                continue
    except PermissionError:
        return JSONResponse({"error": "Permission denied"}, status_code=403)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return {"path": abs_path, "parent": parent, "drives": None, "items": items}




# ── HackerOne Scope Fetcher ───────────────────────────────────────────────────
@app.post("/api/hackerone/scope")
async def fetch_h1_scope(request: Request):
    """Fetch scope information from a HackerOne program page and return structured data."""
    import aiohttp as _ah
    body = await request.json()
    url = (body.get("url") or "").strip()

    if not url:
        return JSONResponse({"error": "No URL provided"}, status_code=400)

    # Extract program handle
    m = re.search(r'hackerone\.com/([^/?#\s]+)', url, re.IGNORECASE)
    if not m:
        return JSONResponse({"error": "Invalid HackerOne URL"}, status_code=400)

    handle = m.group(1).strip("/")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
    }

    in_scope: list = []
    out_scope: list = []
    message: str = ""

    try:
        async with _ah.ClientSession(headers=headers) as s:
            async with s.get(
                f"https://hackerone.com/{handle}",
                timeout=_ah.ClientTimeout(total=20),
                allow_redirects=True,
            ) as resp:
                if resp.status == 404:
                    return JSONResponse({"error": "Program not found"}, status_code=404)
                if resp.status == 401 or resp.status == 403:
                    return JSONResponse({"error": "Program is private — login required"}, status_code=403)
                text = await resp.text(errors="replace")

        # ── Try __NEXT_DATA__ JSON embedded in page ──────────────────────────
        nd_m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', text, re.DOTALL)
        if nd_m:
            try:
                nd = json.loads(nd_m.group(1))
                # Walk common paths for scope nodes
                program = (
                    nd.get("props", {}).get("pageProps", {}).get("program")
                    or nd.get("props", {}).get("pageProps", {}).get("data", {}).get("program")
                )
                if program:
                    nodes = (
                        program.get("relationships", {}).get("scopes", {}).get("nodes", [])
                        or program.get("scopes", {}).get("nodes", [])
                        or []
                    )
                    for node in nodes:
                        identifier = (node.get("identifier") or node.get("asset_identifier") or "").strip()
                        asset_type = node.get("asset_type", "URL")
                        eligible_bounty = node.get("eligible_for_bounty", False)
                        eligible_sub    = node.get("eligible_for_submission", True)
                        scope_type      = node.get("scope_type", "in")
                        item = {
                            "identifier": identifier,
                            "asset_type": asset_type,
                            "eligible_for_bounty": eligible_bounty,
                            "eligible_for_submission": eligible_sub,
                        }
                        if scope_type == "out":
                            out_scope.append(item)
                        elif eligible_sub:
                            in_scope.append(item)
            except Exception:
                pass

        # ── Fallback: scan rendered HTML for scope table rows ────────────────
        if not in_scope and not out_scope:
            # HackerOne renders scope tables with data-asset-identifier attributes
            identifiers = re.findall(r'data-asset-identifier="([^"]+)"', text)
            types_raw   = re.findall(r'data-asset-type="([^"]+)"', text)
            if identifiers:
                for i, ident in enumerate(identifiers):
                    in_scope.append({
                        "identifier": ident,
                        "asset_type": types_raw[i] if i < len(types_raw) else "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                    })

        # ── Fallback 2: regex on text-rendered scope section ─────────────────
        if not in_scope and not out_scope:
            stripped = re.sub(r'<[^>]+>', ' ', text)
            stripped = re.sub(r'\s+', ' ', stripped)
            # Look for lines that look like domains / wildcards
            domain_re = re.compile(
                r'(?<!\w)((?:\*\.)?[\w\-]+\.[\w\-]+(?:\.[\w\-]+)*(?:/[^\s<>]{0,60})?)'
            )
            found_domains = domain_re.findall(stripped)
            # Deduplicate and filter noise
            seen = set()
            for d in found_domains:
                d = d.strip(".,;")
                if d in seen or len(d) > 120:
                    continue
                if re.search(r'\.(css|js|png|jpg|gif|svg|woff|ico)$', d, re.I):
                    continue
                seen.add(d)
                in_scope.append({
                    "identifier": d,
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                })
                if len(in_scope) >= 20:
                    break

        if not in_scope and not out_scope:
            message = "Could not extract scope — the program may be private or require login"

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    # ── Infer allowed vulnerability types from in-scope asset types ──────────
    asset_types = {s["asset_type"].upper() for s in in_scope}
    allowed_vulns: list[str] = []
    # Web / URL assets → full web vuln set
    if asset_types & {"URL", "WILDCARD", "DOMAIN", "WEB_APPLICATION", ""}:
        allowed_vulns += ["XSS", "SQLi", "SSRF", "LFI", "IDOR", "Open Redirect",
                          "SSTI", "XXE", "CMDi", "Security Headers"]
    # API
    if asset_types & {"API", "URL", "DOMAIN", "WILDCARD", "WEB_APPLICATION", ""}:
        if "SQLi" not in allowed_vulns:
            allowed_vulns += ["SQLi", "SSRF", "IDOR"]
    # Source code → code review oriented
    if "SOURCE_CODE" in asset_types:
        allowed_vulns += ["Hardcoded Secrets", "Insecure Dependencies"]
    # Remove dupes preserving order
    seen_v: set = set()
    allowed_vulns = [v for v in allowed_vulns if not (v in seen_v or seen_v.add(v))]

    return {
        "handle": handle,
        "in_scope": in_scope,
        "out_scope": out_scope,
        "allowed_vuln_types": allowed_vulns,
        "message": message,
    }



# ── Agent: execute script, stream output ─────────────────────────────────────
@app.post("/api/exec")
async def exec_script(request: Request):
    body = await request.json()
    code = (body.get("code") or "").strip()
    lang = (body.get("lang") or "python").lower()
    target_dir = (body.get("target_dir") or "unknown_target").strip()
    script_name = re.sub(r'[^\w\-]', '_', (body.get("script_name") or "scan").strip())[:40] or "scan"
    if not code:
        return JSONResponse({"error": "No code provided"}, status_code=400)

    _scripts_dir = os.path.join(_PROJ_ROOT, target_dir)
    os.makedirs(_scripts_dir, exist_ok=True)

    ext = {"python": ".py", "powershell": ".ps1", "bash": ".sh", "batch": ".bat"}.get(lang, ".py")
    _ts = datetime.now().strftime("%H%M%S")
    fname = os.path.join(_scripts_dir, f"{script_name}_{_ts}{ext}")

    # Prepend UTF-8 fix for Python scripts to avoid Windows cp1252 errors
    if lang == "python":
        utf8_header = "import sys, io\nsys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')\nsys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')\n\n"
        code = utf8_header + code
        # Priority 2: Syntax check before saving/running
        try:
            compile(code, "<agent_script>", "exec")
        except SyntaxError as se:
            def _err_stream():
                yield "data: " + json.dumps({"level": "exec_err", "message": f"Syntax error: {se}"}) + "\n\n"
                yield "data: " + json.dumps({"level": "exec_exit", "code": 1}) + "\n\n"
                yield "data: [DONE]\n\n"
            return StreamingResponse(_err_stream(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    with open(fname, "w", encoding="utf-8") as _f:
        _f.write(code)

    if lang == "python":
        _py = os.path.join(_PROJ_ROOT, ".venv", "Scripts", "python.exe")
        if not os.path.exists(_py):
            _py = sys.executable
        cmd = [_py, "-u", fname]  # -u = unbuffered
    elif lang == "powershell":
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", fname]
    elif lang == "bash":
        cmd = ["bash", fname]
    else:
        cmd = [fname]

    def _sse_exec(level, msg):
        return "data: " + json.dumps({"level": level, "message": msg}) + "\n\n"

    async def _stream():
        yield _sse_exec("exec_start", f"Running: {target_dir}/{os.path.basename(fname)}")
        exit_code = -1
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=_PROJ_ROOT,
                env=env,
            )
            # Hard timeout: 60s max per script
            try:
                async def _read():
                    while True:
                        line = await proc.stdout.readline()
                        if not line:
                            break
                        yield line.decode("utf-8", errors="replace").rstrip()
                async for out_line in _read():
                    yield _sse_exec("exec_out", out_line)
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                proc.kill()
                yield _sse_exec("exec_err", "[TIMEOUT] Script exceeded 60s limit — killed.")
                exit_code = -9
            else:
                exit_code = proc.returncode
            if exit_code != -9:
                status = "Done" if exit_code == 0 else f"Error (code {exit_code})"
                yield _sse_exec("exec_done", f"{status} • Script: {target_dir}/{os.path.basename(fname)}")
        except Exception as e:
            yield _sse_exec("exec_err", f"Error: {e}")
        yield "data: " + json.dumps({"level": "exec_exit", "code": exit_code}) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Local agentic chat helpers (local model only) ──────────────────────────────
_AGENT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
             "AppleWebKit/537.36 Chrome/124.0 Safari/537.36")


def _trim_ctx(ctx: str, limit: int) -> str:
    """Trim context at line boundaries (does not cut JSON/data in the middle)."""
    if not ctx or len(ctx) <= limit:
        return ctx or ""
    cut = ctx[:limit]
    nl = cut.rfind("\n")
    return cut[:nl] if nl > limit * 0.5 else cut


# Tools available to the chat agent (Ollama function-calling format)
CHAT_AGENT_TOOLS = [
    {"type": "function", "function": {
        "name": "make_request",
        "description": ("Send a REAL HTTP request to a URL and read the live response "
                        "(status, headers, body). Use this to investigate/verify before claiming anything."),
        "parameters": {"type": "object", "properties": {
            "url":     {"type": "string", "description": "Full URL to request"},
            "method":  {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]},
            "headers": {"type": "object", "description": "Optional extra headers"},
            "body":    {"type": "string", "description": "Optional request body"},
        }, "required": ["url"]},
    }},
    {"type": "function", "function": {
        "name": "run_python",
        "description": ("Write and execute a Python script on the server to verify/exploit a vulnerability. "
                        "Returns stdout+stderr. Use the 'requests' library, timeout=10, max ~15 requests, 60s limit. "
                        "CRITICAL: the script MUST actually CALL the function and PRINT results with print() — "
                        "print [FOUND]/[SAFE]/[INFO] lines and end with 'VERDICT: VULNERABLE' or 'VERDICT: SAFE'. "
                        "A script with no print() produces no output and is useless. Saved inside the TARGET's folder."),
        "parameters": {"type": "object", "properties": {
            "code": {"type": "string", "description": "Complete Python source to run"},
            "name": {"type": "string", "description": "Short snake_case name describing what the script tests, "
                                                      "e.g. xss_test, sqli_probe, idor_check, ssrf_scan"},
        }, "required": ["code"]},
    }},
    {"type": "function", "function": {
        "name": "run_security_test",
        "description": ("FAST + DEEP + PRECISE: build and run a COMPREHENSIVE prebuilt security test against a URL. "
                        "It sends a baseline request first, then tests many payloads with low-false-positive "
                        "detection (unescaped reflection for XSS, evaluated math for SSTI, baseline-relative timing "
                        "for SQLi). PREFER this over run_python for standard web vulns. "
                        "IMPORTANT: if a SPECIFIC payload/URL was seen in an image or given by the user, pass it in "
                        "'payload' so the EXACT vulnerability is verified first (not just generic payloads). "
                        "Returns the live results + VERDICT (VULNERABLE/SAFE) with confidence + evidence."),
        "parameters": {"type": "object", "properties": {
            "url":       {"type": "string", "description": "Full target URL (include query params if any)"},
            "vuln_type": {"type": "string", "enum": ["xss", "sqli", "lfi", "ssrf", "open_redirect", "ssti", "cmdi"],
                          "description": "Vulnerability class to test"},
            "param":     {"type": "string", "description": "Optional: query param name to inject into"},
            "payload":   {"type": "string", "description": "Optional but PREFERRED: the exact payload observed "
                          "(e.g. from the image/context). It is tested FIRST so the verdict matches the real vuln."},
        }, "required": ["url", "vuln_type"]},
    }},
]


# ── Professional payload library (deep scripts are built from it instantly — fast + reliable) ──
_SEC_PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>", "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>", "javascript:alert(1)",
    ],
    "sqli": [
        "'", "\"", "' OR '1'='1", "' OR '1'='1'-- ", "\" OR \"1\"=\"1",
        "1' ORDER BY 1-- ", "1' UNION SELECT NULL-- ", "' AND SLEEP(5)-- ",
        "1; WAITFOR DELAY '0:0:5'-- ", "' OR SLEEP(5)#",
    ],
    "lfi": [
        "../../../../etc/passwd", "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd", "../../../../proc/self/environ",
        "../../../../windows/win.ini", "....\\\\....\\\\windows\\\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini", "C:\\\\windows\\\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=index",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/", "http://localhost/", "file:///etc/passwd",
    ],
    "open_redirect": [
        "https://evil.example.com", "//evil.example.com",
        "https:evil.example.com", "/\\evil.example.com",
        "https://evil.example.com/%2f..",
    ],
    # Distinctive numbers (product 1788906) do not appear naturally in pages → precise SSTI detection with no false positives
    "ssti": ["{{1337*1338}}", "${1337*1338}", "<%= 1337*1338 %>",
             "#{1337*1338}", "{{1337*1338}}", "*{1337*1338}"],
    # OS command injection via GET parameter — detected by id/uid output or time delay
    "cmdi": [";id", "|id", "&&id", "`id`", "$(id)", ";whoami", "|whoami",
             "& whoami", "%0aid", "; sleep 5", "| sleep 5", "$(sleep 5)",
             "`sleep 5`", "& ping -n 5 127.0.0.1 &"],
}


# ── Shared verification helpers for all detectors (reducing false positives at the root) ──────────
_WAF_BLOCK_SIGNS = (
    "blocked by", "request was blocked", "cloudflare", "attention required",
    "403 forbidden", "access denied", "web application firewall",
    "challenge page", "akamai", "incapsula", "imperva", "mod_security",
    "cf-ray", "captcha", "are you human",
)
_THEORETICAL_SIGNS = (
    "could be exploited if", "improperly sanitized", "if user input",
    "may be vulnerable", "might be vulnerable", "potentially vulnerable",
    "could allow", "if not sanitized", "in theory", "theoretically",
)


def _finding_blocked_or_theoretical(*texts) -> bool:
    """True if the text indicates a WAF/Cloudflare block or an unconfirmed theoretical claim."""
    blob = " ".join(t for t in texts if t).lower()
    return (any(s in blob for s in _WAF_BLOCK_SIGNS)
            or any(s in blob for s in _THEORETICAL_SIGNS))


# ── Classify the response: did the origin actually serve it, or did a WAF/Cloudflare block it? ───────────
# Any vuln proof built on a block/challenge page is a false positive. Called from all detection
# paths (pre-test / make_request / live-verify / prebuilt script) to unify the guard.
_WAF_RESP_HEADERS = ("cf-ray", "cf-mitigated", "x-sucuri-id", "x-datadome",
                     "x-distil-cs", "x-iinfo")
_WAF_BODY_MARKERS = (
    "attention required! | cloudflare", "checking your browser before accessing",
    "just a moment...", "you have been blocked", "sorry, you have been blocked",
    "request unsuccessful. incapsula incident", "ddos protection by",
    "verify you are human", "enable javascript and cookies to continue",
    "this request has been blocked", "performance & security by cloudflare",
    "cf-error-details", "/cdn-cgi/challenge-platform",
)


def _response_blocked(status, headers, body) -> bool:
    """True if the response is a WAF block/challenge page rather than an actual reply from the origin.

    Deliberately conservative to avoid rejecting real vulnerabilities: requires either (a block
    status + a WAF header/server) or an explicit challenge phrase at the start of the body — merely
    mentioning 'cloudflare' on a normal page is not enough.
    """
    try:
        st = int(status or 0)
    except Exception:
        st = 0
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    server = h.get("server", "")
    if st in (401, 403, 429, 503) and (
            "cloudflare" in server or "akamai" in server or "sucuri" in server
            or any(k in h for k in _WAF_RESP_HEADERS)):
        return True
    head = (body or "")[:4000].lower()
    return any(m in head for m in _WAF_BODY_MARKERS)


# Strong reliable secret patterns (the key shape itself proves it is a real secret)
_STRONG_SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"),   # JWT
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                    # Google API key
    re.compile(r"sk_live_[0-9a-zA-Z]{20,}"),                  # Stripe live key
    re.compile(r"ghp_[0-9A-Za-z]{36}"),                       # GitHub token
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),             # Slack token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]
# Generic key=value pattern (weak) — requires extra verification of the value's randomness
_GENERIC_SECRET_RE = re.compile(
    r"""(?i)(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|"""
    r"""auth[_-]?token|password|passwd|bearer)\s*[:=]\s*['"]([^'"]{8,})['"]""")
# Pragmas that declare the value is not a secret (already triaged) → we ignore them
_SECRET_ALLOWLIST_PRAGMAS = (
    "pragma: allowlist secret", "gitleaks:allow", "nosec",
    "noqa: secret", "not a secret", "notsecret", "# example", "public key")
# Common placeholder values that are not real secrets
_SECRET_PLACEHOLDERS = (
    "your_api_key", "yourapikey", "changeme", "example", "testkey", "demo",
    "sample", "placeholder", "dummy", "xxxx", "none", "null", "undefined",
    "todo", "redacted", "hidden", "your-", "insert", "fixme", "foobar")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    import math
    n = len(s)
    return -sum((c / n) * math.log2(c / n)
                for c in (s.count(ch) for ch in set(s)))


def _value_looks_secret(v: str) -> bool:
    """True only if the value looks like a real random key, not a placeholder."""
    v = (v or "").strip()
    low = v.lower()
    if len(v) < 16:
        return False
    if any(ph in low for ph in _SECRET_PLACEHOLDERS):
        return False
    if _shannon_entropy(v) < 3.2:           # low-randomness string = not a key
        return False
    # Real keys usually mix letters and digits
    return any(c.isdigit() for c in v) and any(c.isalpha() for c in v)


def _contains_real_secret(text: str) -> bool:
    """True only for an actual high-confidence secret (JWT/AWS/Google/PEM…) or a real random value.

    Rejects: values declared not to be secrets (pragma allowlist), placeholder values,
    and low-randomness public keys like 'febaymaxdevs'.
    """
    if not text:
        return False
    low = text.lower()
    if any(p in low for p in _SECRET_ALLOWLIST_PRAGMAS):
        return False
    if any(p.search(text) for p in _STRONG_SECRET_PATTERNS):
        return True
    m = _GENERIC_SECRET_RE.search(text)
    return bool(m and _value_looks_secret(m.group(1)))


# Database error patterns to confirm SQLi live
_SQLI_ERR_SIGNS = (
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "ora-0", "sqlite_error", "pg_query()",
    "postgresql error", "syntax error at or near", "microsoft jet database",
    "odbc microsoft access", "sqlstate", "mysql_fetch")

# Extract the first absolute URL (to determine the redirect target)
_ABS_URL_RE = re.compile(r"https?:\\?/\\?/[^\s'\"<>]+", re.I)


def _redirect_target_external(evidence: str, payload: str, target_netloc: str) -> bool:
    """True only if the redirect target (Location) is a domain external to the target.

    Redirecting to the same domain (e.g. signin with a returnurl to the same site) is not an Open Redirect.
    """
    target_netloc = (target_netloc or "").lower()
    txt = evidence or ""
    low = txt.lower()
    idx = low.find("location")
    scope = txt[idx:] if idx != -1 else txt
    m = _ABS_URL_RE.search(scope)
    cand = m.group(0) if m else ""
    if not cand:   # support protocol-relative //evil.com in the payload
        pm = re.search(r"//([^\s'\"/<>]+)", payload or "")
        cand = "http://" + pm.group(1) if pm else ""
    if not cand:
        return False
    net = _uparse.urlparse(cand.replace("\\", "")).netloc.lower().split("@")[-1].split(":")[0]
    if not net:
        return False
    return not (net == target_netloc or net.endswith("." + target_netloc))


def _finding_dup_key(url: str, vuln_type: str) -> tuple:
    _u = (url or "").split("#")[0]
    try:
        _pr = _uparse.urlparse(_u)
        _pnames = sorted(k for k, _ in _uparse.parse_qsl(_pr.query, keep_blank_values=True))
        _norm = _uparse.urlunparse(_pr._replace(query="&".join(f"{k}=" for k in _pnames)))
    except Exception:
        _norm = _u
    return ((vuln_type or "").strip().lower(), _norm)


def _is_dup_finding(findings: list, url: str, vuln_type: str) -> bool:
    """Prevent duplicates by (vuln_type + URL) instead of URL alone."""
    key = _finding_dup_key(url, vuln_type)
    return any(_finding_dup_key(f.get("url", ""), f.get("vuln_type", "")) == key
               for f in findings)


def _build_security_script(url: str, vuln: str, param: str = "",
                           custom_payloads: list = None) -> str:
    """Builds a *precise* deep-scan script ready for a specific vulnerability type.

    Detection accuracy:
    - Sends a baseline request (benign canary) first → learns the normal status/length/timing and reflection position.
    - XSS: confirms verbatim *unescaped* reflection in an HTML context (no false positives from encoding).
    - SSTI: verifies that the distinctive product appeared *and* that the original expression disappeared (i.e. it was actually evaluated).
    - Time-based SQLi: compares against the baseline timing (delay > baseline + 4s) instead of an absolute threshold.
    - custom_payloads (from the image/context) are tested first → verification matching the actual vulnerability, not a generic one.
    """
    vuln = (vuln or "xss").lower().replace(" ", "_").replace("-", "_")
    if vuln in ("sql", "sql_injection"): vuln = "sqli"
    if vuln in ("redirect", "openredirect"): vuln = "open_redirect"
    if vuln in ("rce", "command_injection", "cmd", "os_command_injection"): vuln = "cmdi"
    lib = _SEC_PAYLOADS.get(vuln, _SEC_PAYLOADS["xss"])
    # The precise extracted payloads (from the image/user) lead the list, then the knowledge library — no duplicates
    payloads = []
    for p in [str(x) for x in (custom_payloads or []) if str(x).strip()] + list(lib):
        if p not in payloads:
            payloads.append(p)
    # The precise provided payloads (from the image/user) are tested early; the rest of detection is driven by the adaptive engine
    custom = [str(x) for x in (custom_payloads or []) if str(x).strip()]
    tmpl = '''import requests, time, sys, urllib3
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
urllib3.disable_warnings()
sys.path.insert(0, {engine_dir!r})          # shared adaptive detection engine
import detect_engine as de

TARGET = {target!r}
PARAM  = {param!r}
VULN   = {vuln!r}
CUSTOM = {custom}
UA = {{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"}}

_pr  = urlparse(TARGET)
_qs  = parse_qs(_pr.query, keep_blank_values=True)
_KEY = PARAM if (PARAM and PARAM in _qs) else (list(_qs.keys())[0] if _qs else (PARAM or "q"))
ORIG = (_qs.get(_KEY, ["1"])[0] or "1")

def _build(value):
    flat = {{k: v[0] for k, v in _qs.items()}} if _qs else {{}}
    flat[_KEY] = value
    return urlunparse(_pr._replace(query=urlencode(flat)))

def probe(value):
    \"\"\"Injects the value into the target parameter and returns a unified response for the engine.\"\"\"
    follow = (VULN != "open_redirect")
    u = _build(value); t0 = time.time()
    r = requests.get(u, headers=UA, timeout=12, allow_redirects=follow, verify=False)
    el = time.time() - t0
    loc = r.headers.get("Location", "") if not follow else ""
    return de.Resp(status=r.status_code, headers=dict(r.headers), body=r.text, elapsed=el, url=u, location=loc)

print(f"[INFO] Adaptive {{VULN.upper()}} scan on {{TARGET}} (param={{_KEY}}, orig={{ORIG[:30]}})")

# Early check of the precise reported payload (from the image/user) if present
for _cp in CUSTOM[:3]:
    try:
        _r = probe(_cp)
        if de.is_blocked(_r):
            print(f"[EXACT] provided payload BLOCKED by WAF: {{_cp[:60]}}")
        else:
            print(f"[EXACT] provided payload {{_cp[:60]}} -> reflected={{_cp in (_r.body or '')}} status={{_r.status}}")
    except Exception as _e:
        print(f"[EXACT] error: {{_e}}")

# Adaptive detection: calibrate for this site, then differential confirmation by type
res = de.scan(VULN, probe, orig=ORIG, target_netloc=_pr.netloc, calibrate_samples=2)

print(f"[INFO] baseline: {{res.proof.get('baseline', {{}})}}")
for _s in res.signals:
    print(f"[SIGNAL] {{_s}}")
if res.evidence:
    print(f"[EVIDENCE] {{res.evidence[:300]}}")
print(f"[PROOF] {{res.proof}}")

if res.confidence == de.CONFIRMED:
    print(f"[FOUND] {{VULN.upper()}} CONFIRMED (real) — payload: {{res.payload}}")
    print("VERDICT: VULNERABLE")
elif res.confidence == de.PROBABLE:
    print(f"[SUSPECT] {{VULN.upper()}} PROBABLE — single signal, needs manual review — payload: {{res.payload}}")
    print("VERDICT: PROBABLE")
elif res.confidence == de.BLOCKED:
    print("[BLOCKED] target behind WAF/Cloudflare — cannot confirm through it")
    print("VERDICT: BLOCKED")
else:
    print("[SAFE] adaptive engine found no confirmable evidence (differential checks negative)")
    print("VERDICT: SAFE")
'''
    return tmpl.format(target=url, param=(param or ""), vuln=vuln,
                       custom=json.dumps(custom), engine_dir=BASE_DIR)


def _ensure_target_dir(folder: str) -> str:
    """Creates the target folder (named after the site) with scripts/ and reports/ — returns the safe name or ''."""
    safe = re.sub(r"[^\w\.\-]", "_", (folder or "").lstrip("www.")).strip("_")
    if not safe:
        return ""
    base = os.path.join(_PROJ_ROOT, safe)
    os.makedirs(os.path.join(base, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(base, "reports"), exist_ok=True)
    return safe


# Program identity — the chat assistant uses this whenever asked who made / what this tool is.
_PROGRAM_IDENTITY = (
    "هوية البرنامج: تم برمجة هذا البرنامج (BugBîner AI) من قِبل المبرمج جودي جنبلي (Joudi Janble) "
    "من أجل اكتشاف الثغرات وتحليلها والإبلاغ عنها بشكل قانوني على منصات موثوقة مثل HackerOne (هكرون). "
    "إذا سُئلت: من برمج/صنع/طوّر هذا البرنامج، أو من المبرمج/المطوّر، أو ما الغرض منه — "
    "فأجب بهذه المعلومة بالضبط وبالعربية، ولا تقل إنك لا تعرف."
)


def _build_agent_system() -> str:
    return (
        "You are an autonomous AI security agent embedded in BugBîner AI — act like an elite bug-bounty hunter.\n"
        + _PROGRAM_IDENTITY + "\n"
        "You work in a LOOP, exactly like a real agent: THINK -> ACT (call a tool) -> OBSERVE (read the tool "
        "result) -> repeat — until you reach a FINAL VERDICT backed by real evidence.\n\n"
        "TOOLS:\n"
        "- run_security_test: FASTEST + DEEPEST + MOST PRECISE way to test a standard web vuln (xss/sqli/lfi/"
        "ssrf/open_redirect/ssti). The server sends a baseline request, then tests payloads with low-false-"
        "positive detection. PREFER THIS for standard vulns — give it {url, vuln_type}. "
        "CRITICAL: when a SPECIFIC payload/URL is visible in an image or given by the user, ALSO pass it as "
        "'payload' so the EXACT reported vulnerability is verified first — do not settle for generic payloads.\n"
        "- make_request: send a single real HTTP request and read the live response.\n"
        "- run_python: write & run a CUSTOM Python script (only when run_security_test doesn't fit). "
        "Returns stdout+stderr.\n\n"
        "STRATEGY: For a known/standard vuln type, call run_security_test FIRST (fast + deep). "
        "Use run_python only for custom/multi-step logic. Then write the final verdict.\n\n"
        "DEEP TESTING PROTOCOL (when you must write code with run_python) — write COMPREHENSIVE, PROFESSIONAL "
        "scripts like a senior bug-bounty hunter. NEVER write a trivial one-payload one-liner.\n"
        "0. PRECISION FIRST: when the target URL and a specific payload are known (e.g. extracted from an image), "
        "REPRODUCE THAT EXACT request first and confirm the precise reported issue — only then broaden to "
        "variants. The verification must match the ACTUAL vulnerability, not a generic probe.\n"
        "   Always establish a BASELINE (a benign request) and judge VULNERABLE only by a real DIFFERENCE from "
        "that baseline: payload reflected UNESCAPED in HTML (XSS), DB error text or timing delay vs baseline "
        "(SQLi), template math actually EVALUATED i.e. product present & expression gone (SSTI), file contents "
        "leaked (LFI), metadata returned (SSRF), Location header to attacker domain (Open Redirect).\n"
        "1. Identify the target URL and the vulnerability type (from the user, context, or image analysis).\n"
        "2. With run_python, write a POWERFUL and DEEP Python script for that exact vuln type. It MUST be "
        "thorough and try MANY payloads/techniques across multiple injection points (query params, headers, "
        "body). Depth guide per type:\n"
        "   - XSS: 8+ payloads across contexts (HTML body, attribute, <script>, URL/JS, SVG, event handlers); "
        "check verbatim reflection AND filter/encoding bypass; test each parameter.\n"
        "   - SQLi: error-based + boolean-based + time-based; payloads like \"'\", '\"', \" OR 1=1-- \", "
        "UNION SELECT, SLEEP/pg_sleep/WAITFOR; detect DB error strings and timing.\n"
        "   - SSRF: internal & cloud-metadata targets (169.254.169.254, localhost, 127.0.0.1, file://) across "
        "multiple param names (url=,next=,dest=,redirect=).\n"
        "   - IDOR: enumerate several adjacent IDs and diff responses/sizes/status.\n"
        "   - LFI/Path-Traversal: many traversal payloads + encodings (../, ..%2f, ....//), look for "
        "/etc/passwd, win.ini, boot.ini.\n"
        "   - Open Redirect: many payloads, parse the Location header's NETLOC and confirm it is an EXTERNAL "
        "domain (exact match, not substring — beware target.evil.com and user@evil.com tricks).\n"
        "   - SSTI: polyglot probes ({{7*7}}, ${7*7}, <%=7*7%>); use UNIQUE numbers (e.g. 1337*1338=1788906) "
        "and confirm the product appears AND the literal expression is gone (evaluated, not reflected).\n"
        "   - CMDi/RCE: separators ; | & && `` $() and %0a, payloads like ';id', '|whoami', '$(sleep 5)'; "
        "confirm via command output (uid=.. gid=..) OR a CONFIRMED time delay (re-request to rule out jitter).\n"
        "   - XXE: send a POST with Content-Type: application/xml and an external-entity body "
        "(<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>); confirm file contents in the "
        "response, or use an OOB/collaborator callback for blind XXE.\n"
        "   Use the requests library, timeout=10, a realistic User-Agent, loop over a payload LIST, and collect "
        "evidence for each hit.\n"
        "3. OUTPUT FORMAT (do this in addition to depth, not instead of it): the script must PRINT progress — "
        "an [INFO] line per payload/test, [FOUND] with the proof when a payload triggers, [SAFE] when a test "
        "is clean, and END with exactly one line 'VERDICT: VULNERABLE' or 'VERDICT: SAFE'. Compute the VERDICT "
        "from the actual results (VULNERABLE only inside the branch where real evidence was found) — NEVER "
        "hardcode it. A script that does not actually run requests and print results is WRONG.\n"
        "4. AUTO-FIX LOOP: if run_python output contains a Python error/traceback (SyntaxError, NameError, "
        "Exception, etc.), READ the error, FIX the script, and call run_python AGAIN. Repeat until it runs "
        "cleanly. If inconclusive, ADD more payloads/techniques and run again. NEVER give up after one script.\n"
        "5. Only mark VULNERABLE when the live response actually proves it (payload reflected verbatim, SQL "
        "error text, timing delay, Location redirect to attacker domain, metadata leak). NEVER guess.\n\n"
        "RULES:\n"
        "- ALWAYS verify with a tool before any claim. Stay on the target scope. Up to ~10 tool steps.\n"
        "- Do NOT stop until you can give a clear FINAL VERDICT (مصاب/سليم) or you've exhausted reasonable tests.\n"
        "- FINAL ANSWER must be in ARABIC, markdown, covering: الحكم (VULNERABLE/SAFE), الدليل (evidence من ردّ "
        "HTTP), الـpayload, الخطورة (severity), والتوصية.\n"
        "Be precise and evidence-driven."
    )


# Known vision model name patterns in Ollama
_VISION_NAME_PATS = ("vl", "vision", "llava", "bakllava", "moondream",
                     "minicpm-v", "llama3.2-vision", "qwen2.5vl", "qwen2-vl")


async def _detect_vision_model(ollama_base: str, configured: str = "") -> str:
    """Returns the name of an installed vision model (the one configured in settings first, then auto-detection), or '' if none exists."""
    import aiohttp as _ah
    try:
        async with _ah.ClientSession() as s:
            async with s.get(f"{ollama_base}/api/tags",
                             timeout=_ah.ClientTimeout(total=8)) as r:
                names = [m.get("name", "") for m in (await r.json()).get("models", [])]
    except Exception:
        names = []
    if configured and any(configured == n or configured == n.split(":")[0] for n in names):
        return configured
    for n in names:
        low = n.lower()
        if any(p in low for p in _VISION_NAME_PATS):
            return n
    return ""


async def _vision_extract(ollama_base: str, vision_model: str,
                          images_b64: list, user_hint: str = "") -> str:
    """Passes the image to the vision model and extracts: the URL + vulnerability type + details (as text)."""
    import aiohttp as _ah
    prompt = (
        "You are analyzing a screenshot for a security test. Extract and output EXACTLY in this format:\n"
        "URL: <the exact target URL/endpoint visible, with full path & query params, or NONE>\n"
        "VULN: <the vulnerability type shown/implied: XSS, SQLi, SSRF, IDOR, LFI, SSTI, Open Redirect, RCE, or UNKNOWN>\n"
        "PAYLOAD: <any injected payload/parameter visible, or NONE>\n"
        "DETAILS: <one line: what the image shows that indicates the issue>\n"
        "Read all visible text, URLs, HTTP requests/responses, and error messages carefully."
    )
    if user_hint:
        prompt += f"\nUser note: {user_hint[:300]}"
    payload = {
        "model": vision_model,
        "stream": False,
        "keep_alive": "15m",
        "options": {"temperature": 0.0, "num_ctx": 4096, "num_gpu": 99, "num_predict": 400},
        "messages": [{"role": "user", "content": prompt, "images": images_b64}],
    }
    try:
        async with _ah.ClientSession() as s:
            async with s.post(f"{ollama_base}/api/chat",
                              headers={"Content-Type": "application/json"},
                              json=payload,
                              timeout=_ah.ClientTimeout(total=180)) as r:
                data = json.loads((await r.read()).decode("utf-8", errors="replace"))
        return (data.get("message") or {}).get("content", "").strip()
    except Exception as e:
        return f"[vision error: {e}]"


async def _agent_http_request(session, url: str, method: str = "GET",
                              headers: dict = None, body=None,
                              cookie_header: str = "") -> dict:
    """A real HTTP request for the chat agent."""
    merged = {"User-Agent": _AGENT_UA,
              "Accept": "text/html,application/json,*/*;q=0.8",
              **(headers or {})}
    if cookie_header:
        merged["Cookie"] = cookie_header
    try:
        async with session.request(
            method.upper(), url, headers=merged, data=body,
            timeout=__import__("aiohttp").ClientTimeout(total=20, connect=8),
            allow_redirects=True, max_redirects=5, ssl=False,
        ) as r:
            raw = await r.read()
            return {"status": r.status, "headers": dict(r.headers),
                    "body": raw.decode("utf-8", errors="replace")[:8000],
                    "url": str(r.url), "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}


async def _agent_run_python(code: str, target_dir: str = "agent_chat",
                            script_name: str = "scan") -> str:
    """Writes a Python script inside the target folder, runs it, and returns the output (stdout+stderr)."""
    safe_dir = re.sub(r"[^\w\.\-]", "_", target_dir or "agent_chat") or "agent_chat"
    scripts_dir = os.path.join(_PROJ_ROOT, safe_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    # Script name based on its function/vulnerability
    sname = re.sub(r"[^\w\-]", "_", (script_name or "scan").strip().lower())[:40].strip("_") or "scan"
    utf8_header = ("import sys, io\n"
                   "sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')\n"
                   "sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')\n\n")
    full_code = utf8_header + (code or "")
    try:
        compile(full_code, "<agent_script>", "exec")
    except SyntaxError as se:
        return f"[SYNTAX ERROR] {se}"
    _ts = datetime.now().strftime("%H%M%S")
    fname = os.path.join(scripts_dir, f"{sname}_{_ts}.py")
    with open(fname, "w", encoding="utf-8") as _f:
        _f.write(full_code)
    _py = os.path.join(_PROJ_ROOT, ".venv", "Scripts", "python.exe")
    if not os.path.exists(_py):
        _py = sys.executable
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    out_lines: list = []
    try:
        proc = await asyncio.create_subprocess_exec(
            _py, "-u", fname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=_PROJ_ROOT, env=env,
        )
        try:
            async def _read():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    out_lines.append(line.decode("utf-8", errors="replace").rstrip())
            await asyncio.wait_for(_read(), timeout=60.0)
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            out_lines.append("[TIMEOUT] Script exceeded 60s — killed.")
    except Exception as e:
        out_lines.append(f"[EXEC ERROR] {e}")
    output = "\n".join(out_lines).strip()
    if output:
        return output[:6000]
    # No output → the model probably forgot to add print — give it an explicit corrective instruction
    return ("[NO OUTPUT] The script ran but printed nothing. You MUST add print() statements to show "
            "results. Rewrite the script so it actually CALLS requests, checks the response, and prints "
            "[FOUND]/[SAFE]/[INFO] lines plus a final line 'VERDICT: VULNERABLE' or 'VERDICT: SAFE', "
            "then call run_python again.")


def _extract_text_tool_calls(content: str) -> list:
    """Extracts tool calls written as text (Qwen <tool_call>{...}</tool_call> or raw JSON).
    Tolerates minor malformation and infers the tool name from the keys if needed."""
    if not content or "{" not in content:
        return []
    out, seen = [], set()
    # Candidates: content inside <tool_call>..</tool_call> first, then the full text
    candidates = re.findall(r"<tool_call>\s*(.*?)\s*</tool_call>", content, re.DOTALL)
    candidates.append(content)
    dec = json.JSONDecoder()
    for cand in candidates:
        i = 0
        while i < len(cand):
            if cand[i] != "{":
                i += 1
                continue
            try:
                obj, end = dec.raw_decode(cand[i:])
            except Exception:
                i += 1
                continue
            i += end
            if not isinstance(obj, dict):
                continue
            fn   = obj.get("function") if isinstance(obj.get("function"), dict) else {}
            name = obj.get("name") or fn.get("name")
            args = (obj.get("arguments") or obj.get("parameters")
                    or fn.get("arguments") or {})
            if isinstance(args, str):
                try: args = json.loads(args)
                except Exception: args = {}
            # Infer the tool from the keys when the name is missing/wrong
            if name not in ("make_request", "run_python"):
                if isinstance(args, dict) and "code" in args:
                    name = "run_python"
                elif isinstance(args, dict) and "url" in args:
                    name = "make_request"
                else:
                    continue
            key = name + "|" + json.dumps(args, sort_keys=True)[:200]
            if key in seen:
                continue
            seen.add(key)
            out.append({"function": {"name": name, "arguments": args}})
        if out:
            break
    return out


async def _agent_ollama_call(ollama_base: str, model: str, messages: list,
                             tools=None, max_tokens: int = 1500) -> dict:
    """A single call to the local model (Ollama). Returns the full assistant message (content + tool_calls)."""
    import aiohttp as _ah
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,            # tool_calls arrive complete only with stream=False
        "keep_alive": "15m",
        "options": {"num_ctx": 4096, "num_gpu": 99, "temperature": 0.15,
                    "num_predict": max_tokens},
    }
    if tools:
        payload["tools"] = tools
    # Two attempts: avoids a temporary connection refusal while the model loads (cold start)
    _last_err = ""
    for _attempt in range(2):
        try:
            async with _ah.ClientSession() as s:
                async with s.post(f"{ollama_base}/api/chat",
                                  headers={"Content-Type": "application/json"},
                                  json=payload,
                                  timeout=_ah.ClientTimeout(total=240)) as r:
                    data = json.loads((await r.read()).decode("utf-8", errors="replace"))
            return data.get("message") or {}
        except Exception as e:
            _last_err = str(e)
            if _attempt == 0:
                await asyncio.sleep(2)   # give Ollama a moment to finish loading the model
    return {"role": "assistant", "content": f"[Ollama error: {_last_err}]"}


# ── AI Chat endpoint (streaming SSE) ─────────────────────────────────────────
@app.post("/api/chat/stream")
async def chat_stream_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception as e:
        logging.error(f"chat/stream body parse error: {e}")
        return JSONResponse({"error": f"Invalid request body: {e}"}, status_code=400)
    message = (body.get("message") or "").strip()
    context = (body.get("context") or "").strip()
    mode    = body.get("mode", "ask")  # "ask" | "agent"
    image   = body.get("image")        # {base64, mediaType, name} or None (legacy single)
    images  = body.get("images") or ([] if not image else [image])  # multiple images
    # Conversation history for cross-turn memory — [{role, content}, ...]
    conversation = body.get("conversation") or []
    # Copilot removed - only Ollama supported now

    if not message and not images:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    # Auto-create target folder when a URL is detected in the message
    _url_m = re.search(r"https?://([^/:?#\s]+)", message)
    if _url_m:
        _chat_domain = _url_m.group(1).lstrip("www.")
        _chat_folder = re.sub(r"[^\w\.\-]", "_", _chat_domain)
        if _chat_folder:
            _chat_tdir = os.path.join(_PROJ_ROOT, _chat_folder)
            os.makedirs(os.path.join(_chat_tdir, "reports"), exist_ok=True)
            os.makedirs(os.path.join(_chat_tdir, "scripts"), exist_ok=True)

    cfg = load_config()

    # ── Same model for scanning and chat; parallelism (OLLAMA_NUM_PARALLEL) separates the requests ──
    ollama_base  = cfg.get("ollama_base", "http://localhost:11434")
    ollama_model = body.get("model") or cfg.get("ollama_model") or "qwen2.5:7b"

    # Context — trim at line boundaries instead of blind cutting (1500 for the agent, 800 for the question)
    _ctx_max     = 1500 if mode == "agent" else 800
    _ctx_limited = _trim_ctx(context, _ctx_max)
    msg_text = (f"=== السياق ===\n{_ctx_limited}\n\n=== السؤال ===\n{message}"
                if _ctx_limited else (message or "مرحبا"))

    # Target folder for running the agent's scripts (derived from a URL if present)
    _agent_target = ""
    if _url_m:
        _agent_target = re.sub(r"[^\w\.\-]", "_", _url_m.group(1).lstrip("www.")) or "agent_chat"

    # ── Conversation memory: last ~8 turns (we skip the last user message because it is msg_text) ──
    def _history_msgs() -> list:
        out = []
        hist = conversation[:-1] if (conversation and conversation[-1].get("role") == "user") else conversation
        for turn in hist[-6:]:  # sliding window: last 6 turns only
            role = turn.get("role")
            content = (turn.get("content") or "")
            if role in ("user", "assistant") and content:
                out.append({"role": role, "content": content[:1200]})
        return out

    # Current question text (with an instruction for images if the user wrote nothing)
    _user_text = msg_text
    if images and not message:
        _user_text = ("حلّل الصورة المرفقة، استخرج أي رابط فيها، ثم تحقق من الثغرة "
                      "باستخدام الأدوات (make_request / run_python) وأعطِ الحكم.")

    _img_b64 = [img.get("base64", "") for img in (images or []) if img.get("base64")]

    # ── ASK MODE: direct Q&A with memory (local model, live streaming) ──────────────
    if mode != "agent":
        ask_system = (
            "You are an expert AI security assistant embedded in BugBîner AI bug bounty tool. "
            + _PROGRAM_IDENTITY + " "
            "You have FULL ACCESS to the current program state provided in the context: terminal output, "
            "discovered vulnerabilities, site map, and scan state. Read it and answer directly. "
            "When asked 'هل مصاب' / 'is it vulnerable', analyze the context and give a verdict. "
            "حرجٌ جدًا: ردّ بالعربية فقط دائمًا — لا تستخدم الإنجليزية ولا الصينية إطلاقًا مهما كانت لغة السؤال. "
            "Be direct and precise. Use markdown: **bold**, `inline code`, lists."
        )
        _ask_user = {"role": "user", "content": _user_text}
        if _img_b64:
            _ask_user["images"] = _img_b64
        _ask_messages = [{"role": "system", "content": ask_system}] + _history_msgs() + [_ask_user]

        async def ask_stream():
            import aiohttp as _aiohttp
            _pld = {
                "model": ollama_model, "stream": True, "keep_alive": "15m",
                "options": {"temperature": 0.15, "num_predict": 800,
                            "num_ctx": 4096, "num_gpu": 99},
                "messages": _ask_messages,
            }
            try:
                async with _aiohttp.ClientSession() as _sess:
                    async with _sess.post(
                        f"{ollama_base}/api/chat",
                        headers={"Content-Type": "application/json"}, json=_pld,
                        timeout=_aiohttp.ClientTimeout(total=120, connect=30),
                    ) as _resp:
                        while True:
                            _raw = await _resp.content.readline()
                            if not _raw:
                                break
                            try:
                                _chunk = json.loads(_raw.decode("utf-8", errors="replace"))
                                _delta = (_chunk.get("message") or {}).get("content", "")
                                if _delta:
                                    yield f"data: {json.dumps({'delta': _delta})}\n\n"
                                    await asyncio.sleep(0)
                                if _chunk.get("done"):
                                    yield "data: [DONE]\n\n"
                                    return
                            except Exception:
                                pass
                yield "data: [DONE]\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': f'Ollama error: {e}'})}\n\n"

        return StreamingResponse(ask_stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── AGENT MODE: a real agent loop (think → tool → observe → repeat → answer) ──
    # The reasoning/tools model = the same scan model; parallelism ensures neither blocks the other.
    reasoner_model    = cfg.get("ollama_model") or "qwen2.5:7b"
    vision_model_cfg  = cfg.get("vision_model", "")

    agent_user = {"role": "user", "content": _user_text}   # text only — no images for the text model
    agent_messages = ([{"role": "system", "content": _build_agent_system()}]
                      + _history_msgs() + [agent_user])

    async def agent_stream():
        import aiohttp as _aiohttp
        MAX_STEPS = 10
        # Target state: site folder + vulnerability type + the precise payload extracted from the image/context
        tgt_state = {"dir": _agent_target, "vuln": "", "payload": "", "url": ""}

        # ── Vision step: if images exist, extract the URL + vulnerability type via a vision model ──
        if _img_b64:
            vmodel = await _detect_vision_model(ollama_base, vision_model_cfg)
            if not vmodel:
                yield "data: " + json.dumps({"delta":
                    "❌ لا يوجد نموذج رؤية مثبّت لقراءة الصورة.\n"
                    "ثبّت نموذجاً ثم أعد المحاولة:\n```\nollama pull qwen2.5vl\n```"}) + "\n\n"
                yield "data: [DONE]\n\n"
                return
            yield "data: " + json.dumps({"delta": "👁️ قراءة الصورة بنموذج الرؤية (" + vmodel + ")…\n"}) + "\n\n"
            extraction = await _vision_extract(ollama_base, vmodel, _img_b64, message)
            yield "data: " + json.dumps({"delta": "```\n" + extraction[:600] + "\n```\n"}) + "\n\n"
            # Extract the URL, vulnerability type, and the precise payload from the vision analysis
            _mu = re.search(r"URL:\s*(\S+)", extraction)
            if _mu and _mu.group(1).upper() != "NONE":
                tgt_state["url"] = _mu.group(1).strip()
                _host = _uparse.urlparse(_mu.group(1)).netloc or _mu.group(1)
                tgt_state["dir"] = _host
            _mv = re.search(r"VULN:\s*([A-Za-z _\-]+)", extraction)
            if _mv and _mv.group(1).strip().upper() != "UNKNOWN":
                tgt_state["vuln"] = _mv.group(1).strip()
            # The precise payload visible in the image → tested first (verification matching the actual vulnerability)
            _mp = re.search(r"PAYLOAD:\s*(.+)", extraction)
            if _mp:
                _pv = _mp.group(1).strip().strip("`")
                if _pv and _pv.upper() != "NONE":
                    tgt_state["payload"] = _pv
            # Inject the vision extraction into the text agent's conversation with an explicit instruction to reproduce the precise payload
            _exact_hint = ""
            if tgt_state["payload"]:
                _exact_hint = ("\n\nمهم: الـpayload الدقيق الظاهر في الصورة هو: " + tgt_state["payload"] +
                               "\nمرّره في حقل 'payload' عند استدعاء run_security_test ليُختبر الـpayload الفعلي أولاً، "
                               "ولا تكتفِ بـpayloads عامة.")
            agent_messages.append({"role": "user", "content":
                "تحليل الصورة (من نموذج الرؤية) — استخدمه لتحديد الهدف والثغرة ثم تحقّق بالأدوات:\n"
                + extraction + _exact_hint})

        # ── First step: create a folder named after the target (all its scripts are saved inside it) ──
        if tgt_state["dir"]:
            _created = _ensure_target_dir(tgt_state["dir"])
            if _created:
                tgt_state["dir"] = _created
                yield "data: " + json.dumps({"delta":
                    "📁 مجلد الهدف: `" + _created + "/` (السكربتات والتقارير تُحفظ هنا)\n"}) + "\n\n"

        _used_tools = False
        async with _aiohttp.ClientSession() as http_sess:
            for _step in range(MAX_STEPS):
                msg_obj = await _agent_ollama_call(
                    ollama_base, reasoner_model, agent_messages,
                    tools=CHAT_AGENT_TOOLS, max_tokens=3000,   # large enough for a deep script
                )
                content   = msg_obj.get("content") or ""
                tool_calls = msg_obj.get("tool_calls") or []

                # Fallback: the model wrote the tool call as text (<tool_call> or JSON) → extract it
                if not tool_calls and content:
                    _txt_calls = _extract_text_tool_calls(content)
                    if _txt_calls:
                        tool_calls = _txt_calls
                        content = ""   # do not show the tool JSON as an answer

                # No tools → this is the final answer
                if not tool_calls:
                    final = content.strip()
                    # Terse ending after using the tools → ask for a formatted Arabic summary
                    if _used_tools and len(final) < 60:
                        agent_messages.append({"role": "user", "content":
                            "اكتب الآن الإجابة النهائية بالعربية فقط بصيغة markdown بناءً على الأدلة التي جمعتها، "
                            "وتشمل: **الحكم** (مصاب/سليم)، **الدليل** (من ردّ HTTP)، **الـpayload**، "
                            "**الخطورة**، **التوصية**."})
                        _sum = await _agent_ollama_call(ollama_base, reasoner_model,
                                                        agent_messages, tools=None, max_tokens=1200)
                        final = (_sum.get("content") or final).strip()
                    yield f"data: {json.dumps({'delta': final or 'لم أتمكّن من إنتاج إجابة.'})}\n\n"
                    yield "data: [DONE]\n\n"
                    return

                # Record the assistant message (with the tool calls) in memory
                _used_tools = True
                agent_messages.append({"role": "assistant", "content": content,
                                       "tool_calls": tool_calls})

                # Execute each tool, show a step to the user, then return the result to the model
                for tc in tool_calls:
                    fn    = tc.get("function") or {}
                    tname = fn.get("name", "")
                    targs = fn.get("arguments", {})
                    if isinstance(targs, str):
                        try: targs = json.loads(targs)
                        except Exception: targs = {}

                    if tname == "make_request":
                        _u = targs.get("url", "")
                        _method = targs.get("method", "GET")
                        # If the target is not known yet, derive it from the first URL and create its folder
                        if not tgt_state["dir"] and _u:
                            _h = _uparse.urlparse(_u).netloc
                            _c = _ensure_target_dir(_h)
                            if _c:
                                tgt_state["dir"] = _c
                                yield "data: " + json.dumps({"delta":
                                    "📁 مجلد الهدف: `" + _c + "/`\n"}) + "\n\n"
                        _step_note = "🔎 طلب HTTP: `" + _method + " " + _u + "`\n"
                        yield "data: " + json.dumps({"delta": _step_note}) + "\n\n"
                        rres = await _agent_http_request(
                            http_sess, _u, method=_method,
                            headers=targs.get("headers"), body=targs.get("body"),
                        )
                        tool_result = json.dumps({
                            "status": rres["status"], "response_url": rres["url"],
                            "headers": {k.lower(): v for k, v in list(rres["headers"].items())[:15]},
                            "body_snippet": rres["body"][:3000], "error": rres.get("error"),
                        }, ensure_ascii=False)
                        _status_note = "   ↳ status " + str(rres["status"]) + "\n"
                        yield "data: " + json.dumps({"delta": _status_note}) + "\n\n"

                    elif tname == "run_python":
                        # Script name: from the model, or the vulnerability type, or a default
                        _sname = (targs.get("name") or tgt_state["vuln"] or "scan")
                        _tdir  = tgt_state["dir"] or "agent_chat"
                        yield "data: " + json.dumps({"delta":
                            "🐍 تشغيل سكربت `" + re.sub(r'[^\w\-]','_',_sname.lower())[:40] +
                            ".py` في `" + _tdir + "/scripts/`…\n"}) + "\n\n"
                        out = await _agent_run_python(targs.get("code", ""), _tdir, _sname)
                        tool_result = out
                        _preview = out[:400] + ("…" if len(out) > 400 else "")
                        _code_note = "```\n" + _preview + "\n```\n"
                        yield "data: " + json.dumps({"delta": _code_note}) + "\n\n"

                    elif tname == "run_security_test":
                        # Prebuilt deep scan (fast): the server builds the script from the payload library
                        _u  = targs.get("url", "") or ""
                        _vt = (targs.get("vuln_type") or tgt_state["vuln"] or "xss")
                        if not tgt_state["dir"] and _u:
                            _c = _ensure_target_dir(_uparse.urlparse(_u).netloc)
                            if _c:
                                tgt_state["dir"] = _c
                                yield "data: " + json.dumps({"delta": "📁 مجلد الهدف: `" + _c + "/`\n"}) + "\n\n"
                        _tdir = tgt_state["dir"] or "agent_chat"
                        _vt_norm = re.sub(r"[^\w]", "_", _vt.lower())
                        # The precise payload: from the model first, otherwise the one extracted from the image
                        _exact_pl = (targs.get("payload") or "").strip() or tgt_state.get("payload", "")
                        _custom = [_exact_pl] if _exact_pl else []
                        _n_payloads = len(_SEC_PAYLOADS.get(_vt_norm if _vt_norm in _SEC_PAYLOADS else "xss", [])) + len(_custom)
                        _exact_note = (" (يبدأ بالـpayload الدقيق: `" + _exact_pl[:50] + "`)") if _exact_pl else ""
                        yield "data: " + json.dumps({"delta":
                            "🛡️ فحص عميق دقيق `" + _vt + "` بـ " + str(_n_payloads) +
                            " payloads" + _exact_note + " → `" + _tdir + "/scripts/" + _vt_norm + "_test.py`…\n"}) + "\n\n"
                        _script = _build_security_script(_u, _vt, targs.get("param", ""),
                                                         custom_payloads=_custom)
                        out = await _agent_run_python(_script, _tdir, _vt_norm + "_test")
                        tool_result = out
                        _preview = out[:500] + ("…" if len(out) > 500 else "")
                        yield "data: " + json.dumps({"delta": "```\n" + _preview + "\n```\n"}) + "\n\n"

                    else:
                        tool_result = "Unknown tool: " + tname

                    # Tool result with tool_name for correct linkage
                    agent_messages.append({"role": "tool", "tool_name": tname,
                                           "content": tool_result[:6000]})
                    await asyncio.sleep(0)

            # We exceeded the maximum number of steps → ask for a final summary without tools
            agent_messages.append({"role": "user", "content":
                "توقّف عن استخدام الأدوات الآن واكتب الإجابة النهائية بالعربية (الحكم/الدليل/الـpayload/"
                "الخطورة/التوصية) بناءً على الأدلة التي جمعتها."})
            final_obj = await _agent_ollama_call(ollama_base, reasoner_model, agent_messages,
                                                 tools=None, max_tokens=1500)
            _final_txt = (final_obj.get("content") or "").strip() or \
                "انتهت خطوات الأجنت — راجع مخرجات السكربتات أعلاه للحكم."
            yield f"data: {json.dumps({'delta': _final_txt})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(agent_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})




# ── IDOR: distinguish a parameter referencing a user-owned object from a pagination/tracking parameter ──────
# Pagination (page/limit/offset) and tracking identifiers (utm_*/ext-ga*/gaSessionId) change
# the response body naturally without any authorization breach → not IDOR.
_IDOR_SKIP_NAMES = {
    "page", "limit", "offset", "size", "count", "start", "end", "per_page", "perpage",
    "p", "pg", "pagenum", "page_num", "page_size", "pagesize", "top", "skip", "from", "to",
    "sort", "order", "dir", "direction", "filter", "q", "query", "search",
    "lang", "locale", "version", "v", "ts", "timestamp", "_", "cache", "cb", "rand",
    "width", "height", "quality", "w", "h", "x", "y", "zoom",
    "sessionid", "session_id", "clientid", "client_id", "anonymousid",
    "gasessionid", "gaclientid", "fbclid", "gclid", "msclkid", "year", "month", "day",
}


def _is_idor_param(name: str) -> bool:
    """Returns True if the parameter looks like an object identifier (id/user/order…) rather than pagination/tracking."""
    n = (name or "").lower().strip()
    if not n or n in _IDOR_SKIP_NAMES:
        return False
    if n.startswith(("utm_", "ext-", "ga_", "_")):
        return False
    return (n == "id" or n.endswith(("id", "_id"))
            or any(k in n for k in ("user", "account", "customer", "order", "invoice",
                                    "doc", "file", "record", "object", "profile",
                                    "ticket", "uuid", "guid", "uid")))


# ── Pause/resume/background-run for the scan (continues despite page refresh/close) ─────────────
# Pause keys per target host; the scan producer checks them and stops and saves the state.
_aicrawl_pause: dict = {}
# Registry of scans running in the background: host -> {status, stop, findings, tested, meta, subscribers, task}
_scans: dict = {}


def _scan_host(target: str) -> str:
    return (_uparse.urlparse(target).netloc or target).lstrip("www.")


def _scan_state_path(target: str) -> str:
    folder = re.sub(r"[^\w.\-]", "_", _scan_host(target))
    return os.path.join(_PROJ_ROOT, folder, "scan_state.json")


async def _hard_stop_scan(scan: dict):
    """Stop a background scan IMMEDIATELY and fully (the Stop button + Restart):
      1) raise the stop flag so every loop/worker exits at its next check,
      2) open the pause gate so workers suspended while paused wake up and see the stop,
      3) cancel the in-flight AI workers so the current Ollama calls are aborted now,
      4) kill the Node.js crawler subprocess so no new URLs are queued,
      5) flush progress to disk so the scan stays resumable later.
    This does NOT cancel the producer task itself — it lets the producer run its own
    finally (clean eof + final summary). The producer notices the stop flag within a
    couple of seconds; killing the crawler + cancelling the workers stops all real work
    right away."""
    if not scan:
        return
    scan["status"] = "stopping"
    # 1) signal stop to producer + crawler-reader + workers
    try: scan["stop"].set()
    except Exception: pass
    # 2) wake anything suspended on the pause gate so it observes the stop flag
    gate = scan.get("resume_gate")
    if gate is not None:
        try: gate.set()
        except Exception: pass
    # 3) cancel the AI scan workers → aborts the current Ollama calls instead of finishing them
    for w in (scan.get("workers") or []):
        try:
            if not w.done(): w.cancel()
        except Exception: pass
    # 4) kill the Node.js crawler subprocess immediately (don't wait for the producer tick)
    proc = scan.get("proc")
    if proc is not None:
        try: proc.kill()
        except Exception: pass
        try:
            if proc.stdin is not None and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception: pass
    # 5) tear down OAST subprocess + headless browser if this scan owns them
    _oc = scan.get("oast")
    if _oc is not None:
        try: _oc.stop()
        except Exception: pass
    _ds = scan.get("dom_scanner")
    if _ds is not None:
        try:
            await asyncio.get_running_loop().run_in_executor(
                _DOM_POOL, functools.partial(_ds.__exit__, None, None, None))
        except Exception: pass
    # 6) persist progress so a later resume still works
    save = scan.get("save")
    if save is not None:
        try: await save("paused", force=True)
        except Exception: pass


async def _aicrawl_subscriber(scan_obj: dict, request: Request):
    """Connects to a scan running in the background: sends a state snapshot then streams live events.
    If the viewer leaves (refresh/close), the scan continues in the background without stopping."""
    def _ev(level, msg):
        return "data: " + json.dumps({"level": level, "message": msg}, ensure_ascii=False) + "\n\n"

    q: asyncio.Queue = asyncio.Queue(maxsize=200000)
    scan_obj["subscribers"].add(q)
    try:
        yield ": connected\n\n"
        findings = scan_obj.get("findings") or []
        meta     = scan_obj.get("meta") or {}
        tested   = scan_obj.get("tested") or set()
        running  = scan_obj.get("status") == "running"
        # ── State snapshot on (re)connection ──
        yield _ev("phase", "🔌 Connected to the running background scan"
                  if running else f"📁 Saved result ({scan_obj.get('status')})")
        for i, f in enumerate(findings, 1):
            yield ("data: " + json.dumps(
                {"level": "vuln",
                 "message": f"[{i}] [{(f.get('severity') or '').upper()}] {f.get('vuln_type','')} - {f.get('url','')}",
                 "finding": f}, ensure_ascii=False) + "\n\n")
        yield ("data: " + json.dumps(
            {"level": "stats", "crawled": meta.get("crawled", 0),
             "total": meta.get("crawled", 0), "tested": len(tested),
             "vulns": len(findings)}, ensure_ascii=False) + "\n\n")
        if not running:
            yield _ev("eof", "end")
            return
        # ── Live streaming ──
        while True:
            if await request.is_disconnected():
                break    # the viewer left — the scan continues in the background
            try:
                ev = await asyncio.wait_for(q.get(), timeout=5.0)
                yield ev
                if '"level": "eof"' in ev or '"level":"eof"' in ev:
                    break
            except asyncio.TimeoutError:
                if scan_obj.get("status") != "running" and q.empty():
                    yield _ev("eof", "end")
                    break
                yield ": keepalive\n\n"
    finally:
        scan_obj["subscribers"].discard(q)


@app.post("/api/aicrawl/pause")
async def aicrawl_pause(request: Request):
    """Suspend the running scan IN PLACE (no restart): clear the resume gate and tell
    the crawler to pause. All in-memory state is kept so resume continues from exactly
    where it stopped. Progress is also flushed to disk for cross-restart resume."""
    body = await request.json()
    target = (body.get("target") or body.get("url") or "").strip().rstrip("/")
    host = _scan_host(target)
    scan = _scans.get(host)
    if scan and scan.get("task") and not scan["task"].done():
        gate = scan.get("resume_gate")
        if gate is not None:
            gate.clear()                       # suspend the Python workers + producer
        scan["status"] = "paused"
        proc = scan.get("proc")
        if proc is not None and proc.stdin is not None:
            try:
                proc.stdin.write(b"PAUSE\n")   # suspend the Node.js crawler in place
                await proc.stdin.drain()
            except Exception:
                pass
        _save = scan.get("save")
        if _save is not None:
            try: await _save("paused", force=True)
            except Exception: pass
        return {"status": "paused", "live": True, "host": host}
    return {"status": "not_running", "host": host}


@app.post("/api/aicrawl/resume")
async def aicrawl_resume(request: Request):
    """Resume a suspended live scan by re-opening the same resume gate and telling the
    crawler to continue — this is NOT a restart and does NOT re-crawl. If no live task
    exists (the program was closed), returns {"resumed":"disk"} so the client starts a
    disk-resume run that skips everything already crawled/scanned."""
    body = await request.json()
    target = (body.get("target") or body.get("url") or "").strip().rstrip("/")
    host = _scan_host(target)
    scan = _scans.get(host)
    if scan and scan.get("task") and not scan["task"].done():
        scan["status"] = "running"
        proc = scan.get("proc")
        if proc is not None and proc.stdin is not None:
            try:
                proc.stdin.write(b"RESUME\n")
                await proc.stdin.drain()
            except Exception:
                pass
        gate = scan.get("resume_gate")
        if gate is not None:
            gate.set()                         # un-suspend the workers + producer
        return {"resumed": "live", "host": host}
    return {"resumed": "disk", "host": host}


@app.post("/api/aicrawl/stop")
async def aicrawl_stop(request: Request):
    """Stop the running background scan NOW: kills the crawler, aborts the AI workers and
    saves progress (still resumable). Works whether the scan is running or paused. If the
    target's host doesn't match (e.g. the URL box was edited), every live scan is stopped
    so the button never silently no-ops."""
    body = await request.json()
    target = (body.get("target") or body.get("url") or "").strip().rstrip("/")
    host = _scan_host(target)
    scan = _scans.get(host)
    if scan and scan.get("task") and not scan["task"].done():
        await _hard_stop_scan(scan)
        return {"status": "stopping", "host": host}
    # No exact match → stop any scan that is still alive (URL edited / host normalised differently)
    alive = [s for s in _scans.values() if s.get("task") and not s["task"].done()]
    for s in alive:
        await _hard_stop_scan(s)
    return {"status": "stopping" if alive else "not_running", "host": host}


@app.post("/api/aicrawl/reset")
async def aicrawl_reset():
    """Full teardown + ZERO for the Reset button: hard-stop EVERY background scan, kill all
    crawler subprocesses, clear the in-memory registry, AND delete every saved scan_state.json
    on disk. Wiping the disk state is what makes the next scan start FRESH — otherwise Start
    would resume the old scan and replay its saved (possibly stale) findings."""
    scans = list(_scans.values())
    for s in scans:
        try: await _hard_stop_scan(s)
        except Exception: pass
    _scans.clear()
    _aicrawl_pause.clear()
    # Delete per-target resume files so no old findings are ever replayed on the next scan
    wiped = 0
    try:
        for _name in os.listdir(_PROJ_ROOT):
            _sf = os.path.join(_PROJ_ROOT, _name, "scan_state.json")
            if os.path.isfile(_sf):
                try:
                    os.remove(_sf); wiped += 1
                except Exception:
                    pass
    except Exception:
        pass
    return {"status": "reset", "count": len(scans), "wiped": wiped}


@app.get("/api/aicrawl/state")
async def aicrawl_state(target: str = ""):
    """Scan state — prefers the live scan in memory, otherwise reads the one saved on disk."""
    if not target:
        return {"exists": False}
    # 1) A live scan in the background?
    live = _scans.get(_scan_host(target))
    if live and live.get("task") and not live["task"].done():
        meta = live.get("meta") or {}
        _st = live.get("status", "running")
        return {
            "exists": True, "status": _st, "live": True, "resumable": True,
            "suspended": _st != "running",
            "tested_count": len(live.get("tested") or set()),
            "vuln_count":   len(live.get("findings") or []),
            "crawled":      meta.get("crawled", 0), "updated": "",
        }
    # 2) Saved on disk (paused/completed)
    path = _scan_state_path(target)
    if not os.path.isfile(path):
        return {"exists": False}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # A disk status of "running" with no live task = program was closed mid-scan → resumable
        _disk_status = data.get("status", "paused")
        if _disk_status == "running":
            _disk_status = "paused"
        return {
            "exists":       True,
            "status":       _disk_status,
            "live":         False,
            "tested_count": data.get("tested_count", len(data.get("tested", []))),
            "vuln_count":   data.get("vuln_count", len(data.get("findings", []))),
            "crawled":      data.get("crawled", 0),
            "updated":      data.get("updated", ""),
            "resumable":    _disk_status != "done",
        }
    except Exception:
        return {"exists": False}


@app.get("/api/aicrawl/findings")
async def aicrawl_findings(target: str = ""):
    """Return all findings for a given target."""
    if not target:
        return []
    live = _scans.get(_scan_host(target))
    if live:
        return live.get("findings") or []
    path = _scan_state_path(target)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("findings") or []
        except Exception:
            return []
    return []


@app.post("/api/aicrawl/analyze-finding")
async def aicrawl_analyze_finding(request: Request):
    """Re-analyze a specific finding with AI."""
    body = await request.json()
    finding = body.get("finding")
    if not finding:
        return {"error": "finding required"}
    try:
        import ai_analyzer as _ai_mod
        await asyncio.to_thread(_ai_mod.analyze_finding, finding)
        return {"ai_analysis": finding.get("ai_analysis", {})}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/aicrawl/exploit-finding")
async def aicrawl_exploit_finding(request: Request):
    """Actively test a finding against the target to confirm if it's exploitable."""
    body = await request.json()
    finding = body.get("finding")
    if not finding:
        return {"error": "finding required"}
    try:
        import exploit_engine as _expl
        result = await asyncio.to_thread(_expl.test_finding, finding)
        return result
    except Exception as e:
        return {"error": str(e)}


# ── Continuous Spider + AI Scan (Burp-style, Node.js crawler) ─────────────────
@app.post("/api/aicrawl/run")
async def aicrawl_run(request: Request):
    """Burp-style continuous spider: Node.js crawler + Python AI scanner."""
    import aiohttp as _aiohttp

    body = await request.json()
    target       = (body.get("target") or body.get("url") or "").strip().rstrip("/")
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)

    # ── Reconnect only: attach to a live scan if one exists, and never start a new scan ──
    if body.get("reconnect"):
        _live = _scans.get(_scan_host(target))
        if _live and _live.get("task") and not _live["task"].done():
            return StreamingResponse(
                _aicrawl_subscriber(_live, request),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

        async def _no_live_scan():
            yield ": connected\n\n"
            yield "data: " + json.dumps({"level": "phase", "message": "No scan is running"}, ensure_ascii=False) + "\n\n"
            yield "data: " + json.dumps({"level": "eof", "message": "end"}, ensure_ascii=False) + "\n\n"
        return StreamingResponse(
            _no_live_scan(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    scope_data    = body.get("scope") or {}
    # Allowed vulnerability types = what the client sends (derived from the HackerOne scope),
    # otherwise the scope types directly, otherwise a comprehensive default list.
    allowed_vulns = (body.get("vuln_types")
                     or (scope_data.get("allowed_vuln_types") if isinstance(scope_data, dict) else None)
                     or ["xss", "sqli", "ssrf", "idor", "lfi",
                         "ssti", "xxe", "command_injection", "open_redirect", "path_traversal"])

    # ── Normalize vulnerability names to standard codes to restrict the scan by scope ──
    def _canon_vuln(v: str) -> str:
        s = re.sub(r"[^a-z0-9]", "", str(v).lower())
        return {
            "xss": "xss", "crosssitescripting": "xss",
            "sqli": "sqli", "sql": "sqli", "sqlinjection": "sqli",
            "ssrf": "ssrf", "serversiderequestforgery": "ssrf",
            "lfi": "lfi", "localfileinclusion": "lfi",
            "pathtraversal": "lfi", "directorytraversal": "lfi",
            "idor": "idor", "insecuredirectobjectreference": "idor",
            "openredirect": "open_redirect", "redirect": "open_redirect",
            "ssti": "ssti", "serversidetemplateinjection": "ssti",
            "xxe": "xxe", "xmlexternalentity": "xxe",
            "cmdi": "cmdi", "commandinjection": "cmdi", "rce": "cmdi",
        }.get(s, s)

    _KNOWN_VULNS = {"xss", "sqli", "ssrf", "lfi", "idor",
                    "open_redirect", "ssti", "xxe", "cmdi",
                    "nosql", "crlf", "cors", "hpp", "ldapi", "xpathi",
                    "deserialization", "host-header", "stored-xss", "blind-xss",
                    "type-juggling", "file-upload", "race-condition", "cache-poison",
                    "cache_poison"}
    allowed_set = {_canon_vuln(v) for v in allowed_vulns}
    # If no known type is derived from the scope, allow all (non-breaking behavior)
    if not (allowed_set & _KNOWN_VULNS):
        allowed_set = set(_KNOWN_VULNS)

    cookies_raw   = body.get("cookies") or body.get("cookies_str") or ""

    try:
        parsed_base = _uparse.urlparse(target)
        base_netloc = parsed_base.netloc
    except Exception as e:
        return JSONResponse({"error": f"Invalid target URL: {e}"}, status_code=400)

    cookies: dict = {}
    for _p in cookies_raw.split(";"):
        _p = _p.strip()
        if "=" in _p:
            _k, _, _v = _p.partition("=")
            cookies[_k.strip()] = _v.strip()
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Optional SECOND account (attacker B) — enables REAL two-identity IDOR/BOLA confirmation
    # (replay account A's object request as account B; if B reads A's private object → broken
    # access control). Without it, IDOR stays the conservative single-session heuristic.
    cookies_b_raw = body.get("cookies_b") or body.get("cookies2") or body.get("attacker_cookies") or ""
    cookie_header_b = ""
    if cookies_b_raw:
        _cb = {}
        for _p in cookies_b_raw.split(";"):
            _p = _p.strip()
            if "=" in _p:
                _k, _, _v = _p.partition("=")
                _cb[_k.strip()] = _v.strip()
        cookie_header_b = "; ".join(f"{k}={v}" for k, v in _cb.items())

    def _to_int(v, dv):
        try: return int(v)
        except: return dv

    MAX_CRAWL_URLS = max(200, min(_to_int(body.get("max_pages", 5000), 5000), 50000))
    MAX_DEPTH      = max(1,   min(_to_int(body.get("max_depth", 10),   10),   20))
    # LLM parallelism = Ollama's actual capacity (set OLLAMA_NUM_PARALLEL on the server to truly enable it).
    # The number of workers is much larger: deterministic tests (HTTP+regex) run in parallel freely while waiting on LLM calls.
    _LLM_PARALLEL  = max(1, _to_int(os.getenv("SCAN_LLM_PARALLEL",
                                              os.getenv("OLLAMA_NUM_PARALLEL", "3")), 3))
    N_SCAN         = max(16, _LLM_PARALLEL * 8)  # many workers → scan several URLs together
    _llm_sem       = asyncio.Semaphore(_LLM_PARALLEL)  # gate on model calls only
    MAX_TESTS      = 999999999  # No limit — scan all crawled URLs

    out_scope_ids = [s.get("identifier","").lower()
                     for s in (scope_data.get("out_scope") or [])]

    QUEUE_SCAN_STATUSES = {200, 201, 202, 203, 204, 206, 301, 302, 307, 308, 403, 401, 405, 500}

    WORDLIST = [
        "login","logout","register","auth","oauth","token","session","password",
        "forgot-password","reset-password","2fa","mfa","verify","activate",
        "user","users","account","accounts","profile","me","settings",
        "dashboard","admin","administrator","panel","console","manage","cms",
        "api","api/v1","api/v2","api/v3","v1","v2","v3",
        "api/users","api/user","api/login","api/auth","api/token","api/me",
        "api/search","api/data","api/config","api/status","api/health","api/admin",
        "api/graphql","api/v1/users","api/v1/auth","api/v1/login","api/v1/me",
        "graphql","graphiql","swagger","swagger.json","openapi.json","api-docs",
        "swagger-ui.html","redoc","api/docs",
        "debug","test","dev","staging","status","health","healthz","ping",
        "actuator","actuator/health","actuator/env","actuator/beans","metrics",
        "upload","uploads","files","file","download","media","static","assets",
        "search","find","query","filter","list","catalog","browse",
        "shop","cart","checkout","payment","order","orders","product","products",
        ".env",".git/config","config.json","package.json","robots.txt","sitemap.xml",
        "wp-admin","wp-json","wp-json/wp/v2/users","xmlrpc.php",
        "phpinfo.php","server-status",".htaccess","web.config",
        "internal","private","secret","backup","dump.sql",
    ]
    DIR_WORDLIST = [
        "api","v1","v2","v3","graphql","swagger","openapi.json",
        "login","auth","token","session","account","accounts",
        "user","users","profile","admin","dashboard","settings",
        "search","query","filter","files","upload","download",
        "status","health","metrics","debug","internal","private",
    ]

    # ── SSE helper ─────────────────────────────────────────────────────────────
    # sse_out is defined here (aicrawl_run scope) so _emit_vuln can close over it.
    # Previously it was defined inside event_stream() — a sibling nested function —
    # which made it invisible to _emit_vuln, causing a silent NameError that swallowed
    # every live vuln event (findings only appeared after a page refresh via snapshot).
    sse_out: asyncio.Queue = asyncio.Queue()
    findings: list = []  # defined BEFORE _emit_vuln so the closure sees it

    def _sse(level: str, msg: str) -> str:
        return f"data: {json.dumps({'level': level, 'message': msg})}\n\n"

    def _is_known_fp(af: dict) -> bool:
        """Check if a finding is a known false positive and should be suppressed."""
        vt = (af.get("vuln_type") or "").lower()
        url = af.get("url", "")
        ev = (af.get("evidence") or "").lower()
        detail = (af.get("detail") or "").lower()

        # CSRF on content-only pages (GET pages that happen to have a form)
        if vt == "csrf":
            if any(m in detail for m in ("same page", "same html", "content page")):
                return True
            # WordPress content pages (news, events, etc.)
            wp_paths = ("/news/", "/events", "/blog", "/podcast", "/multimedia",
                        "/images", "/live", "/social", "/nasa-", "/media")
            if any(p in url.lower() for p in wp_paths):
                if "post" in detail and "no anti-csrf" in detail:
                    return True

        # OPEN REDIRECT false positives: trailing-slash redirects where evil.com only appears as query param
        if vt == "open redirect" or vt == "open-redirect":
            if "301" in detail or "302" in detail:
                try:
                    _loc_part = ev.strip() if ev else ""
                    if _loc_part:
                        _pl2 = _uparse.urlparse(_loc_part)
                        if _pl2 and _pl2.netloc and "evil" not in _pl2.netloc:
                            return True
                except Exception:
                    pass

        # SECRET EXPOSURE: known public analytics/CMS identifiers
        if vt == "secret exposure" or vt == "secret-exposure":
            if any(m in detail for m in ("generic secret", "parsely", "siteid", "analytics")):
                return True

        # INFO DISCLOSURE: .env/.git/.svn without real content
        if vt == "info disclosure":
            p = url.lower()
            # .env paths — must contain actual env content
            if any(x in p for x in (".env",)):
                if not any(m in ev for m in ("app_", "db_", "secret", "api_key", "password", "key=", "token", "database_url")):
                    return True
            # .git paths — must contain actual git content
            if any(x in p for x in (".git",)):
                if not any(m in ev for m in ("[core]", "repositoryformatversion", "ref:", "refs/heads")):
                    return True
            # .svn paths — must contain svn content
            if ".svn" in p:
                if not any(m in ev for m in ("svn://", "dir", "svn:")):
                    return True
            # Catch-all JSON responses (e.g. sso.malwarebytes.com returns {"status":"ok"} for any path)
            body = ev[:500]
            if body.startswith("{") and '"status"' in body and ('"ok"' in body or '"error"' in body):
                return True
            # 403/redirect responses without real content
            if any(m in detail for m in ("403", "forbidden", "redirect")):
                if len(ev) < 100 or any(m in body for m in ("<html", "<!doctype", "cloudflare", "nginx", "iis")):
                    return True
            # WordPress admin redirect (302 to wp-login/wp-admin) — not real exposure
            if any(m in detail for m in ("302", "redirect")) and any(x in p for x in ("/admin", "/wp-admin", "/console")):
                if any(m in body for m in ("<html", "<!doctype", "wordpress", "wp-login", "redirect_to")):
                    return True
            # 301 trailing-slash redirects (WordPress adds / to URLs)
            if "301" in detail and "moved permanently" in detail.lower():
                return True
            # Login/signin pages — not real info disclosure
            if any(lp in p for lp in ("/login", "/signin", "/auth/", "/sign-up", "/register")):
                return True
            # robots.txt — public file by definition
            if p.endswith("/robots.txt") or p == "robots.txt":
                return True
            # access.log / install.log — only real if it actually returns log content
            if "/access.log" in p or p.endswith("access.log") or "/install.log" in p or p.endswith("install.log"):
                if "302" in detail or "redirect" in detail.lower() or "login" in body or "sign in" in body:
                    return True
                if body.startswith("<!DOCTYPE") or body.startswith("<html") or body.startswith("<HTML"):
                    if any(m in body for m in ("<meta", "<script", "<link", "<title", "<!doctype")):
                        return True
            # .git / .env / backup / dump — only real if returns actual sensitive content (not HTML)
            if any(k in p for k in (".git", ".env", "/backup", "/dump")):
                if body.startswith("<!DOCTYPE") or body.startswith("<html"):
                    return True
            # actuator paths — only real if returns actual JSON actuator content
            if "actuator" in p:
                if any(m in detail for m in ("301", "302", "redirect")):
                    return True
                if body.startswith("<!DOCTYPE") or body.startswith("<html"):
                    return True
            # Generic admin paths that redirect to login (not exposing real admin content)
            if "/admin" in p and any(m in detail for m in ("302", "redirect", "login", "signin")):
                return True

        # CACHE POISONING: never actually verified cache persistence
        if vt == "cache poisoning":
            return True

        # FILE UPLOAD BYPASS: never actually uploaded + re-fetched a working file
        if vt == "file upload bypass":
            return True

        # SSRF without actual cloud-metadata content or OOB callback
        if vt == "ssrf":
            # Re-check evidence for cloud-metadata content or OOB
            if not any(m in ev for m in ("ami-id", "instance-id", "security-credentials",
                                          "computemetadata", "instance-identity", "root:x:0:0",
                                          "redis_version", "oob", "callback", "interactsh")):
                return True

        return False

    async def _emit_vuln(af: dict):
        """Enrich finding with AI analysis + PoC exploit, append, and emit SSE."""
        _vt = af.get('vuln_type','?')
        _sv = af.get('severity','?')
        _ur = af.get('url','')[:60]

        # Suppress known false positives
        if _is_known_fp(af):
            logging.debug("FP suppressed: %s — %s", _vt, _ur)
            return

        # Emit SSE FIRST so the frontend sees the finding immediately
        findings.append(af)
        _msg = f"[{af.get('severity','?').upper()}] [{af.get('vuln_type','?')}] {af.get('url','')[:80]}"
        try:
            await sse_out.put(f"data: {json.dumps({'level': 'vuln', 'message': _msg, 'finding': af}, ensure_ascii=False, default=str)}\n\n")
        except Exception as _ex:
            pass

        # Then enrich with AI analysis and PoC in background (non-blocking)
        try:
            import ai_analyzer as _ai_mod
            await asyncio.to_thread(_ai_mod.analyze_finding, af)
        except Exception:
            pass
        try:
            import exploit_gen as _eg_mod
            _ep = await asyncio.to_thread(_eg_mod.generate_poc, af)
            if _ep.get("type") == "html":
                _dm2 = re.sub(r"[^\w.\-]", "_", _uparse.urlparse(target).netloc.lstrip("www.")) if target else ""
                _ep_dir = os.path.join(_PROJ_ROOT, _dm2, "reports", "pocs") if _dm2 else os.path.join(_PROJ_ROOT, "reports", "pocs")
                os.makedirs(_ep_dir, exist_ok=True)
                _ep_file = os.path.join(_ep_dir, _ep.get("filename", "poc.html"))
                with open(_ep_file, "w", encoding="utf-8") as _epf:
                    _epf.write(_ep.get("html", ""))
                _ep["saved_to"] = _ep_file
            af["exploit_poc"] = _ep
        except Exception:
            pass

    TOOLS = [
        {"type":"function","function":{
            "name":"make_request",
            "description":"Send a real HTTP request to test for vulnerabilities.",
            "parameters":{"type":"object","properties":{
                "url":      {"type":"string"},
                "method":   {"type":"string","enum":["GET","POST","PUT","DELETE",
                             "OPTIONS","HEAD","PATCH"]},
                "params":   {"type":"object","additionalProperties":{"type":"string"}},
                "body":     {"type":"string"},
                "headers":  {"type":"object","additionalProperties":{"type":"string"}},
                "json_body":{"type":"object"},
            },"required":["url"]},
        }},
        {"type":"function","function":{
            "name":"report_finding",
            "description":(
                "Report a CONFIRMED vulnerability. "
                "ONLY call this when you have REAL HTTP response evidence. "
                "DO NOT call for static JS/CSS files. "
                "DO NOT call if you have not verified with make_request first. "
                "DO NOT call based on guessing, code analysis, or theoretical risk. "
                "The 'evidence' field MUST contain actual HTTP response content proving the vuln."
            ),
            "parameters":{"type":"object","properties":{
                "vuln_type":     {"type":"string","description":"e.g. XSS, SQLi, SSRF, IDOR, Open Redirect, LFI, SSTI, RCE"},
                "severity":      {"type":"string","enum":["critical","high","medium","low"]},
                "url":           {"type":"string","description":"The exact vulnerable URL tested"},
                "detail":        {"type":"string","description":"What was found and why it is vulnerable"},
                "evidence":      {"type":"string","description":"Copy of the HTTP response that proves the vulnerability"},
                "payload":       {"type":"string","description":"The exact payload that triggered the vulnerability"},
                "cvss_estimate": {"type":"string"},
                "recommendation":{"type":"string"},
            },"required":["vuln_type","severity","url","detail","evidence","payload"]},
        }},
    ]

    async def _ai_call(messages: list, tools=None, max_tokens=1500) -> tuple:
        cfg = load_config()
        # ── Local only: the agent always runs via the preloaded local model (Ollama) ──
        use_ollama = True

        ollama_base = cfg.get("ollama_base", "http://localhost:11434")
        ollama_model = cfg.get("ollama_model", "llama3.1:8b")
        # ── Important: stream=False when tools are present — ensures complete tool_calls are received ──
        _do_stream = (tools is None)
        payload = {
            "model": ollama_model,
            "messages": messages,
            "stream": _do_stream,
            "keep_alive": "15m",
            "options": {
                "num_ctx": 4096,
                "num_gpu": 99,
                "temperature": 0.1,
                "num_predict": max_tokens,
            },
        }
        if tools:
            payload["tools"] = tools
        hdrs = {"Content-Type": "application/json"}
        url = f"{ollama_base}/api/chat"

        chunks, content, tcs, finish = [], "", {}, "stop"
        try:
            # Gate: we allow only _LLM_PARALLEL concurrent model calls (Ollama's real capacity);
            # deterministic tests are outside this gate, so they never wait on the model.
            async with _llm_sem, _aiohttp.ClientSession() as s:
                async with s.post(
                    url, headers=hdrs, json=payload,
                    timeout=_aiohttp.ClientTimeout(total=120),
                ) as r:
                    # ── Path 1: Ollama non-streaming (stream=False) ─────────────────
                    if use_ollama and not _do_stream:
                        resp_bytes = await r.read()
                        resp_text  = resp_bytes.decode("utf-8", errors="replace")
                        try:
                            c = json.loads(resp_text)
                        except Exception:
                            # Sometimes Ollama sends a single NDJSON line
                            c = {}
                            for _ln in resp_text.splitlines():
                                _ln = _ln.strip()
                                if _ln:
                                    try: c = json.loads(_ln); break
                                    except: pass
                        msg_obj = c.get("message") or {}
                        dc = msg_obj.get("content") or ""
                        if dc:
                            content = dc
                            chunks.append(f"data: {json.dumps({'level':'ai','message':dc,'ai_phase':'test'})}\n\n")
                        for i, tc_item in enumerate(msg_obj.get("tool_calls") or []):
                            fn     = tc_item.get("function") or {}
                            tc_id  = f"call_{i}"
                            tc_args = fn.get("arguments", {})
                            tcs[tc_id] = {
                                "id":        tc_id,
                                "name":      fn.get("name", ""),
                                "arguments": json.dumps(tc_args) if isinstance(tc_args, dict) else (tc_args or "{}"),
                            }
                    # ── Path 2: streaming (stream=True) ────────────────────────────
                    else:
                        async for raw in r.content:
                            line = raw.decode("utf-8", errors="replace").strip()
                            if not line: continue
                            try:
                                c = json.loads(line)
                                if "message" in c:
                                    msg_obj = c.get("message") or {}
                                    dc = msg_obj.get("content", "")
                                    if dc:
                                        content += dc
                                        chunks.append(f"data: {json.dumps({'level':'ai','message':dc,'ai_phase':'test'})}\n\n")
                                    for i, tc_item in enumerate(msg_obj.get("tool_calls") or []):
                                        fn     = tc_item.get("function") or {}
                                        tc_id  = f"call_{i}"
                                        tc_args = fn.get("arguments", {})
                                        tcs[tc_id] = {
                                            "id":        tc_id,
                                            "name":      fn.get("name", ""),
                                            "arguments": json.dumps(tc_args) if isinstance(tc_args, dict) else (tc_args or "{}"),
                                        }
                                    if c.get("done"): break
                                elif line.startswith("data: "):
                                    ds = line[6:]
                                    if ds == "[DONE]": break
                                    ch = (c.get("choices") or [{}])[0]
                                    d  = ch.get("delta", {})
                                    if ch.get("finish_reason"): finish = ch["finish_reason"]
                                    dc = d.get("content", "")
                                    if dc:
                                        content += dc
                                        chunks.append(f"data: {json.dumps({'level':'ai','message':dc,'ai_phase':'test'})}\n\n")
                            except Exception:
                                continue
        except Exception as e:
            content = f"[AI error: {e}]"
        return chunks, content, tcs, finish

    async def _ai_triage_url(url, prms, forms, snippet, hdrs, st_code, allowed) -> dict:
        """Single fast AI call: analyze URL context and return structured attack-surface hints.
        Runs BEFORE the static scan so results guide what to prioritize.
        Returns {"priority_vulns":[...], "interesting_params":[...], "hints":[...], "skip":bool}
        or {} on any failure (never raises)."""
        import re as _re2
        _sys = (
            "You are a vulnerability triage expert. Analyze a web URL and return ONLY valid JSON.\n"
            'JSON schema: {"priority_vulns":["list of vuln types ordered by likelihood"],'
            '"interesting_params":["param names most worth injecting"],'
            '"hints":["short reasoning strings, max 60 chars each"],'
            '"skip":false}\n'
            "priority_vulns: only types from the allowed list that are plausible given the context.\n"
            "interesting_params: params that look like object IDs, user input, redirects, file paths.\n"
            "hints: 1-3 short clues explaining each choice.\n"
            "skip: true ONLY for pure static media (images/fonts/video) with no injection surface.\n"
            "Return ONLY the JSON object — no markdown fences, no extra text."
        )
        _usr = (
            f"URL: {url}\nHTTP status: {st_code}\n"
            f"Query params: {json.dumps(list((prms or {}).keys()))}\n"
            f"Form count: {len(forms or [])}\n"
            f"Response headers: {json.dumps({k: v for k, v in list((hdrs or {}).items())[:10]})}\n"
            f"Allowed vuln types: {json.dumps(sorted(allowed))}\n"
            f"Page snippet (first 1000 chars):\n{(snippet or '')[:1000]}\n\n"
            "Return JSON triage — which vulns are most likely HERE and WHY."
        )
        try:
            _, _tc, _, _ = await _ai_call(
                [{"role": "system", "content": _sys},
                 {"role": "user",   "content": _usr}],
                tools=None, max_tokens=350
            )
            _jm = _re2.search(r'\{[\s\S]{10,800}\}', _tc or "")
            if _jm:
                _parsed = json.loads(_jm.group())
                if isinstance(_parsed, dict):
                    return _parsed
        except Exception:
            pass
        return {}

    # ── Shared mutable state ────────────────────────────────────────────────────
    tested:   set  = set()      # URLs/forms already AI-scanned (never re-scanned)
    seen:     set  = set()      # every URL emitted by the crawler (for resume skip)
    _passive_seen: set = set()  # dedup key for passive findings (site-wide vs per-URL)
    _reqlevel_hosts: set = set()# hosts already checked for CORS/Host-header/XXE (run once per host)
    _oob_pending: list = []     # [(token, vtype, url, detail)] awaiting an OAST callback
    _dom_seen: set = set()      # URLs already DOM-XSS scanned (browser is expensive)
    _pro_hosts: set = set()     # hosts already given the once-per-host pro checks (VCS/GraphQL/clickjacking)
    fp_text:  list = [""]

    # ── Resumable state on disk (pause + continue after closing the program/machine) ──
    import time as _time
    _resume       = bool(body.get("resume"))
    _state_host   = (_uparse.urlparse(target).netloc or target).lstrip("www.")
    _state_folder = re.sub(r"[^\w.\-]", "_", _state_host)
    _state_dir    = os.path.join(_PROJ_ROOT, _state_folder)
    _state_file   = os.path.join(_state_dir, "scan_state.json")
    _state_lock   = asyncio.Lock()
    _state_meta   = {"crawled": 0, "last_save": 0.0, "completed": False}

    # ── Pause gate: SET = running, CLEARED = paused. Pause suspends the workers and the
    # crawler IN PLACE (state kept in memory) so resume continues from exactly where it
    # stopped — it is NOT a restart. Shared on the scan object for the pause/resume endpoints.
    resume_gate = asyncio.Event()
    resume_gate.set()

    if _resume and os.path.isfile(_state_file):
        try:
            with open(_state_file, "r", encoding="utf-8") as _rf:
                _saved = json.load(_rf)
            for _u in _saved.get("tested", []):
                tested.add(_u)
            findings.extend(_saved.get("findings", []))
            _state_meta["crawled"] = _saved.get("crawled", 0)
        except Exception:
            pass

    async def _save_scan_state(status: str = "paused", force: bool = False):
        """Saves the scan progress (tested + findings) to disk so it can be resumed later.
        Rate-limited to once every ~4 seconds to avoid disk pressure, or immediate when force."""
        now = _time.time()
        if not force and (now - _state_meta["last_save"]) < 4.0:
            return
        _state_meta["last_save"] = now
        async with _state_lock:
            try:
                os.makedirs(_state_dir, exist_ok=True)
                _tmp = _state_file + ".tmp"
                with open(_tmp, "w", encoding="utf-8") as _wf:
                    json.dump({
                        "target":       target,
                        "status":       status,
                        "tested":       list(tested),
                        "seen":         list(seen),
                        "findings":     findings,
                        "crawled":      _state_meta["crawled"],
                        "tested_count": len(tested),
                        "vuln_count":   len(findings),
                        "updated":      datetime.now().isoformat(timespec="seconds"),
                    }, _wf, ensure_ascii=False)
                os.replace(_tmp, _state_file)
            except Exception:
                pass

    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
          "AppleWebKit/537.36 Chrome/124.0 Safari/537.36")

    async def _req_ai(session, url: str, method="GET",
                      params=None, data=None, json_b=None, hdrs=None) -> dict:
        merged = {"User-Agent": UA, "Accept": "text/html,application/json,*/*;q=0.8",
                  **(hdrs or {})}
        if cookies:
            merged["Cookie"] = cookie_header
        try:
            async with session.request(
                method, url, headers=merged, params=params,
                data=data, json=json_b,
                timeout=_aiohttp.ClientTimeout(total=20, connect=8),
                allow_redirects=True, max_redirects=5, ssl=False,
            ) as r:
                raw  = await r.read()
                body = raw.decode("utf-8", errors="replace")
                return {"status": r.status, "headers": dict(r.headers),
                        "body": body[:40000], "url": str(r.url), "error": None}
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}

    # ── AI SCAN WORKER ──────────────────────────────────────────────────────────
    async def scan_worker(session, scan_q: asyncio.Queue, sse_out: asyncio.Queue,
                          stop_event: asyncio.Event):
        while not stop_event.is_set():
            await resume_gate.wait()           # suspend here while paused (queue is preserved)
            if stop_event.is_set(): break
            try:
                page = await asyncio.wait_for(scan_q.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                if stop_event.is_set():
                    continue   # Stop pressed → drop this page without scanning (task_done in finally)
                url     = page["url"]
                # ── POST/GET form scan: adaptive injection into every field (like Burp) ──────────
                if page.get("is_form") and de is not None:
                    _fm = page.get("form") or {}
                    _fields = [i for i in _fm.get("inputs", []) if i.get("name")]
                    _fmethod = (_fm.get("method") or "GET").upper()
                    _fkey = "FORM:" + _fmethod + ":" + url + ":" + ",".join(sorted(i["name"] for i in _fields))
                    if not _fields or _fkey in tested:
                        continue
                    tested.add(_fkey)
                    _fenc = _fm.get("enctype", "application/x-www-form-urlencoded")
                    _vals = {i["name"]: (i.get("value") or "1") for i in _fields}
                    if "json" in _fenc:
                        _fbody = json.dumps(_vals); _fct = "application/json"; _faction = url
                    elif _fmethod == "GET":
                        _faction = url + ("&" if "?" in url else "?") + _uparse.urlencode(_vals)
                        _fbody = ""; _fct = ""
                    else:
                        _fbody = _uparse.urlencode(_vals); _fct = "application/x-www-form-urlencoded"; _faction = url

                    def _fsend(_m, _u, _h, _c, _b, _ff=True):
                        import time as _t
                        import requests as _rq
                        _hh = dict(_h or {})
                        if _c:
                            _hh["Cookie"] = "; ".join(f"{k}={v}" for k, v in _c.items())
                        if _b and _fct:
                            _hh["Content-Type"] = _fct
                        _t0 = _t.time()
                        _rr = _rq.request(_m, _u, headers=_hh, data=(_b or None),
                                          timeout=12, allow_redirects=_ff, verify=False)
                        return de.Resp(status=_rr.status_code, headers=dict(_rr.headers),
                                       body=_rr.text, elapsed=_t.time() - _t0, url=_u)

                    _ck = {}
                    for _kv in (cookie_header or "").split(";"):
                        if "=" in _kv:
                            _kk, _vv = _kv.split("=", 1); _ck[_kk.strip()] = _vv.strip()
                    _ftypes = [t for t in ("xss", "sqli", "ssti", "lfi", "cmdi") if t in allowed_set]
                    await sse_out.put(_sse("scan", f"🔬 form scan [{_fmethod}] {url[:70]} ({len(_fields)} fields)"))
                    try:
                        _fap = await asyncio.get_running_loop().run_in_executor(
                            _DET_POOL, functools.partial(
                                de.scan_all_points, _fsend, _fmethod, _faction,
                                {"User-Agent": UA}, _ck, _fbody, _fct, _ftypes, False, 24))
                    except Exception:
                        _fap = []
                    _FSEV = {"xss": ("high", "6.1"), "sqli": ("critical", "9.8"),
                             "ssti": ("critical", "9.0"), "lfi": ("high", "7.5"),
                             "cmdi": ("critical", "9.8")}
                    for _pt, _vt, _res in _fap:
                        if _res.confidence not in (de.CONFIRMED, de.PROBABLE):
                            continue
                        _pd = f"{_pt.place}:{_pt.name}"
                        if any(f.get("vuln_type") == _vt.upper()
                               and f.get("proof", {}).get("point", {}).get("name") == _pt.name
                               for f in findings):
                            continue
                        _sev, _cv = _FSEV.get(_vt, ("high", "6.1"))
                        if _res.confidence == de.PROBABLE:
                            _af = {
                                "vuln_type": _vt.upper(), "severity": "low", "url": url,
                                "detail": (f"[PROBABLE] {_vt.upper()} in form field {_pd} [{_fmethod}] "
                                           "— single signal, manual review: " + "; ".join(_res.signals[:3])),
                                "evidence": (_res.evidence or "")[:600], "payload": _res.payload,
                                "cvss": "3.1", "proof": _res.proof,
                                "recommendation": "Manual verification required — single detection signal.",
                            }
                        else:
                            _af = {
                                "vuln_type": _vt.upper(), "severity": _sev, "url": url,
                                "detail": (f"{_vt.upper()} CONFIRMED in form field {_pd} [{_fmethod}] "
                                           "(adaptive differential): " + "; ".join(_res.signals[:3])),
                                "evidence": (_res.evidence or "")[:600], "payload": _res.payload,
                                "cvss": _cv, "proof": _res.proof,
                                "recommendation": "Validate/encode input; parameterized queries / sandboxed templates as applicable.",
                            }
                        await _emit_vuln(_af)

                    # ── CSRF check on state-changing forms ──
                    if _fmethod in ("POST", "PUT", "DELETE", "PATCH"):
                        try:
                            _csrf_res = await asyncio.get_running_loop().run_in_executor(
                                _DET_POOL, functools.partial(
                                    de.detect_csrf, _fsend, _fmethod, _faction,
                                    {"User-Agent": UA}, _ck, _fbody, _fct,
                                    target_netloc=_uparse.urlparse(target).netloc))
                        except Exception:
                            _csrf_res = None
                        if _csrf_res is not None and _csrf_res.confidence in (de.CONFIRMED, de.PROBABLE):
                            _cssev = _csrf_res.severity or "high"
                            _af = {
                                "vuln_type": "CSRF",
                                "severity": _cssev,
                                "url": _faction,
                                "detail": "; ".join(_csrf_res.signals[:3]) or "CSRF protection missing",
                                "evidence": json.dumps(_csrf_res.proof or {})[:400],
                                "payload": "",
                                "cvss": "6.5" if _cssev == "high" else "4.3",
                                "proof": _csrf_res.proof or {},
                                "recommendation": "Implement anti-CSRF tokens (CSRF-Token header or SameSite=Strict cookies) "
                                                  "or validate Origin/Referer headers on state-changing requests.",
                            }
                            if not _is_dup_finding(findings, _faction, "CSRF"):
                                await _emit_vuln(_af)

                    # ── API body checks on JSON forms: Mass Assignment (BOPLA) + NoSQL operator injection ──
                    if ps is not None and _fct == "application/json" and _fmethod in ("POST", "PUT", "PATCH"):
                        _jhdr = {"User-Agent": UA, "Content-Type": "application/json"}

                        def _send_fields(_extra):
                            _bd = dict(_vals); _bd.update(_extra or {})
                            return _fsend(_fmethod, _faction, _jhdr, _ck, json.dumps(_bd), True)

                        _opfield = next(iter(_vals), None)   # commonly user/login/email

                        def _send_op(_value):
                            _bd = dict(_vals)
                            if _opfield is not None:
                                _bd[_opfield] = _value
                            return _fsend(_fmethod, _faction, _jhdr, _ck, json.dumps(_bd), True)

                        try:
                            _fapi = await asyncio.get_running_loop().run_in_executor(
                                _DET_POOL, functools.partial(ps.run_form_checks, _send_fields, _send_op, url))
                        except Exception:
                            _fapi = []
                        for _pf in _fapi:
                            if _is_dup_finding(findings, _pf.get("url", ""), _pf.get("vuln_type", "")):
                                continue
                            await _emit_vuln(_pf)
                    continue
                if url in tested:
                    continue
                tested.add(url)
                prms    = page.get("params", {})
                forms   = page.get("forms", [])
                _has_injection = bool(prms) or bool(forms)
                p_hdrs  = {k.lower(): v[:150] for k, v in list(page.get("headers", {}).items())[:20]}
                snippet = page.get("body", "")[:2000]
                st_code = page.get("status", "?")

                await sse_out.put(
                    f"data: {json.dumps({'level':'live_url','url':url,'status':st_code,'state':'scanning'}, ensure_ascii=False)}\n\n"
                )
                # Show in terminal that scanning is happening
                await sse_out.put(_sse("scan", f"🔍 [{st_code}] {url[:90]}"))

                # Determine the file type to steer the AI toward the correct vulnerabilities
                _url_path = _uparse.urlparse(url).path.lower()
                _, _url_ext = os.path.splitext(_url_path)
                _is_js_css = _url_ext in {'.js','.jsx','.mjs','.cjs','.ts','.tsx','.css','.scss','.map'}
                _is_media  = _url_ext in {'.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.woff','.woff2','.ttf','.eot','.mp4','.mp3','.pdf'}

                # ── AI Pre-Analysis: understand attack surface BEFORE static scan runs ──
                # The AI sees the URL, params, headers, and page snippet and decides:
                #   • which vuln types are most plausible (priority_vulns)
                #   • which params are most worth injecting (interesting_params)
                #   • why (hints — shown to the user and passed to the final AI loop)
                # The deterministic static scan then uses this to prioritize its work.
                _triage: dict = {}
                if not _is_media and not stop_event.is_set() and _has_injection:
                    try:
                        _triage = await _ai_triage_url(
                            url, prms, forms, snippet, p_hdrs, st_code, allowed_set) or {}
                    except Exception:
                        _triage = {}
                    if _triage:
                        if _triage.get("skip"):
                            await sse_out.put(_sse("scan",
                                f"🧠 AI: static asset — skipping deep scan @ {url[:60]}"))
                            continue
                        _t_vulns  = [v for v in (_triage.get("priority_vulns") or [])
                                     if v in allowed_set]
                        _t_params = (_triage.get("interesting_params") or [])[:5]
                        _t_hints  = (_triage.get("hints") or [])[:3]
                        _tsummary = (
                            (f"focus: [{', '.join(_t_vulns[:4])}]" if _t_vulns else "") +
                            (f" | params: {', '.join(_t_params)}" if _t_params else "")
                        ).strip(" |")
                        if _tsummary:
                            await sse_out.put(_sse("scan",
                                f"🧠 AI triage → {_tsummary} @ {url[:45]}"))
                        if _t_hints:
                            await sse_out.put(_sse("scan",
                                "   💡 " + " • ".join(_t_hints)))

                # ── PRO detectors: access-control / JWT / GraphQL / exposed-VCS / blind-OOB /
                #    JS secret+endpoint mining / clickjacking — same dict shape, emitted inline ──
                if de is not None and ps is not None and not _is_media:
                    _pck = {}
                    for _kv in (cookie_header or "").split(";"):
                        if "=" in _kv:
                            _k2, _v2 = _kv.split("=", 1); _pck[_k2.strip()] = _v2.strip()

                    def _psend(_m, _u, _h, _c, _b, _f=True):
                        import time as _t
                        import requests as _rq
                        _hh = dict(_h or {})
                        if _c:
                            _hh["Cookie"] = "; ".join(f"{k}={v}" for k, v in _c.items())
                        _t0 = _t.time()
                        _rr = _rq.request(_m, _u, headers=_hh, data=(_b or None),
                                          timeout=12, allow_redirects=_f, verify=False)
                        return de.Resp(status=_rr.status_code, headers=dict(_rr.headers),
                                       body=_rr.text, elapsed=_t.time() - _t0, url=_u)

                    _phost = _uparse.urlparse(url).netloc
                    _host_first = _phost not in _pro_hosts
                    if _host_first:
                        _pro_hosts.add(_phost)
                    _ocp = scan_obj.get("oast")
                    _newoob = (_ocp.new_payload if (_ocp is not None and getattr(_ocp, "ready", False)) else None)
                    try:
                        _pres = await asyncio.get_running_loop().run_in_executor(
                            _DET_POOL, functools.partial(
                                ps.run_url_checks, _psend, url,
                                status=(st_code if isinstance(st_code, int) else 0),
                                page_headers=page.get("headers") or {}, cookies=_pck,
                                allowed=allowed_set, host_first_seen=_host_first,
                                is_js=_is_js_css, new_oob=_newoob, ua=UA))
                    except Exception:
                        _pres = {"findings": [], "oob_pending": []}
                    for _pf in _pres.get("findings", []):
                        if _is_dup_finding(findings, _pf.get("url", ""), _pf.get("vuln_type", "")):
                            continue
                        if _is_known_fp(_pf):
                            continue
                        _sv = (_pf.get("severity") or "info").upper()
                        if _sv == "INFO":
                            findings.append(_pf)
                            await sse_out.put("data: " + json.dumps(
                                {"level": "scan", "message": f"[{_sv}] [{_pf.get('vuln_type')}] {(_pf.get('url') or url)[:70]}",
                                 "finding": _pf}, ensure_ascii=False) + "\n\n")
                        else:
                            await _emit_vuln(_pf)
                    for _op in _pres.get("oob_pending", []):
                        _oob_pending.append(_op)

                    # ── SPA Crawler (once per host) — executor so event loop is never blocked ──
                    if _host_first and _browser_mod is not None and _browser_mod.available():
                        try:
                            await sse_out.put(_sse("info", "🌐 Launching SPA crawler for JS route discovery …"))
                            _spa_url_cap = url
                            _spa_mod_cap = _browser_mod
                            def _do_spa_crawl():
                                _s = _spa_mod_cap.SPACrawler()
                                with _s:
                                    return _s.crawl(_spa_url_cap, max_pages=5)
                            _spa_result = await asyncio.get_running_loop().run_in_executor(_DET_POOL, _do_spa_crawl)
                            _discovered = [u for u in _spa_result.get("urls", []) if u not in crawled_urls]
                            for _du in _discovered[:10]:
                                if _du not in crawled_urls:
                                    crawled_urls.add(_du)
                                    await scan_q.put(_du)
                                    await sse_out.put(_sse("crawl", f"SPA: {_du}"))
                            for _api in _spa_result.get("apis", [])[:5]:
                                if _api not in crawled_urls:
                                    crawled_urls.add(_api)
                                    await scan_q.put(_api)
                                    await sse_out.put(_sse("crawl", f"API: {_api}"))
                            for _frm in _spa_result.get("forms", []):
                                _fa = _frm.get("action", "")
                                if _fa and _fa not in crawled_urls:
                                    _full = _uparse.urljoin(url, _fa)
                                    crawled_urls.add(_full)
                                    await scan_q.put(_full)
                        except Exception as _se:
                            logging.warning(f"SPA crawl fail: {_se}")

                    # ── Wordlist generation (once per host) — executor so HTTP calls don't block event loop ──
                    if _host_first and _dpro_mod is not None:
                        try:
                            _wl_url_cap = url
                            _wl_body_cap = page.get("body") or ""
                            _wl_psend_cap = _psend
                            _wl_dpro_cap = _dpro_mod
                            def _do_wordlist():
                                _rb = _wl_psend_cap("GET", _uparse.urlunparse(
                                    _uparse.urlparse(_wl_url_cap)._replace(path="/robots.txt")), {}, {}, "", True)
                                _sm = _wl_psend_cap("GET", _uparse.urlunparse(
                                    _uparse.urlparse(_wl_url_cap)._replace(path="/sitemap.xml")), {}, {}, "", True)
                                return _wl_dpro_cap.build_site_wordlist(
                                    body=_wl_body_cap, url=_wl_url_cap,
                                    robots_txt=(_rb.body or "") if _rb and _rb.status == 200 else "",
                                    sitemap_xml=(_sm.body or "") if _sm and _sm.status == 200 else "",
                                )
                            _words = await asyncio.get_running_loop().run_in_executor(_DET_POOL, _do_wordlist)
                            scan_obj["site_wordlist"] = _words
                            if _words:
                                await sse_out.put(_sse("info", f"📝 Generated {len(_words)} site-specific words for fuzzing"))
                        except Exception as _we:
                            pass

                    # ── Business Logic detection (once per host) — executor ──
                    if _host_first:
                        try:
                            import detect_extras as _dx
                            _blr = await asyncio.get_running_loop().run_in_executor(
                                _DET_POOL, functools.partial(_dx.detect_business_logic, _psend, url))
                            if _blr and _blr.confidence in (de.CONFIRMED, de.PROBABLE):
                                _af = {"vuln_type": "BUSINESS LOGIC", "severity": _blr.severity or "critical",
                                       "url": url, "detail": "; ".join(_blr.signals[:3]),
                                       "evidence": (_blr.evidence or "")[:600],
                                       "payload": _blr.payload or "", "cvss": "9.0",
                                       "proof": _blr.proof,
                                       "recommendation": "Review business logic flow for bypass vulnerabilities."}
                                await _emit_vuln(_af)
                        except Exception as _ble:
                            pass

                    # ── Screenshot diff for XSS findings ──
                    if "xss" in allowed_set and _browser_mod is not None and _browser_mod.available():
                        try:
                            if "screenshot_diff" not in scan_obj:
                                scan_obj["screenshot_diff"] = _browser_mod.ScreenshotDiff(
                                    output_dir=os.path.join(_PROJ_ROOT, re.sub(r"[^\w.\-]", "_",
                                        _uparse.urlparse(url).netloc.lstrip("www.")), "reports", "screenshots"))
                        except Exception:
                            pass

                # ── Programmatic pre-test (runs regardless of AI) ────────────────
                _parsed_url = _uparse.urlparse(url)
                _qparams    = _uparse.parse_qs(_parsed_url.query, keep_blank_values=True)
                if _qparams and not _is_js_css and not _is_media:
                    # ── Adaptive scan of all injection points (URL params + HTTP headers + cookies) like Burp ──
                    # One calibration per URL, differential confirmation, fast mode (no 5s timing) to preserve speed.
                    if de is not None:
                        def _send(_m, _u, _h, _c, _b, _f=True):
                            import time as _t
                            import requests as _rq
                            _hh = dict(_h or {})
                            if _c:
                                _hh["Cookie"] = "; ".join(f"{k}={v}" for k, v in _c.items())
                            _t0 = _t.time()
                            _rr = _rq.request(_m, _u, headers=_hh, data=(_b or None),
                                              timeout=12, allow_redirects=_f, verify=False)
                            return de.Resp(status=_rr.status_code, headers=dict(_rr.headers),
                                           body=_rr.text, elapsed=_t.time() - _t0, url=_u)
                        _ck = {}
                        for _kv in (cookie_header or "").split(";"):
                            if "=" in _kv:
                                _ckk, _ckv = _kv.split("=", 1)
                                _ck[_ckk.strip()] = _ckv.strip()
                        _types = [t for t in ("xss", "sqli", "ssti", "lfi", "cmdi", "nosql", "crlf")
                                  if t in allowed_set]
                        # ── Reorder by AI triage priority: AI-flagged types go first ──
                        if _triage:
                            _ai_prio = [v for v in (_triage.get("priority_vulns") or [])
                                        if v in _types]
                            _rest    = [t for t in _types if t not in _ai_prio]
                            _types   = _ai_prio + _rest
                        for _x in ("nosql", "crlf"):   # always test these high-value classes
                            if _x not in _types:
                                _types.append(_x)
                        try:
                            _ap = await asyncio.get_running_loop().run_in_executor(
                                _DET_POOL, functools.partial(
                                    de.scan_all_points, _send, "GET", url,
                                    {"User-Agent": UA}, _ck, "", "", _types, False, 24))
                        except Exception:
                            _ap = []
                        # POST retry — resend same params as form body (catches endpoints that
                        # reject GET injection but accept POST; doubles detection surface)
                        if prms:
                            try:
                                _post_body = "&".join(f"{k}=FUZZ" for k in prms)
                                _ap_post = await asyncio.get_running_loop().run_in_executor(
                                    _DET_POOL, functools.partial(
                                        de.scan_all_points, _send, "POST", url,
                                        {"User-Agent": UA,
                                         "Content-Type": "application/x-www-form-urlencoded"},
                                        _ck, _post_body,
                                        "application/x-www-form-urlencoded", _types, False, 24))
                                _ap = list(_ap) + [_pp for _pp in _ap_post
                                                   if _pp[2].confidence != de.SAFE
                                                   and not any(_e[0].name == _pp[0].name
                                                               and _e[1] == _pp[1] for _e in _ap)]
                            except Exception:
                                pass
                        _ESEV = {"xss": ("high", "6.1"), "sqli": ("critical", "9.8"),
                                 "ssti": ("critical", "9.0"), "lfi": ("high", "7.5"),
                                 "cmdi": ("critical", "9.8"), "nosql": ("critical", "9.8"),
                                 "crlf": ("high", "6.5")}
                        for _pt, _vt, _res in _ap:
                            _pdesc = ("an injected URL parameter NAME"
                                      if _pt.place == "query_name" else f"{_pt.place}:{_pt.name}")
                            _seen = any(f.get("vuln_type") == _vt.upper()
                                        and f.get("proof", {}).get("point", {}).get("name") == _pt.name
                                        and f.get("proof", {}).get("point", {}).get("place") == _pt.place
                                        for f in findings)
                            if _seen:
                                continue
                            if _res.confidence == de.CONFIRMED:
                                _sev, _cv = _ESEV.get(_vt, ("high", "6.1"))
                                _af = {
                                    "vuln_type": _vt.upper(), "severity": _sev, "url": url,
                                    "detail": (f"{_vt.upper()} CONFIRMED at {_pdesc} (adaptive differential): "
                                               + "; ".join(_res.signals[:3])),
                                    "evidence": (_res.evidence or "")[:600],
                                    "payload": _res.payload, "cvss": _cv, "proof": _res.proof,
                                    "recommendation": "Validate/encode input; parameterized queries / sandboxed templates as applicable.",
                                }
                                await _emit_vuln(_af)
                            elif _res.confidence == de.PROBABLE:
                                _prob_af = {
                                    "vuln_type": _vt.upper(), "severity": "low", "url": url,
                                    "detail": (f"[PROBABLE] {_vt.upper()} at {_pdesc} — single signal, "
                                               "manual review: " + "; ".join(_res.signals[:3])),
                                    "evidence": (_res.evidence or "")[:600],
                                    "payload": _res.payload, "cvss": "3.1", "proof": _res.proof,
                                    "recommendation": "Manual verification required — single detection signal.",
                                }
                                await _emit_vuln(_prob_af)

                        # ── Request-level checks (once per host): CORS / Host-header / in-band XXE ──
                        _host = _uparse.urlparse(url).netloc
                        if _host and _host not in _reqlevel_hosts:
                            _reqlevel_hosts.add(_host)
                            for _rn, _rfn in (("cors", de.detect_cors_active),
                                              ("host-header", de.detect_host_injection),
                                              ("xxe", de.detect_xxe)):
                                try:
                                    _rr = await asyncio.get_running_loop().run_in_executor(
                                        _DET_POOL, functools.partial(_rfn, _send, url, {"User-Agent": UA}, _ck))
                                except Exception:
                                    _rr = None
                                if _rr and _rr.confidence == de.CONFIRMED:
                                    _rsev = _rr.severity or "medium"
                                    _af = {"vuln_type": _rn.upper().replace("-", " "), "severity": _rsev,
                                           "url": url, "detail": "; ".join(_rr.signals[:3]),
                                           "evidence": (_rr.evidence or "")[:600], "payload": _rr.payload,
                                           "cvss": "", "proof": _rr.proof, "recommendation": ""}
                                    await _emit_vuln(_af)

                        # ── DOM-based XSS via headless Chromium (once per param'd URL) ──
                        _dsx = scan_obj.get("dom_scanner")
                        if _dsx is not None and url not in _dom_seen and "xss" in allowed_set:
                            _dom_seen.add(url)
                            try:
                                _domhit = await asyncio.get_running_loop().run_in_executor(
                                    _DOM_POOL, functools.partial(_dsx.scan_url, url, _ck))
                            except Exception:
                                _domhit = None
                            if _domhit:
                                _af = {"vuln_type": "DOM XSS", "severity": "high", "url": _domhit["url"],
                                       "detail": f"DOM-based XSS executed in the browser ({_domhit['sink']}) — payload fired alert()",
                                       "evidence": _domhit["payload"], "payload": _domhit["payload"], "cvss": "6.1",
                                       "proof": {"sink": _domhit["sink"], "marker": _domhit["marker"]},
                                       "recommendation": "Avoid innerHTML/document.write/eval on untrusted DOM sources; use textContent/sanitizers."}
                                await _emit_vuln(_af)

                        # ── Out-of-band (blind) SSRF: inject a unique OAST URL; correlated at scan end ──
                        _oc2 = scan_obj.get("oast")
                        if _oc2 is not None and getattr(_oc2, "ready", False) and \
                                ("ssrf" in allowed_set or "open_redirect" in allowed_set):
                            _urlish = [p for p in _qparams if any(s in p.lower() for s in (
                                "url", "uri", "next", "redirect", "return", "dest", "callback", "feed",
                                "host", "site", "path", "src", "target", "link", "domain", "page", "img"))]
                            for _pp in _urlish[:3]:
                                _tok, _ohost = _oc2.new_payload()
                                if not _tok:
                                    break
                                _oqs = {k: v[0] for k, v in _qparams.items()}
                                _oqs[_pp] = f"http://{_ohost}/"
                                _ourl = _uparse.urlunparse(_parsed_url._replace(query=_uparse.urlencode(_oqs)))
                                try:
                                    await asyncio.get_running_loop().run_in_executor(
                                        _DET_POOL, functools.partial(_send, "GET", _ourl, {"User-Agent": UA}, _ck, "", True))
                                except Exception:
                                    pass
                                _oob_pending.append((_tok, "SSRF", _ourl, f"param '{_pp}' fetched our OAST URL (blind SSRF)"))

                        # ── New Extra Detectors (25 Burp-class modules) ──
                        try:
                            import detect_extras as _dx
                            _dx_imported = True
                        except Exception:
                            _dx_imported = False
                        if _dx_imported and _qparams and not _is_js_css and not _is_media:
                            _dx_params = {k: v[0] for k, v in _qparams.items()}
                            _dx_host = _uparse.urlparse(url).netloc
                            # Run extra detectors per URL
                            for _dx_type, _dx_fn, _dx_sev, _dx_cv in (
                                ("ssrf", _dx.detect_ssrf, "critical", "9.8"),
                                ("cmdi", _dx.detect_cmd_injection, "critical", "9.8"),
                                ("ssti", _dx.detect_ssti, "critical", "9.0"),
                                ("xxe", _dx.detect_xxe, "critical", "9.0"),
                                ("open-redirect", _dx.detect_open_redirect, "medium", "6.1"),
                                ("hpp", _dx.detect_hpp, "medium", "5.3"),
                                ("ldapi", _dx.detect_ldapi, "critical", "9.8"),
                                ("xpathi", _dx.detect_xpathi, "high", "7.5"),
                                ("deserialization", _dx.detect_insecure_deserialization, "critical", "9.8"),
                                ("type-juggling", _dx.detect_type_juggling, "critical", "9.8"),
                                ("crlf", _dx.detect_crlf, "high", "6.5"),
                                ("host-header", _dx.detect_host_header_injection, "high", "6.5"),
                                ("cache-poison", _dx.detect_cache_poisoning, "high", "6.5"),
                            ):
                                if _dx_type not in allowed_set:
                                    continue
                                try:
                                    if _dx_type == "host-header":
                                        _dxcall = functools.partial(_dx_fn, _send, url)
                                    elif _dx_type == "xxe":
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params)
                                    elif _dx_type == "cache-poison":
                                        _dxcall = functools.partial(_dx_fn, _send, url)
                                    elif _dx_type in ("crlf", "hpp", "ldapi", "xpathi", "type-juggling"):
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params)
                                    elif _dx_type == "ssti":
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params)
                                    elif _dx_type == "open-redirect":
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params)
                                    elif _dx_type == "deserialization":
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params)
                                    elif _dx_type in ("ssrf",):
                                        _oc2b = scan_obj.get("oast")
                                        _oob_ready = _oc2b is not None and getattr(_oc2b, "ready", False)
                                        _oob_host = ""
                                        if _oob_ready:
                                            _tok_b, _oob_host = _oc2b.new_payload()
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params, _oob_ready, _oob_host)
                                    else:
                                        _dxcall = functools.partial(_dx_fn, _send, url, _dx_params)
                                    _dxr = await asyncio.get_running_loop().run_in_executor(_DET_POOL, _dxcall)
                                except Exception as _dxe:
                                    _dxr = None
                                if _dxr and _dxr.confidence in (de.CONFIRMED, de.PROBABLE):
                                    _dxsev = _dxr.severity or _dx_sev
                                    _af = {
                                        "vuln_type": _dx_type.upper().replace("-", " "),
                                        "severity": _dxsev, "url": url,
                                        "detail": "; ".join(_dxr.signals[:3]) or _dx_type,
                                        "evidence": (_dxr.evidence or "")[:600],
                                        "payload": _dxr.payload or "", "cvss": _dx_cv,
                                        "proof": _dxr.proof,
                                        "recommendation": "Review and fix the identified vulnerability per security best practices.",
                                    }
                                    await _emit_vuln(_af)

                    for _pname in list(_qparams.keys())[:3]:  # IDOR per param (kept separate)
                        # IDOR probe — strict conditions to avoid false positives (pagination/tracking):
                        #  1) IDOR within scope  2) an authenticated session (cookies) — there are no privileges
                        #     to bypass without a session  3) the parameter looks like an object identifier, not pagination.
                        _pval = _qparams[_pname][0]
                        if (_pval.isdigit() and "idor" in allowed_set
                                and cookies and _is_idor_param(_pname)):
                            # ── REAL two-identity BOLA (account B replays account A's object request) ──
                            # Accurate & low-FP: confirmed only when B reads A's PRIVATE object AND a
                            # control (B reading a different object) proves the endpoint is per-object.
                            if cookie_header_b and ps is not None:
                                _q_other = {k: v[0] for k, v in _qparams.items()}
                                _q_other[_pname] = str(int(_pval) + 1)
                                _url_other = _uparse.urlunparse(
                                    _parsed_url._replace(query=_uparse.urlencode(_q_other)))

                                def _mk(_cookieh, _u):
                                    def _f():
                                        import time as _t
                                        import requests as _rq
                                        _hh = {"User-Agent": UA}
                                        if _cookieh:
                                            _hh["Cookie"] = _cookieh
                                        _t0 = _t.time()
                                        _rr = _rq.get(_u, headers=_hh, timeout=12,
                                                      allow_redirects=True, verify=False)
                                        return de.Resp(status=_rr.status_code, headers=dict(_rr.headers),
                                                       body=_rr.text, elapsed=_t.time() - _t0, url=_u)
                                    return _f
                                try:
                                    _acl = await asyncio.get_running_loop().run_in_executor(
                                        _DET_POOL, functools.partial(
                                            ps.run_access_control,
                                            _mk(cookie_header, url),           # victim: A reads A's object
                                            _mk(cookie_header_b, url),         # attacker: B reads A's object
                                            None,
                                            _mk(cookie_header_b, _url_other),  # control: B reads another object
                                            url))
                                except Exception:
                                    _acl = []
                                if _acl:
                                    for _pf in _acl:
                                        _pf["vuln_type"] = "IDOR"
                                        _pf["detail"] = (f"BOLA/IDOR in '{_pname}': account B read account A's "
                                                         f"private object (id={_pval}). " + _pf.get("detail", ""))
                                        if _is_dup_finding(findings, url, "IDOR"):
                                            continue
                                        await _emit_vuln(_pf)
                                    continue   # confirmed via two identities — skip the weaker heuristic
                            _idor_val = str(int(_pval) + 1)
                            _idor_params = dict(_qparams)
                            _idor_params[_pname] = [_idor_val]
                            _idor_qs  = _uparse.urlencode({k: v[0] for k,v in _idor_params.items()})
                            _idor_url = _uparse.urlunparse(_parsed_url._replace(query=_idor_qs))
                            try:
                                _ir1 = await _req_ai(session, url)
                                _ir2 = await _req_ai(session, _idor_url)
                                # The original must be 200 with content, and the modified one 200 with substantially
                                # different content (not a minor pagination difference) — otherwise it is generic content, not IDOR.
                                _b1, _b2 = _ir1["body"].strip(), _ir2["body"].strip()
                                _len_ratio = (min(len(_b1), len(_b2)) / max(len(_b1), len(_b2))
                                              if _b1 and _b2 else 0)
                                if (_ir1["status"] == 200 and _ir2["status"] == 200
                                        and _b1 and _b2 and _b1 != _b2
                                        and _len_ratio > 0.5   # similar structure (object vs object)
                                        and not _response_blocked(_ir1.get("status"), _ir1.get("headers"), _ir1.get("body"))
                                        and not _response_blocked(_ir2.get("status"), _ir2.get("headers"), _ir2.get("body"))
                                        and not _is_dup_finding(findings, _idor_url, "IDOR")):
                                    _af = {
                                        "vuln_type": "IDOR", "severity": "high",
                                        "url": _idor_url,
                                        "detail": f"Potential IDOR in '{_pname}': authenticated id={_pval} → id={_idor_val} returns a different object — verify it belongs to another user.",
                                        "evidence": _ir2["body"][:600],
                                        "payload": f"?{_pname}={_idor_val}",
                                        "cvss": "8.0",
                                        "recommendation": "Enforce ownership checks on every object access.",
                                    }
                                    await _emit_vuln(_af)
                            except Exception:
                                pass
                # ── End programmatic pre-test ────────────────────────────────────

                # Fast-path: no injection points and not a JS/CSS file → skip AI loop entirely.
                # Pro detectors (headers, CORS, secrets) already ran above — no Ollama call needed.
                if not _has_injection and not _is_js_css:
                    await sse_out.put(
                        f"data: {json.dumps({'level':'live_url','url':url,'status':st_code,'state':'done'}, ensure_ascii=False)}\n\n"
                    )
                    continue  # finally still calls task_done()

                sys_msg = {"role":"system","content":(
                    f"You are an elite bug bounty hunter testing: {target}\n"
                    f"Tech stack: {fp_text[0][:300]}\n\n"
                    "ACCURACY RULES — Only report CONFIRMED vulns with real HTTP proof:\n"
                    "\n"
                    + (
                    # For static files (JS/CSS)
                    "URL TYPE: Static JS/CSS/Map file\n"
                    "WHAT TO TEST:\n"
                    "  - Hardcoded secrets/API keys/tokens: scan content for patterns like 'api_key=', 'secret=', 'password=', 'Bearer ', AWS/GCP key patterns\n"
                    "  - Source map exposure (.map files): if sourcemap contains real source code with credentials\n"
                    "  - Sensitive internal URLs/endpoints embedded in JS\n"
                    "WHAT NOT TO TEST: XSS, SQLi, SSRF, IDOR, Open Redirect (these are server-side vulns)\n"
                    "EVIDENCE REQUIRED: Paste the actual secret/token found in the file content\n"
                    if _is_js_css else
                    # For media — no server-side vulnerabilities here
                    "URL TYPE: Media/Font/Image file\n"
                    "RESULT: Call make_request once, check if response leaks sensitive server info in headers only\n"
                    "If headers are normal → do nothing, do NOT call report_finding\n"
                    if _is_media else
                    # For normal pages / API
                    f"URL TYPE: Web page / API endpoint\n"
                    f"Allowed vuln types (HackerOne scope — TEST AND REPORT ONLY THESE): {json.dumps(sorted(allowed_set))}\n"
                    "Any vulnerability class NOT in the allowed list above is OUT OF SCOPE — do not test or report it.\n"
                    "WHAT TO TEST based on what the URL has (restricted to the allowed list):\n"
                    "  - Has query params → test XSS, SQLi, SSTI, LFI, SSRF, Open Redirect\n"
                    "  - Has forms → test XSS, SQLi\n"
                    "  - Has an OBJECT-id param (id/user_id/order/invoice…) AND an authenticated session → test IDOR. "
                    "NEVER flag pagination/tracking params (page, limit, offset, size, utm_*, ext-ga*, gaSessionId) as IDOR — "
                    "different page content is NOT IDOR; IDOR = accessing ANOTHER user's PRIVATE data.\n"
                    "  - Has redirect param (url=, next=, return=) → test Open Redirect\n"
                    "  - No params/forms → call make_request once, check response headers/content for leaks\n"
                    ) +
                    "\nSTRICT RULES (apply to ALL URL types):\n"
                    "1. ALWAYS call make_request FIRST — NEVER report without real HTTP evidence\n"
                    "2. ONLY call report_finding when HTTP response CONFIRMS the vuln:\n"
                    "   - XSS: your exact payload appears verbatim in HTML response body\n"
                    "   - SQLi: SQL error message (MySQL/Postgres/MSSQL error text) in response body\n"
                    "   - Open Redirect: Location header contains your injected domain\n"
                    "   - SSRF: response body contains 169.254.x.x or cloud metadata content\n"
                    "   - IDOR: response contains another user's private data\n"
                    "   - Secret: actual key/token string visible in file content\n"
                    "3. If not 100% confirmed by response → do NOT call report_finding\n"
                    "4. Max 4 make_request calls total. Stay on exact target domain.\n"
                    "5. DO NOT report: missing security headers, CORS config, SSL issues, version numbers, cookies without Secure flag"
                )}
                # Gather findings the static scan already confirmed for this URL
                _url_base = url[:url.find("?") if "?" in url else len(url)]
                _url_findings = [f for f in findings
                                 if (f.get("url") or "").startswith(_url_base)]
                usr_msg = {"role":"user","content":(
                    f"Test this URL for vulnerabilities:\n\n"
                    f"URL: {url}\nHTTP status: {st_code}\n"
                    f"Query parameters: {json.dumps(prms) if prms else 'none'}\n"
                    f"Forms found: {json.dumps(forms) if forms else 'none'}\n"
                    f"Response headers: {json.dumps(p_hdrs)}\n"
                    f"Page content snippet:\n{snippet}\n"
                    + (
                        "\n--- AI PRE-SCAN ANALYSIS ---\n"
                        + "\n".join(f"• {h}" for h in (_triage.get("hints") or [])[:4])
                        + (f"\nPriority vuln types: {', '.join((_triage.get('priority_vulns') or [])[:4])}"
                           if _triage.get("priority_vulns") else "")
                        + (f"\nHigh-interest params: {', '.join((_triage.get('interesting_params') or [])[:5])}"
                           if _triage.get("interesting_params") else "")
                        + "\n"
                        if _triage else ""
                    )
                    + (
                        "\n--- STATIC SCAN ALREADY FOUND (verify / investigate further) ---\n"
                        + "\n".join(
                            f"• [{(f.get('severity') or '?').upper()}] {f.get('vuln_type','?')}: "
                            f"{(f.get('detail') or '')[:120]}"
                            for f in _url_findings[:5]
                        ) + "\n"
                        if _url_findings else ""
                    )
                    + "\nStart testing NOW."
                )}
                messages = [sys_msg, usr_msg]

                for _turn in range(5):
                    if stop_event.is_set():
                        break   # Stop pressed mid-URL → don't fire another Ollama round
                    chunks, content, tcs, finish = await _ai_call(messages, TOOLS, 1500)
                    for ev in chunks:
                        await sse_out.put(ev)

                    # ── Text-based tool call extractor ─────────────────────────
                    # llama3.1:8b sometimes writes tool calls as JSON text instead
                    # of using the proper tool_calls format. Parse them here.
                    if not tcs and content:
                        import re as _re
                        _KNOWN_TOOLS = {"make_request", "report_finding"}
                        _tool_json_pats = [
                            # {"name": "make_request", "parameters": {...}}
                            r'\{[^{}]*"name"\s*:\s*"(' + '|'.join(_KNOWN_TOOLS) + r')"[^{}]*"(?:parameters|arguments)"\s*:\s*(\{(?:[^{}]|\{[^{}]*\})*\})',
                            # {"function": {"name": "...", "arguments": {...}}}
                            r'\{[^{}]*"function"\s*:\s*\{[^{}]*"name"\s*:\s*"(' + '|'.join(_KNOWN_TOOLS) + r')"[^{}]*"arguments"\s*:\s*(\{(?:[^{}]|\{[^{}]*\})*\})',
                        ]
                        _ti = 0
                        for _pat in _tool_json_pats:
                            for _m in _re.finditer(_pat, content, _re.DOTALL):
                                try:
                                    _tc_name = _m.group(1)
                                    _tc_args = json.loads(_m.group(2))
                                    _tc_id   = f"text_call_{_ti}"
                                    tcs[_tc_id] = {
                                        "id":        _tc_id,
                                        "name":      _tc_name,
                                        "arguments": json.dumps(_tc_args),
                                    }
                                    _ti += 1
                                except Exception:
                                    pass
                        # Also try: last JSON object in content that has "name" matching a tool
                        if not tcs:
                            for _raw_blk in _re.findall(r'\{[^`]{10,1500}\}', content, _re.DOTALL):
                                try:
                                    _obj = json.loads(_raw_blk)
                                    _fn  = _obj.get("name") or (_obj.get("function") or {}).get("name")
                                    if _fn in _KNOWN_TOOLS:
                                        _args = (_obj.get("parameters") or _obj.get("arguments") or
                                                 (_obj.get("function") or {}).get("arguments") or {})
                                        _tc_id = f"text_call_{_ti}"
                                        tcs[_tc_id] = {
                                            "id":        _tc_id,
                                            "name":      _fn,
                                            "arguments": json.dumps(_args) if isinstance(_args, dict) else (_args or "{}"),
                                        }
                                        _ti += 1
                                except Exception:
                                    pass
                    # ────────────────────────────────────────────────────────────

                    asst: dict = {"role":"assistant","content": content or ""}
                    if tcs:
                        asst["tool_calls"] = [
                            {"function":{"name":tc["name"],"arguments":
                                json.loads(tc["arguments"]) if isinstance(tc["arguments"],str) else (tc["arguments"] or {})}}
                            for tc in tcs.values() if tc["name"]
                        ]
                    messages.append(asst)
                    if not tcs:
                        # ── We do not record a vuln from text alone (no HTTP evidence) — avoid false positives ──
                        # If the model claims a vuln without calling make_request, we emit an alert
                        # for manual review only, and do not add it to findings as a confirmed vuln.
                        _cu = content.upper()
                        _CONFIRMED_KW = [
                            "EXPLOITATION CONFIRMED", "VULNERABILITY CONFIRMED",
                            "PAYLOAD WAS REFLECTED", "PAYLOAD EXECUTED IN RESPONSE",
                            "SQL ERROR IN RESPONSE", "CONFIRMED XSS", "CONFIRMED SQLI",
                            "CONFIRMED SSRF", "CONFIRMED RCE", "CONFIRMED IDOR",
                            "CONFIRMED OPEN REDIRECT", "CONFIRMED LFI",
                        ]
                        _SAFE_KW = [
                            "NOT VULNERABLE", "NO VULNERABILITY", "SAFE",
                            "NOT CONFIRMED", "CANNOT CONFIRM", "NO EVIDENCE",
                            "PROTECTED", "BLOCKED", "INCONCLUSIVE",
                            "NO PARAMETERS", "STATIC FILE",
                        ]
                        _is_confirmed = any(kw in _cu for kw in _CONFIRMED_KW)
                        _is_safe      = any(kw in _cu for kw in _SAFE_KW)
                        if _is_confirmed and not _is_safe and content.strip():
                            # An alert that needs review — not a confirmed finding (no programmatic HTTP evidence)
                            await sse_out.put(
                                f"data: {json.dumps({'level':'ai','message':f'⚠️ Suspicion needs manual verification (no HTTP evidence): {url[:80]}','ai_phase':'suspect'}, ensure_ascii=False)}\n\n"
                            )
                        break

                    for tc in tcs.values():
                        if not tc["name"]: continue
                        try:
                            _raw_args = tc["arguments"]
                            args = json.loads(_raw_args) if isinstance(_raw_args, str) and _raw_args else (_raw_args if isinstance(_raw_args, dict) else {})
                        except: args = {}
                        tool_result = ""

                        if tc["name"] == "make_request":
                            rres = await _req_ai(
                                session, args.get("url", url),
                                method=args.get("method","GET").upper(),
                                params=args.get("params"), data=args.get("body"),
                                json_b=args.get("json_body"), hdrs=args.get("headers"),
                            )
                            tool_result = json.dumps({
                                "status":       rres["status"],
                                "response_url": rres["url"],
                                "headers":      {k.lower():v for k,v in list(rres["headers"].items())[:20]},
                                "body_snippet": rres["body"][:3000],
                                "error":        rres.get("error"),
                            }, ensure_ascii=False)

                            # ── Programmatic vuln confirmation ──────────────────
                            _rr_url  = args.get("url", url).lower()
                            _rr_body = rres["body"].lower()
                            _rr_hdrs = {k.lower(): v.lower() for k,v in rres["headers"].items()}
                            _rr_ct   = _rr_hdrs.get("content-type", "")
                            _rr_st   = rres["status"]
                            # Was the request blocked by a WAF/Cloudflare? Then we confirm no vuln from this response.
                            _rr_blocked = _response_blocked(_rr_st, rres["headers"], rres["body"])

                            # XSS: a generic signature (<script>...) in the body is not enough — every page has
                            # legitimate scripts. We require reflection of *the injected parameter value itself, verbatim*
                            # and unescaped, not just a generic substring (prevents false positives).
                            _XSS_SIGS = [
                                "<script", "javascript:", "onerror=", "onload=",
                                "ontoggle=", "onfocus=", "<svg", "<img src=x",
                                "<iframe", "<details", "<body onload",
                            ]
                            _xss_vals = []
                            for _vl in _uparse.parse_qs(
                                    _uparse.urlparse(args.get("url", url)).query,
                                    keep_blank_values=True).values():
                                _xss_vals.extend(_vl)
                            # The injected value that contains an actual XSS payload
                            _xss_inj = next((v for v in _xss_vals
                                             if any(s in v.lower() for s in _XSS_SIGS)), None)
                            # Verbatim unescaped reflection of the full value inside the body
                            _xss_reflected = bool(_xss_inj) and _xss_inj.lower() in _rr_body
                            if ("xss" in allowed_set and _xss_reflected and _rr_st in {200, 201}
                                    and "text/html" in _rr_ct and not _rr_blocked
                                    and not _is_dup_finding(findings, args.get("url", url), "XSS")):
                                _af = {
                                    "vuln_type": "XSS", "severity": "high",
                                    "url": args.get("url", url),
                                    "detail": f"Reflected XSS: injected value '{_xss_inj[:60]}' reflected verbatim & unescaped in HTML",
                                    "evidence": rres["body"][:600],
                                    "payload": _xss_inj,
                                    "cvss": "6.1",
                                    "recommendation": "Encode all user input before rendering in HTML (use htmlspecialchars / DOMPurify).",
                                }
                                await _emit_vuln(_af)

                            # SQLi is handled by detect_engine.detect_sqli (adaptive boolean differential
                            # with re-confirmation + error message + timing) — no separate raw check.

                            # Open Redirect: Location header points outside target
                            _loc = _rr_hdrs.get("location", "")
                            _OR_PARAMS = ["redirect", "url=", "next=", "return=", "goto=", "redir="]
                            _or_in_url = any(p in _rr_url for p in _OR_PARAMS)
                            _target_netloc = _uparse.urlparse(target).netloc.lower()
                            # Exact domain match (ignores the userinfo @ trick) to prevent substring-check bypass
                            _loc_net = _uparse.urlparse(_loc).netloc.lower().split("@")[-1].split(":")[0]
                            _loc_external = bool(_loc_net) and not (
                                _loc_net == _target_netloc or _loc_net.endswith("." + _target_netloc))
                            if ("open_redirect" in allowed_set and _or_in_url and _loc and not _loc.startswith("/")
                                    and _loc_external and not _rr_blocked
                                    and not _is_dup_finding(findings, args.get("url", url), "Open Redirect")):
                                _af = {
                                    "vuln_type": "Open Redirect", "severity": "medium",
                                    "url": args.get("url", url),
                                    "detail": f"Open Redirect → '{_loc[:80]}'",
                                    "evidence": f"Location: {_loc}",
                                    "payload": args.get("url", url),
                                    "cvss": "6.1",
                                    "recommendation": "Validate redirect destinations against an allowlist.",
                                }
                                await _emit_vuln(_af)
                            # ────────────────────────────────────────────────────

                        elif tc["name"] == "report_finding":
                            _rf_url      = args.get("url", url)
                            _rf_evidence = (args.get("evidence") or "").strip()
                            _rf_detail   = (args.get("detail") or "").strip()
                            _rf_payload  = (args.get("payload") or "").strip()
                            _rf_sev      = (args.get("severity") or "medium").lower()
                            _rf_vtype    = (args.get("vuln_type") or "Unknown").strip()

                            # ── Validate the vulnerability before accepting it ──────────────────────
                            # There must be actual HTTP evidence + a payload for interactive vulnerabilities
                            _needs_payload = _rf_vtype.upper() in {
                                "XSS","SQLI","SQL INJECTION","SSTI","LFI",
                                "SSRF","OPEN REDIRECT","IDOR","RCE","CMDI","XXE"
                            }
                            # Standard vulnerability type — rejected if it is known and out of scope
                            _rf_canon = _canon_vuln(_rf_vtype)
                            # Does the text indicate a WAF/Cloudflare block or an unconfirmed theoretical claim?
                            _rf_blocked = _finding_blocked_or_theoretical(_rf_detail, _rf_evidence)
                            # Sensitive data exposure vulns: require an actual secret, not just a mention of storage
                            _rf_is_info = any(w in _rf_vtype.lower() for w in
                                              ("sensitive", "exposure", "disclosure",
                                               "secret", "credential", "information leak"))
                            # Unknown/unrecognized type (e.g. "Unknown") and not data exposure → not an actual vuln
                            _rf_unknown_type = (_rf_canon not in _KNOWN_VULNS) and not _rf_is_info
                            # Negative result: the model mistakenly reports "no vulnerability" as a finding
                            _rf_neg_txt = (_rf_detail + " " + _rf_evidence).lower()
                            _rf_negative = any(p in _rf_neg_txt for p in (
                                "no confirmed", "no vulnerab", "not vulnerable", "no evidence",
                                "none found", "not found", "no issues", "inconclusive",
                                "appears safe", "is safe", "no security issue", "did not find",
                                "could not find", "no open redirect", "no xss", "no sqli",
                                "no sql injection", "no idor", "no ssrf", "no findings"))
                            if _rf_unknown_type:
                                tool_result = ("REJECTED: vuln_type is Unknown/unrecognized. Report ONLY a real "
                                               "confirmed class (XSS/SQLi/SSRF/LFI/IDOR/Open Redirect/SSTI/XXE/CMDi). "
                                               "If nothing is confirmed, do NOT call report_finding at all.")
                            elif _rf_negative:
                                tool_result = ("REJECTED: this is a NEGATIVE result ('no vulnerability found'). "
                                               "Do NOT call report_finding when nothing is confirmed — just move on.")
                            elif _rf_canon in _KNOWN_VULNS and _rf_canon not in allowed_set:
                                tool_result = f"REJECTED: {_rf_vtype} is not in the allowed HackerOne scope vuln types."
                            elif not _rf_evidence and not _rf_detail:
                                tool_result = "REJECTED: No evidence provided. Must include actual HTTP response content proving the vuln."
                            elif _needs_payload and not _rf_payload:
                                tool_result = "REJECTED: Missing 'payload' field. You must provide the exact payload that triggered this vulnerability."
                            elif _rf_blocked:
                                tool_result = ("REJECTED: The request appears to have been BLOCKED by a WAF/Cloudflare, "
                                               "or the finding is only theoretical ('could be exploited if...'). "
                                               "A blocked or unexecuted payload is NOT a confirmed vulnerability. "
                                               "Only report a vuln when the payload actually executes/reflects/leaks.")
                            elif _rf_canon == "xss" and _rf_payload and _rf_payload.lower() not in _rf_evidence.lower():
                                tool_result = ("REJECTED: XSS not confirmed — the exact payload must appear REFLECTED, "
                                               "verbatim and UNESCAPED, inside the 'evidence' (the HTTP response body). "
                                               "If it is HTML-entity-encoded or absent, it is not exploitable.")
                            elif _rf_is_info and not _contains_real_secret(_rf_evidence + " " + _rf_detail + " " + _rf_payload):
                                tool_result = ("REJECTED: Sensitive Data Exposure not confirmed — the 'evidence' must contain "
                                               "an ACTUAL secret (JWT, API key, AWS/Google key, bearer token, private key). "
                                               "Merely using localStorage/sessionStorage is NOT a vulnerability.")
                            elif _is_dup_finding(findings, _rf_url, _rf_vtype):
                                tool_result = "REJECTED: duplicate — this (vuln_type, URL) was already reported."
                            elif not any(part in _rf_url for part in [
                                _uparse.urlparse(target).netloc,
                                _uparse.urlparse(target).netloc.split('.',1)[-1] if '.' in _uparse.urlparse(target).netloc else ''
                            ]):
                                tool_result = f"REJECTED: {_rf_url} is out of scope."
                            else:
                                # ── Final live verification: we resend an actual HTTP request and accept only what the response confirms ──
                                # (prevents accepting model claims where it copies the payload into the evidence)
                                _t_net = _uparse.urlparse(target).netloc.lower()
                                _verified, _vreason = True, ""
                                try:
                                    if _rf_canon == "open_redirect":
                                        _loc = ""
                                        try:
                                            async with session.get(
                                                _rf_url,
                                                headers={"User-Agent": UA, **({"Cookie": cookie_header} if cookies else {})},
                                                allow_redirects=False, ssl=False,
                                                timeout=_aiohttp.ClientTimeout(total=15)) as _lr:
                                                _loc = _lr.headers.get("Location", "")
                                        except Exception:
                                            _loc = ""
                                        if not (_loc and _redirect_target_external("Location: " + _loc, _rf_payload, _t_net)):
                                            _verified, _vreason = False, (
                                                "Open Redirect NOT confirmed live — the Location header does not point to an "
                                                f"EXTERNAL domain (got: {(_loc[:120] or 'no redirect')}). A same-site returnurl "
                                                "is NOT an open redirect.")
                                    elif _rf_canon == "xss":
                                        _vr = await _req_ai(session, _rf_url)
                                        _ct = (_vr["headers"].get("Content-Type", "") or "").lower()
                                        if _response_blocked(_vr.get("status"), _vr.get("headers"), _vr.get("body")):
                                            _verified, _vreason = False, (
                                                "XSS NOT confirmed — the reported URL is behind a WAF/Cloudflare block or "
                                                "challenge page, so the payload never reached/executed on the origin.")
                                        elif not (_rf_payload and "<" in _rf_payload
                                                  and _rf_payload in _vr["body"] and "text/html" in _ct):
                                            _verified, _vreason = False, (
                                                "XSS NOT confirmed live — the exact payload is not reflected UNESCAPED in the "
                                                "HTML response of the reported URL (re-fetched it; not present/encoded).")
                                    elif _rf_canon == "sqli":
                                        _vr = await _req_ai(session, _rf_url)
                                        if _response_blocked(_vr.get("status"), _vr.get("headers"), _vr.get("body")):
                                            _verified, _vreason = False, (
                                                "SQLi NOT confirmed — the reported URL is behind a WAF/Cloudflare block page; "
                                                "the database error (if any) was not served by the origin.")
                                        elif not any(e in _vr["body"].lower() for e in _SQLI_ERR_SIGNS):
                                            _verified, _vreason = False, (
                                                "SQLi NOT confirmed live — no database error string in the response of the "
                                                "reported URL when re-fetched.")
                                    elif _rf_canon == "lfi":
                                        _vr = await _req_ai(session, _rf_url)
                                        if _response_blocked(_vr.get("status"), _vr.get("headers"), _vr.get("body")):
                                            _verified, _vreason = False, (
                                                "LFI NOT confirmed — the reported URL is behind a WAF/Cloudflare block page.")
                                        elif not any(s in _vr["body"] for s in
                                                     ("root:x:0:0", "[extensions]", "[fonts]", "daemon:x:", "16-bit app support")):
                                            _verified, _vreason = False, (
                                                "LFI NOT confirmed live — no system file content (e.g. /etc/passwd, win.ini) "
                                                "in the response.")
                                    elif _rf_canon == "ssrf":
                                        _vr = await _req_ai(session, _rf_url)
                                        if _response_blocked(_vr.get("status"), _vr.get("headers"), _vr.get("body")):
                                            _verified, _vreason = False, (
                                                "SSRF NOT confirmed — the reported URL is behind a WAF/Cloudflare block page.")
                                        elif not any(s in _vr["body"].lower() for s in
                                                     ("ami-id", "instance-id", "security-credentials",
                                                      "computemetadata", "instance-identity", "root:x:0:0")):
                                            _verified, _vreason = False, (
                                                "SSRF NOT confirmed live — no internal/cloud-metadata content in the response.")
                                    # (ssti/idor/xxe/cmdi: accepted by their fixed evidence after passing the filters above)
                                except Exception as _ve:
                                    _verified, _vreason = False, f"live verification failed: {_ve}"

                                if not _verified:
                                    tool_result = "REJECTED: " + _vreason + " Do NOT report it."
                                else:
                                    f = {
                                        "vuln_type":      _rf_vtype,
                                        "severity":       _rf_sev,
                                        "url":            _rf_url,
                                        "detail":         _rf_detail[:300],
                                        "evidence":       _rf_evidence[:600],
                                        "payload":        _rf_payload,
                                        "cvss":           (args.get("cvss_estimate") or ""),
                                        "recommendation": (args.get("recommendation") or ""),
                                    }
                                    await _emit_vuln(f)
                                    tool_result = "Finding recorded (live-verified)."
                        else:
                            tool_result = f"Unknown tool: {tc['name']}"

                        # tool_name links the result to the correct tool call (Ollama format)
                        messages.append({"role":"tool","tool_name":tc["name"],"content":tool_result})

                await sse_out.put(
                    f"data: {json.dumps({'level':'live_url','url':url,'status':st_code,'state':'done'}, ensure_ascii=False)}\n\n"
                )
                await sse_out.put(_sse("scan_done", f"✓ [{st_code}] {url[:90]}"))
                # Save progress periodically (rate-limited to every ~4s) to resume after pause/close
                await _save_scan_state("running")
            except BaseException:
                pass
            finally:
                scan_q.task_done()

    # Function-level stop event — controlled by pause/stop and the registry (independent background)
    stop_event = asyncio.Event()

    # ── Scan producer (runs in the background) — streams events through the registry, not via the HTTP response ──
    async def event_stream():
        yield ": connected\n\n"

        # Check that Ollama is running
        cfg = load_config()
        ollama_base = cfg.get("ollama_base", "http://localhost:11434")
        ollama_model = cfg.get("ollama_model", "llama3.1:8b")
        try:
            import aiohttp as _test_ah
            async with _test_ah.ClientSession() as _ts:
                async with _ts.get(f"{ollama_base}/api/tags",
                                   timeout=_test_ah.ClientTimeout(total=5)) as _tr:
                    if _tr.status != 200:
                        raise Exception("Ollama not ready")
        except Exception:
            yield _sse("error", f"Ollama is not connected — make sure it is running: ollama serve")
            yield _sse("eof", "end")
            return

        # ── Resume: announce the resume point (saved findings are shown via the subscriber snapshot) ──
        if _resume and (findings or tested):
            yield _sse("phase", f"↩️ Resuming the scan — {len(tested)} URLs previously scanned, {len(findings)} findings saved")

        scan_q:    asyncio.Queue = asyncio.Queue()  # no maxsize — crawl never waits for scan
        # sse_out is now defined at aicrawl_run scope (above) so _emit_vuln can access it.

        # Find node executable
        node_candidates = [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe",
            r"C:\nvm4w\nodejs\node.exe",
            "node",
        ]
        node_exe = next((n for n in node_candidates if os.path.isfile(n)), "node")
        crawler_js = os.path.join(BASE_DIR, "crawler.js")

        crawler_config = json.dumps({
            "target":      target,
            "maxPages":    MAX_CRAWL_URLS,
            "maxDepth":    MAX_DEPTH,
            "cookies":     cookie_header,
            "outScopeIds": out_scope_ids,
            "wordlist":    WORDLIST,
            "dirWordlist": DIR_WORDLIST,
            "skipUrls":    [],   # full re-crawl on disk-resume; AI worker skips already-tested URLs
            "concurrency": 50,
        }, ensure_ascii=False)

        scan_conn = _aiohttp.TCPConnector(ssl=False, limit=30)

        try:
            async with _aiohttp.ClientSession(connector=scan_conn) as s_sess:

                # AI fingerprint via homepage
                async def _fingerprint():
                    try:
                        async with s_sess.get(
                            target,
                            headers={"User-Agent": UA, **({"Cookie": cookie_header} if cookie_header else {})},
                            timeout=_aiohttp.ClientTimeout(total=15),
                            ssl=False,
                        ) as r:
                            hp_body = (await r.read()).decode("utf-8", errors="replace")[:3000]
                            hp_st   = r.status
                            hp_hdrs = {k.lower(): v[:80] for k, v in list(dict(r.headers).items())[:15]}
                        _, text, _, _ = await _ai_call([
                            {"role":"system","content":"You are a senior bug bounty hunter. Be concise."},
                            {"role":"user","content":(
                                f"Target: {target}\nStatus: {hp_st}\n"
                                f"Headers: {json.dumps(hp_hdrs)[:400]}\n"
                                f"HTML snippet: {hp_body[:1500]}\n\n"
                                f"Allowed: {allowed_vulns}\n\n"
                                "In 100 words max: tech stack, WAF/CDN, top 3 likely vulns."
                            )},
                        ], max_tokens=200)
                        fp_text[0] = text
                        await sse_out.put(_sse("ai", f"🧠 Stack: {text}"))
                    except Exception as e:
                        fp_text[0] = ""

                fp_task = asyncio.create_task(_fingerprint())

                # ── OAST (interactsh) for blind/out-of-band vulns — register a callback domain ──
                oast_client = [None]
                if _oast_mod is not None and os.path.isfile(_OAST_EXE):
                    try:
                        _oc = _oast_mod.OASTClient(_OAST_EXE, os.path.join(BASE_DIR, "..", "tools"))
                        _started = await asyncio.get_running_loop().run_in_executor(
                            _DET_POOL, _oc.start)
                        if _started:
                            oast_client[0] = _oc
                            scan_obj["oast"] = _oc
                            yield _sse("phase", f"📡 OAST ready (blind-vuln callbacks): *.{_oc.base_domain}")
                    except Exception:
                        oast_client[0] = None

                # ── Playwright DOM-XSS engine (one hot Chromium for the whole scan) ──
                dom_scanner = [None]
                if _browser_mod is not None and _browser_mod.available():
                    try:
                        _ds = _browser_mod.DomXSSScanner()
                        await asyncio.get_running_loop().run_in_executor(_DOM_POOL, _ds.__enter__)
                        dom_scanner[0] = _ds
                        scan_obj["dom_scanner"] = _ds
                        yield _sse("phase", "🌐 DOM-XSS engine ready (headless Chromium)")
                    except Exception:
                        dom_scanner[0] = None

                # Launch AI scan workers
                s_tasks = [asyncio.create_task(scan_worker(s_sess, scan_q, sse_out, stop_event))
                           for _ in range(N_SCAN)]
                scan_obj["workers"] = s_tasks   # so Stop/Restart can abort in-flight Ollama calls now

                yield _sse("phase", f"🚀 Node.js crawler → {target}")

                # Start the Node.js crawler subprocess
                try:
                    proc = await asyncio.create_subprocess_exec(
                        node_exe, crawler_js,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                        cwd=BASE_DIR,
                    )
                except FileNotFoundError:
                    yield _sse("error", f"node not found at {node_exe}. Please install Node.js.")
                    yield _sse("eof", "end")
                    return

                # Send config as the first stdin line; keep stdin OPEN so we can send
                # PAUSE/RESUME commands later (true in-place pause without re-crawl).
                scan_obj["proc"] = proc
                proc.stdin.write(crawler_config.encode("utf-8") + b"\n")
                await proc.stdin.drain()

                crawled_count = [0]

                # ── Passive scanner (Burp-style): flag secrets / security-headers / cookies /
                #    CORS / info-disclosure from every crawled response, no payloads sent. ──
                _PASSIVE_CVSS = {"critical": "9.1", "high": "7.5", "medium": "5.3",
                                 "low": "3.1", "info": "0.0"}

                async def _emit_passive(_url, _status, _hdrs, _body):
                    if de is None:
                        return
                    try:
                        _resp = de.Resp(status=_status or 0, headers=_hdrs or {},
                                        body=_body or "", url=_url)
                        _pres = de.passive_scan(_resp, url=_url)
                    except Exception:
                        return
                    for _r in _pres:
                        # site-wide categories dedup by signal text; secrets dedup per URL+token
                        if _r.vuln == "secret-exposure":
                            _k = "P:secret:" + _url + ":" + (_r.proof.get("match", "") or "")
                        else:
                            _k = "P:" + _r.vuln + ":" + (_r.signals[0][:80] if _r.signals else "")
                        if _k in _passive_seen:
                            continue
                        _passive_seen.add(_k)
                        _sev = _r.severity or "info"
                        _f = {
                            "vuln_type":      _r.vuln.upper().replace("-", " "),
                            "severity":       _sev,
                            "url":            _r.url or _url,
                            "detail":         (_r.signals[0] if _r.signals else _r.vuln) + " [passive]",
                            "evidence":       (_r.evidence or "")[:600],
                            "payload":        "",
                            "cvss":           _PASSIVE_CVSS.get(_sev, "0.0"),
                            "recommendation": "",
                            "passive":        True,
                        }
                        await _emit_vuln(_f)

                # Async task: read crawler stdout and feed scan_q
                async def _read_crawler():
                    async for raw_line in proc.stdout:
                        _last_crawler_ev[0] = asyncio.get_event_loop().time()  # watchdog heartbeat
                        if stop_event.is_set(): break
                        await resume_gate.wait()          # block while paused (keeps crawl state)
                        if stop_event.is_set(): break
                        line = raw_line.strip()
                        if not line: continue
                        try:
                            ev = json.loads(line)
                        except Exception:
                            continue
                        t = ev.get("type")

                        if t == "url":
                            url    = ev.get("url", "")
                            status = ev.get("status", 0)
                            forms  = ev.get("forms", [])
                            hdrs   = ev.get("headers", {})
                            body   = ev.get("body", "")
                            depth  = ev.get("depth", 0)

                            # Skip 403/404 — not real endpoints
                            if status in (403, 404):
                                continue

                            # Count/emit each URL once only (dedup across resume + crawler retries)
                            if url not in seen:
                                seen.add(url)
                                crawled_count[0] += 1
                                _state_meta["crawled"] = crawled_count[0]
                                await sse_out.put(
                                    f"data: {json.dumps({'level':'live_url','url':url,'status':status,'state':'found','method':ev.get('method','GET'),'mimeType':ev.get('mimeType',''),'contentLength':ev.get('contentLength',0),'hasParams':ev.get('hasParams',False)}, ensure_ascii=False)}\n\n"
                                )
                                # Passive pass on this response (secrets/headers/cookies/CORS/info-leak)
                                await _emit_passive(url, status, hdrs, body)

                            if status in QUEUE_SCAN_STATUSES and scan_q.qsize() < 3000:
                                params = dict(_uparse.parse_qsl(_uparse.urlparse(url).query))
                                scan_q.put_nowait({
                                    "url": url, "status": status,
                                    "headers": hdrs, "body": body,
                                    "params": params, "forms": forms, "depth": depth,
                                })

                        elif t == "form":
                            # POST/GET form discovered by the crawler → its fields are scanned (injection into the body)
                            _faction = ev.get("action", "")
                            if _faction:
                                await sse_out.put(_sse("scan", f"📝 form [{ev.get('method','GET')}] {_faction[:80]}"))
                                scan_q.put_nowait({
                                    "url": _faction, "status": 200,
                                    "headers": {}, "body": "", "params": {}, "forms": [],
                                    "depth": 0, "is_form": True, "form": {
                                        "action": _faction,
                                        "method": (ev.get("method") or "GET").upper(),
                                        "enctype": (ev.get("enctype") or "application/x-www-form-urlencoded").lower(),
                                        "inputs": ev.get("inputs") or [],
                                    },
                                })

                        elif t == "phase":
                            await sse_out.put(_sse("phase", ev.get("message", "")))

                        elif t == "probe":
                            pass  # silent — only show if actually queued for scan

                        elif t == "stats":
                            await sse_out.put(
                                f"data: {json.dumps({'level':'stats','crawled':ev.get('crawled',0),'queued':ev.get('queued',0),'active':ev.get('active',0),'rps':ev.get('rps',0),'total':ev.get('total',0),'requests':ev.get('requests',0)}, ensure_ascii=False)}\n\n"
                            )

                        elif t == "error":
                            await sse_out.put(_sse("error", ev.get("message", "")))

                        elif t == "done":
                            await sse_out.put(
                                _sse("phase", f"🕷️  Crawler finished — {ev.get('crawled',0)} pages crawled")
                            )

                # ── HTTP fallback crawler (browser-free) ─────────────────────────────────
                # Runs ONLY if the headless browser reached 0 pages — e.g. a local security
                # product blocks the browser process (ERR_BLOCKED_BY_CLIENT) or the site is
                # browser-unreachable. Plain aiohttp is not subject to that block, so we can still
                # crawl + feed the AI scan queue. Emits the SAME events as the Node crawler.
                _fb_host = (_uparse.urlparse(target).netloc or "").lstrip("www.")
                _fb_parts = _fb_host.split(".")
                _fb_dom = ".".join(_fb_parts[-2:]) if len(_fb_parts) >= 2 else _fb_host
                _FB_LINK = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'<>\s]+)', re.I)
                _FB_FORM = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
                _FB_INPUT = re.compile(r'<(?:input|textarea|select)\b([^>]*)>', re.I)
                _FB_SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".woff",
                                ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".mp3", ".webp", ".eot", ".otf")

                def _fb_attr(name, s):
                    m = re.search(r'\b' + name + r'\s*=\s*["\']?([^"\'\s>]+)', s, re.I)
                    return m.group(1) if m else ""

                def _fb_inscope(u: str) -> bool:
                    try:
                        pu = _uparse.urlparse(u)
                        h = pu.netloc.lstrip("www.")
                    except Exception:
                        return False
                    if not (h == _fb_host or h.endswith("." + _fb_dom) or h == _fb_dom):
                        return False
                    return not any(sid and (sid in h or pu.path.startswith(sid)) for sid in out_scope_ids)

                async def _http_fallback_crawl(sess):
                    from urllib.parse import urljoin as _join, urldefrag as _defrag
                    _q = [(target, 0)]
                    _local = set()
                    while _q and not stop_event.is_set():
                        await resume_gate.wait()
                        if stop_event.is_set():
                            break
                        url, depth = _q.pop(0)
                        url = _defrag(url)[0].rstrip("/")
                        if not url or url in _local:
                            continue
                        _local.add(url)
                        if len(_local) > MAX_CRAWL_URLS:
                            break
                        try:
                            r = await _req_ai(sess, url)
                        except Exception:
                            continue
                        st = r.get("status", 0)
                        body = r.get("body", "") or ""
                        hdrs = r.get("headers", {}) or {}
                        if st in (0, 403, 404):
                            continue
                        ctype = str(hdrs.get("Content-Type", hdrs.get("content-type", ""))).lower()
                        if url not in seen:
                            seen.add(url)
                            crawled_count[0] += 1
                            _state_meta["crawled"] = crawled_count[0]
                            await sse_out.put(
                                f"data: {json.dumps({'level':'live_url','url':url,'status':st,'state':'found','method':'GET','mimeType':ctype.split(';')[0],'contentLength':len(body),'hasParams':'?' in url}, ensure_ascii=False)}\n\n"
                            )
                        if st in QUEUE_SCAN_STATUSES:
                            params = dict(_uparse.parse_qsl(_uparse.urlparse(url).query))
                            scan_q.put_nowait({"url": url, "status": st, "headers": hdrs,
                                              "body": body, "params": params, "forms": [], "depth": depth})
                        # POST/GET forms -> queue as form-scan items (same shape as the Node crawler)
                        for _fm in _FB_FORM.finditer(body):
                            _fattr, _inner = _fm.group(1), _fm.group(2)
                            _av = _fb_attr("action", _fattr)
                            _action = _join(url, _av) if _av else url
                            if not _fb_inscope(_action):
                                continue
                            _method = (_fb_attr("method", _fattr) or "GET").upper()
                            _inputs = []
                            for _im in _FB_INPUT.finditer(_inner):
                                _ia = _im.group(1)
                                _nm = _fb_attr("name", _ia)
                                if not _nm:
                                    continue
                                _ty = (_fb_attr("type", _ia) or "text").lower()
                                if _ty in ("submit", "button", "image", "reset", "file"):
                                    continue
                                _vm = re.search(r'value\s*=\s*["\']([^"\']*)["\']', _ia, re.I)
                                _inputs.append({"name": _nm, "type": _ty, "value": _vm.group(1) if _vm else ""})
                            if _inputs:
                                await sse_out.put(_sse("scan", f"📝 form [{_method}] {_action[:80]}"))
                                scan_q.put_nowait({"url": _action, "status": 200, "headers": {}, "body": "",
                                                  "params": {}, "forms": [], "depth": 0, "is_form": True,
                                                  "form": {"action": _action, "method": _method,
                                                           "enctype": "application/x-www-form-urlencoded",
                                                           "inputs": _inputs}})
                        # follow links (BFS) within scope
                        if depth < MAX_DEPTH and ("html" in ctype or "<a" in body[:60000].lower()):
                            for _lm in _FB_LINK.finditer(body):
                                _ln = _defrag(_join(url, _lm.group(1)))[0].rstrip("/")
                                if not _ln.lower().startswith("http"):
                                    continue
                                if _ln.lower().endswith(_FB_SKIP_EXT) or _ln in _local:
                                    continue
                                if _fb_inscope(_ln):
                                    _q.append((_ln, depth + 1))
                    await sse_out.put(_sse("phase", f"🕷️  HTTP fallback finished — {crawled_count[0]} pages crawled"))

                _last_crawler_ev = [asyncio.get_event_loop().time()]
                crawler_reader = asyncio.create_task(_read_crawler())
                _fb_started = [False]

                # Main producer loop — independent of the page connection (continues despite refresh/close)
                try:
                    while not stop_event.is_set():
                        # Paused → idle without ending the task (state stays in memory; resume continues)
                        if not resume_gate.is_set():
                            try:
                                await asyncio.wait_for(resume_gate.wait(), timeout=5.0)
                            except asyncio.TimeoutError:
                                yield ": keepalive\n\n"
                            continue
                        # ── Watchdog: crawler silent 60s → treat as done (crash/hang guard) ──
                        if (not crawler_reader.done() and not _fb_started[0]
                                and crawled_count[0] > 0
                                and asyncio.get_event_loop().time() - _last_crawler_ev[0] > 60.0):
                            yield _sse("warn", "⚠ Crawler silent 60s — treating as complete, draining scan queue…")
                            crawler_reader.cancel()
                            await asyncio.sleep(0)  # let event loop process the cancellation
                        # Stop when: crawler done AND scan queue fully joined (all items processed)
                        if crawler_reader.done():
                            # Browser reached 0 pages (blocked/unreachable)? -> switch to the
                            # HTTP fallback crawler ONCE, then let the normal join/complete run.
                            if crawled_count[0] == 0 and not _fb_started[0]:
                                _fb_started[0] = True
                                yield _sse("phase", "🔁 Browser couldn't reach the site — switching to HTTP fallback crawler")
                                crawler_reader = asyncio.create_task(_http_fallback_crawl(s_sess))
                                continue
                            # Run scan_q.join() as background task so we keep streaming events
                            _qsize_at_join = scan_q.qsize()
                            await sse_out.put(_sse("phase", f"⏳ Draining scan queue — {_qsize_at_join} URLs remaining…"))
                            _join_task = asyncio.create_task(scan_q.join())
                            _join_deadline = datetime.now().timestamp() + max(600, _qsize_at_join * 8)  # dynamic: 8s per URL, min 10 min
                            _interrupted = False
                            _last_progress = datetime.now().timestamp()
                            while not _join_task.done() and datetime.now().timestamp() < _join_deadline:
                                if stop_event.is_set():
                                    _interrupted = True
                                    break
                                # Paused during the final drain → suspend here (don't lose the queue)
                                if not resume_gate.is_set():
                                    try:
                                        await asyncio.wait_for(resume_gate.wait(), timeout=5.0)
                                    except asyncio.TimeoutError:
                                        pass
                                    continue
                                try:
                                    ev = await asyncio.wait_for(sse_out.get(), timeout=1.0)
                                    if ev: yield ev
                                except asyncio.TimeoutError:
                                    pass
                                # Progress ping every 60s so UI knows scan is still running
                                _now = datetime.now().timestamp()
                                if _now - _last_progress >= 60.0:
                                    _last_progress = _now
                                    _rem = scan_q.qsize()
                                    yield f"data: {json.dumps({'level': 'stats', 'queued': _rem})}\n\n"
                            _join_task.cancel()
                            # Flush remaining SSE events
                            while True:
                                try:
                                    ev = await asyncio.wait_for(sse_out.get(), timeout=0.5)
                                    if ev: yield ev
                                except asyncio.TimeoutError:
                                    break
                            if not _interrupted:
                                _state_meta["completed"] = True   # the scan completed fully
                            stop_event.set()
                            break
                        try:
                            ev = await asyncio.wait_for(sse_out.get(), timeout=5.0)
                            if ev is None: break
                            yield ev
                        except asyncio.TimeoutError:
                            yield ": keepalive\n\n"
                finally:
                    stop_event.set()
                    # Kill Node.js crawler
                    try: proc.kill()
                    except Exception: pass
                    crawler_reader.cancel()
                    fp_task.cancel()
                    for t in s_tasks: t.cancel()
                    await asyncio.gather(crawler_reader, fp_task, *s_tasks, return_exceptions=True)

                    # ── OAST sweep: confirm blind (out-of-band) vulns that called back ──
                    _oc_final = oast_client[0]
                    if _oc_final is not None and _oob_pending:
                        try:
                            await asyncio.sleep(5)   # give late DNS/HTTP callbacks time to land
                        except BaseException:
                            pass
                        for _tok, _ovt, _ourl, _odetail in _oob_pending:
                            try:
                                _hit = _oc_final.had_interaction(_tok)
                            except Exception:
                                _hit = False
                            if _hit:
                                _af = {"vuln_type": _ovt, "severity": "critical", "url": _ourl,
                                       "detail": f"{_odetail} — CONFIRMED by out-of-band callback (interactsh)",
                                       "evidence": f"OAST token {_tok} received a callback",
                                       "payload": _ourl, "cvss": "9.1", "proof": {"oast": _tok},
                                        "recommendation": "Block outbound requests to user-controlled URLs; allowlist hosts server-side."}
                                await _emit_vuln(_af)
                    # tear down OAST + headless browser
                    try:
                        if _oc_final is not None: _oc_final.stop()
                    except Exception: pass
                    try:
                        if dom_scanner[0] is not None:
                            await asyncio.get_running_loop().run_in_executor(
                                _DOM_POOL, functools.partial(dom_scanner[0].__exit__, None, None, None))
                    except Exception: pass

                    # Drain remaining SSE events
                    while not sse_out.empty():
                        try:
                            ev = sse_out.get_nowait()
                            if ev: yield ev
                        except Exception:
                            break

                    # ── Burp-class Turbo Extras ──
                    if _turbo and _state_meta.get("completed"):
                        yield _sse("phase", "🔧 Running Burp-class turbo modules …")
                        _m = re.search(r"https?://([^/:?#]+)", target)
                        _host = _m.group(1) if _m else target
                        # 1) Request Smuggling detection
                        try:
                            _smug = _turbo.detect_smuggle(target, _host)
                            if _smug.get("smuggle_type"):
                                _smug["vuln_type"] = _smug.get("smuggle_type", "Request Smuggling")
                                await _emit_vuln(_smug)
                        except Exception as _e:
                            logging.warning(f"Turbo smuggle fail: {_e}")

                        # 2) Prototype Pollution on JSON endpoints (from crawl state)
                        _pp_urls = []
                        try:
                            _cs = json.loads(open(_STATE_PATH, "r", encoding="utf-8").read()) if _STATE_PATH else {}
                            for _u, _d in _cs.get("url_map", {}).items():
                                _ct = (_d.get("ex_data") or {}).get("content_type", "")
                                if "json" in _ct.lower():
                                    _pp_urls.append(_u)
                        except Exception:
                            pass
                        for _u in _pp_urls[:20]:
                            try:
                                _pp = _turbo.detect_pp_server_side(_u)
                                if _pp.get("payload"):
                                    _pp_f = {**_pp, "url": _u, "vuln_type": "Prototype Pollution"}
                                    await _emit_vuln(_pp_f)
                            except Exception as _e:
                                logging.warning(f"Turbo PP fail {_u}: {_e}")

                        # 3) Generate HTML report if findings exist
                        if findings:
                            _m = re.search(r"https?://([^/:?#]+)", target)
                            _dm = _m.group(1).lstrip("www.") if _m else ""
                            _fl = re.sub(r"[^\w.\-]", "_", _dm)
                            _td = os.path.join(_PROJ_ROOT, _fl)
                            os.makedirs(os.path.join(_td, "reports"), exist_ok=True)
                            _html_path = os.path.join(_td, "reports", f"aicrawl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
                            _html = _turbo.generate_html_report(findings, target)
                            with open(_html_path, "w", encoding="utf-8") as _hf:
                                _hf.write(_html)
                            yield _sse("phase", f"📄 HTML report → {_html_path}")

                    # ── AI Analysis of findings ──
                    if findings and _state_meta.get("completed"):
                        try:
                            yield _sse("phase", "🤖 AI analyzing findings …")
                            import ai_analyzer as _ai
                            findings[:] = _ai.analyze_all_findings(findings, batch_size=20)
                            # Generate PoC exploits for confirmed
                            import exploit_gen as _eg
                            _m = re.search(r"https?://([^/:?#]+)", target)
                            _dm = _m.group(1).lstrip("www.") if _m else ""
                            _fl = re.sub(r"[^\w.\-]", "_", _dm)
                            _td = os.path.join(_PROJ_ROOT, _fl, "reports") if _dm else ""
                            _pocs = _eg.generate_all_pocs(findings, output_dir=_td)
                            _poc_count = sum(1 for p in _pocs if p.get("type") == "html" and p.get("saved_to"))
                            if _poc_count:
                                yield _sse("phase", f"⚡ {_poc_count} PoC exploit(s) generated in {_td}")
                            yield _sse("phase", f"🎯 {sum(1 for f in findings if f.get('ai_analysis',{}).get('real'))}/{len(findings)} findings confirmed real by AI")
                        except Exception as _aie:
                            logging.warning(f"AI analysis fail: {_aie}")

                    # Save the final resume state (completed or paused)
                    _final_status = "done" if _state_meta["completed"] else "paused"
                    await _save_scan_state(_final_status, force=True)

                    # Final summary
                    live_n = len(tested)
                    vuln_n = len(findings)
                    yield _sse("phase", "═" * 50)
                    yield _sse("phase", "✅ Scan Complete" if _state_meta["completed"]
                              else "⏸ Scan Paused — progress saved, press resume to continue")
                    yield _sse("phase", f"   🕷️  Crawled:   {crawled_count[0]} URLs")
                    yield _sse("phase", f"   🎯  AI tested: {live_n}")
                    yield _sse("phase", f"   🚨  Findings:  {vuln_n}")
                    yield _sse("phase", "═" * 50)
                    for i, f in enumerate(findings, 1):
                        yield ("data: " + json.dumps(
                            {"level":"vuln","message":f"[{i}] [{f['severity'].upper()}] {f['vuln_type']} - {f['url']}","finding":f},
                            ensure_ascii=False, default=str
                        ) + "\n\n")

                    # Save findings
                    _m  = re.search(r"https?://([^/:?#]+)", target)
                    _dm = _m.group(1).lstrip("www.") if _m else ""
                    _fl = re.sub(r"[^\w.\-]", "_", _dm)
                    _td = os.path.join(_PROJ_ROOT, _fl) if _fl and findings else None
                    if _td:
                        os.makedirs(os.path.join(_td, "reports"), exist_ok=True)
                        _save_path = os.path.join(_td, "reports", f"aicrawl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                        with open(_save_path, "w", encoding="utf-8") as _sf:
                            _sf.write(json.dumps({"target": target, "findings": findings}, ensure_ascii=False))
                        yield _sse("saved", f"{vuln_n} finding(s) saved → {_save_path}")
                    yield _sse("eof", "end")

        except Exception as fatal:
            import traceback as _tb
            stop_event.set()
            tb_str = _tb.format_exc()
            logging.error(f"aicrawl fatal: {tb_str}")
            yield _sse("error", f"Fatal: {fatal} | {tb_str[:300]}")
            yield _sse("eof", "end")

    # ── Run the scan as an independent background task, then connect to it as a subscriber (continues despite page refresh/close) ──
    _existing = _scans.get(_state_host)
    if _existing and _existing.get("task") and not _existing["task"].done():
        scan_obj = _existing                       # attach to an alive scan (running or paused) — never restart
    else:
        scan_obj = {
            "host": _state_host, "target": target, "status": "running",
            "stop": stop_event, "findings": findings, "tested": tested,
            "meta": _state_meta, "subscribers": set(), "started": _time.time(),
            "resume_gate": resume_gate, "proc": None, "save": _save_scan_state,
        }
        _scans[_state_host] = scan_obj

        async def _bg_run():
            try:
                async for _ev in event_stream():
                    _subs = list(scan_obj["subscribers"])
                    if '"level": "vuln"' in _ev:
                        logging.info(f"BG_RUN fanout vuln event to {len(_subs)} subscribers")
                    for _q in _subs:
                        try: _q.put_nowait(_ev)
                        except Exception as _ex:
                            if '"level": "vuln"' in _ev:
                                logging.warning(f"BG_RUN put_nowait FAILED: {_ex}")
            except Exception as _e:
                logging.error(f"aicrawl bg error: {_e}")
            finally:
                scan_obj["status"] = "done" if _state_meta.get("completed") else "paused"
                scan_obj["ended"] = _time.time()

        scan_obj["task"] = asyncio.create_task(_bg_run())

    return StreamingResponse(
        _aicrawl_subscriber(scan_obj, request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Serve frontend (no-cache headers so browser always loads fresh JS/CSS) ────
frontend_dir = os.path.join(BASE_DIR, "..", "frontend")
if os.path.isdir(frontend_dir):

    @app.middleware("http")
    async def _no_cache_static(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path == "/" or path.endswith((".html", ".js", ".css")):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")


if __name__ == "__main__":
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("\n  +===================================+")
    print("  |       BugBîner AI  v1.0            |")
    print("  |   Gen AI-Powered Vuln Scanner      |")
    print("  |   Built by Joudi Janble                  |")
    print("  +===================================+")
    print("\n  -> http://localhost:9090\n")
    uvicorn.run("main:app", host="0.0.0.0", port=9090, reload=False, log_level="warning")
