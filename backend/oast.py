"""Out-of-band application security testing (OAST) — the Burp-Collaborator equivalent.

Wraps the `interactsh-client` binary so the scanner can confirm BLIND vulnerabilities
(blind SSRF / XXE / OS-command / out-of-band SQLi) by observing a real DNS/HTTP callback
to a unique subdomain. NAT-safe: the public interactsh server receives the callbacks and
this client polls it outbound over HTTPS — no inbound port-forwarding needed.

Flow:
  oast = OASTClient(exe_path, workdir); oast.start()
  token, host = oast.new_payload()         # host = "<token>.<base>.oast.site"
  ...inject http://host/ into the target and trigger it...
  (later)  oast.had_interaction(token)      # True once the callback lands
"""
from __future__ import annotations

import itertools
import os
import re
import subprocess
import threading
import time

_DOMAIN_RE = re.compile(r"\b([a-z0-9]{20,}\.oast\.[a-z]+)\b", re.I)


class OASTClient:
    def __init__(self, exe_path: str, workdir: str):
        self.exe = exe_path
        self.workdir = workdir
        self.base_domain = ""
        self.proc = None
        self._jsonl = os.path.join(workdir, "oast_interactions.jsonl")
        self._counter = itertools.count(1)
        self._ok = False

    @property
    def ready(self) -> bool:
        return self._ok and bool(self.base_domain)

    def start(self, timeout: float = 20.0) -> bool:
        """Launch interactsh-client and capture the registered base domain. Returns ready."""
        if not self.exe or not os.path.isfile(self.exe):
            return False
        try:
            os.makedirs(self.workdir, exist_ok=True)
            open(self._jsonl, "w", encoding="utf-8").close()
            self.proc = subprocess.Popen(
                [self.exe, "-json", "-o", self._jsonl],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                cwd=self.workdir, text=True, bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self.proc.stderr.readline()
            except Exception:
                break
            if not line:
                if self.proc.poll() is not None:
                    break
                continue
            m = _DOMAIN_RE.search(line)
            if m:
                self.base_domain = m.group(1).lower()
                self._ok = True
                threading.Thread(target=self._drain, daemon=True).start()
                return True
        return False

    def _drain(self):
        # keep the stderr pipe flowing so the client never blocks on a full buffer
        try:
            for _ in self.proc.stderr:
                pass
        except Exception:
            pass

    def new_payload(self):
        """Return (token, full_host). token is the unique correlation id to look for later."""
        if not self.ready:
            return None, ""
        token = f"zq{next(self._counter):05d}q"
        return token, f"{token}.{self.base_domain}"

    def _raw(self) -> str:
        try:
            with open(self._jsonl, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return ""

    def had_interaction(self, token: str) -> bool:
        if not token:
            return False
        return token.lower() in self._raw().lower()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


if __name__ == "__main__":
    # quick smoke test: register a domain and print it
    here = os.path.dirname(os.path.abspath(__file__))
    exe = os.path.join(here, "..", "tools", "interactsh-client.exe")
    c = OASTClient(exe, os.path.join(here, "..", "tools"))
    print("started:", c.start(), "| base:", c.base_domain)
    print("payload:", c.new_payload())
    c.stop()
