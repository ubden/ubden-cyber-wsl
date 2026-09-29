"""Unauthenticated appliance identity/version disclosure: FortiGate and Webmin.

- Webmin: its web server MiniServ returns `Server: MiniServ/<ver>` even on the 401 login
  page, which fingerprints the install (port 10000, Usermin on 20000). Read-only banner grab.
- FortiGate: the admin/SSL-VPN login page carries FortiGate/FortiOS markers (fgt_lang,
  /remote/login, logindisclaimer, FortiClient). FortiOS usually hides the exact build, so
  this positively identifies the firewall and leaks a version only when the page does.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=8, method="GET", limit=200000):
    """Return (headers, body) following an HTTPError so we still read 401/403 pages."""
    try:
        req = urllib.request.Request(url, method=method)
        resp = urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        return resp.headers, ("" if method == "HEAD" else resp.read(limit).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.headers, ("" if method == "HEAD" else exc.read(limit).decode("utf-8", "replace"))
        except Exception:
            return exc.headers, ""
    except Exception:
        return None, None


def webmin(ip, ports) -> dict:
    """Fingerprint Webmin/Usermin via the MiniServ Server header."""
    for port in (p for p in (10000, 20000) if p in ports):
        for scheme in ("https", "http"):
            headers, _ = _fetch(f"{scheme}://{ip}:{port}/", method="HEAD")
            server = (headers.get("Server", "") if headers else "")
            m = re.search(r"MiniServ/([\d.]+)", server)
            if m:
                product = "Usermin" if port == 20000 else "Webmin"
                return {"product": f"{product} (MiniServ)", "version": m.group(1),
                        "port": port, "server": server[:120]}
    return {}


_FGT_MARKERS = re.compile(r"fortigate|fortios|/remote/login|fgt_lang|logindisclaimer|forticlient|fortinet", re.I)
_FGT_VER = re.compile(r"(?i)fortios[ _v-]*([0-9]+\.[0-9]+\.[0-9]+)")


def fortigate(ip, ports) -> dict:
    """Detect a FortiGate admin/SSL-VPN portal and leak a version if the page carries one."""
    for port in (p for p in (443, 10443, 8443, 4443) if p in ports) or (443,):
        for path in ("/", "/login", "/remote/login"):
            headers, body = _fetch(f"https://{ip}:{port}{path}")
            if not body:
                continue
            if not _FGT_MARKERS.search(body):
                continue
            out = {"product": "Fortinet FortiGate", "version": "", "port": port,
                   "evidence": "login sayfası işaretleri (FortiOS)"}
            m = _FGT_VER.search(body)
            if m:
                out["version"] = m.group(1)
            return out
    return {}


def run(assets, opened, raw, events) -> None:
    """Probe hosts for FortiGate and Webmin; write appliance_<ip>.json per identified host."""
    raw = Path(raw)
    hits = 0
    for ip in assets:
        ports = set(opened.get(ip) or [])
        found = {}
        if ports & {10000, 20000}:
            found.update({"webmin": webmin(ip, ports)})
        if ports & {443, 10443, 8443, 4443}:
            fg = fortigate(ip, ports)
            if fg:
                found["fortigate"] = fg
        found = {k: v for k, v in found.items() if v}
        if found:
            hits += 1
            try:
                (raw / f"appliance_{re.sub(r'[^A-Za-z0-9._-]', '_', str(ip))[:90]}.json").write_text(
                    json.dumps({"target": str(ip), **found}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    if hits:
        events.append({"step": "appliance_version", "status": "ok",
                       "detail": f"{hits} host FortiGate/Webmin kimliği/sürümü ifşa etti"})
