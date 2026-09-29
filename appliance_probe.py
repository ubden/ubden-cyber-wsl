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


def _xml(tag, body):
    m = re.search(rf"<{tag}>([^<]+)</{tag}>", body)
    return m.group(1).strip() if m else ""


def ilo(ip, ports) -> dict:
    """HPE iLO: /xmldata?item=All is unauthenticated and returns iLO generation (PN),
    firmware (FWRI), server model (SPN) and serial (SBSN)."""
    for scheme in ("https", "http"):
        _, body = _fetch(f"{scheme}://{ip}/xmldata?item=All", timeout=7)
        if not body or "FWRI" not in body and "RIMP" not in body:
            continue
        fw, pn, spn, sbsn = _xml("FWRI", body), _xml("PN", body), _xml("SPN", body), _xml("SBSN", body)
        if fw or pn:
            product = pn or "HPE iLO"
            if spn:
                product += f" — {spn}"
            return {"product": product[:160], "version": fw, "server_model": spn[:80], "serial": sbsn[:40]}
    return {}


def idrac(ip, ports) -> dict:
    """Dell iDRAC: /sysmgmt/2015/bmc/info leaks the BMC firmware version unauthenticated on
    many builds; otherwise the login page carries iDRAC markers."""
    _, body = _fetch(f"https://{ip}/sysmgmt/2015/bmc/info", timeout=7)
    if body and re.search(r"idrac|FwVer|BuildVersion", body, re.I):
        m = (re.search(r'"FwVer"\s*:\s*"([^"]+)"', body)
             or re.search(r'"(?:FirmwareVersion|BuildVersion)"\s*:\s*"([^"]+)"', body))
        return {"product": "Dell iDRAC", "version": m.group(1) if m else "", "evidence": "/sysmgmt/2015/bmc/info"}
    _, body = _fetch(f"https://{ip}/", timeout=7)
    if body and re.search(r"idrac|integrated dell remote access", body, re.I):
        gen = re.search(r"(?i)idrac\s*([6-9])", body)
        return {"product": "Dell iDRAC" + (gen.group(1) if gen else ""), "version": "", "evidence": "login sayfası"}
    return {}


def synology(ip, ports) -> dict:
    """Synology DSM: SYNO.API.Info answers unauthenticated (confirms DSM); DSM version is read
    from the login page when present."""
    for port in (p for p in (5001, 5000) if p in ports or 443 in ports):
        scheme = "https" if port == 5001 else "http"
        _, body = _fetch(f"{scheme}://{ip}:{port}/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all", timeout=7)
        if not body or "SYNO.API.Auth" not in body:
            continue
        _, login = _fetch(f"{scheme}://{ip}:{port}/", timeout=6)
        m = re.search(r"(?i)DSM\s*([0-9][0-9.\-]+)", login or "")
        return {"product": "Synology DSM", "version": m.group(1) if m else "", "evidence": "SYNO.API.Info", "port": port}
    return {}


def qnap(ip, ports) -> dict:
    """QNAP QTS: /cgi-bin/authLogin.cgi returns model + firmware version/build unauthenticated."""
    for port, scheme in ((8080, "http"), (443, "https"), (80, "http")):
        if port not in ports:
            continue
        _, body = _fetch(f"{scheme}://{ip}:{port}/cgi-bin/authLogin.cgi", timeout=7)
        if not body or "QDocRoot" not in body and "QNAP" not in body.upper() and "modelName" not in body:
            continue
        ver = _xml("version", body) or (re.search(r'"version"\s*:\s*"([^"]+)"', body) or (None, ""))[1]
        build = _xml("build", body) or (re.search(r'"build"\s*:\s*"([^"]+)"', body) or (None, ""))[1]
        model = _xml("modelName", body) or _xml("internalModelName", body)
        return {"product": "QNAP QTS" + (f" ({model})" if model else ""), "version": ver, "build": build,
                "evidence": "authLogin.cgi", "port": port}
    return {}


def run(assets, opened, raw, events) -> None:
    """Probe each host for a known appliance family (BMC / NAS / firewall / mgmt) and write
    appliance_<ip>.json. Stops at the first family that matches (a host is one device)."""
    raw = Path(raw)
    hits = 0
    for ip in assets:
        ports = set(opened.get(ip) or [])
        found = {}
        if ports & {80, 443}:
            for key, fn in (("ilo", ilo), ("idrac", idrac)):
                r = fn(ip, ports)
                if r:
                    found[key] = r
                    break
        if not found and (ports & {5000, 5001, 443}):
            r = synology(ip, ports)
            if r:
                found["synology"] = r
        if not found and (ports & {8080, 443, 80}):
            r = qnap(ip, ports)
            if r:
                found["qnap"] = r
        if not found and (ports & {443, 10443, 8443, 4443}):
            r = fortigate(ip, ports)
            if r:
                found["fortigate"] = r
        if ports & {10000, 20000}:
            r = webmin(ip, ports)
            if r:
                found["webmin"] = r
        if found:
            hits += 1
            try:
                (raw / f"appliance_{re.sub(r'[^A-Za-z0-9._-]', '_', str(ip))[:90]}.json").write_text(
                    json.dumps({"target": str(ip), **found}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    if hits:
        events.append({"step": "appliance_version", "status": "ok",
                       "detail": f"{hits} host BMC/NAS/güvenlik-duvarı kimliği/sürümü ifşa etti"})
