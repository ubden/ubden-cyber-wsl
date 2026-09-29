"""Unauthenticated identity/version fingerprinting for network-device management UIs.

A data-driven table of REAL, sourced fingerprints (firecrawl-researched): for each brand a
management port + a URL path whose unauthenticated response identifies the brand, and a regex
that extracts the software version/build where the vendor leaks it pre-auth. Read-only GET.
Covers firewalls (Sophos, WatchGuard, Palo Alto, Zyxel, DrayTek, Juniper, Cisco ASA),
routers/switches (MikroTik, Cisco IOS-XE, Aruba/HPE, Comware), wireless/SMB (UniFi, Omada,
Aruba Instant/InstantOn, Ruijie/Reyee, TP-Link, EdgeOS) and storage arrays (HPE Nimble/3PAR/
MSA/StoreOnce, Dell PowerVault/Unity/PowerStore/OneFS/Compellent/EqualLogic, generic Redfish).
iLO/iDRAC/FortiGate/Webmin/Synology/QNAP/vCenter are handled by appliance_probe / vmware_probe.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

# (brand, category, ports, scheme, path, identify_regex, version_regex|None, req_headers|None)
_FP = [
    ("Sophos SFOS", "firewall", (4444, 443), "https", "/webconsole/webpages/login.jsp",
     r"<title>Sophos</title>|uiLangToHTMLLangAttributeValueMapping", r"typography\.css\?version=([0-9a-zA-Z.]+)", None),
    ("Sophos User Portal", "firewall", (443,), "https", "/userportal/webpages/myaccount/login.jsp",
     r"<title>Sophos</title>|uiLangToHTMLLangAttributeValueMapping", r"typography\.css\?version=([0-9a-zA-Z.]+)", None),
    ("WatchGuard Fireware", "firewall", (8080, 443, 4100), "https", "/sslvpn.html",
     r"WatchGuard|Fireware", None, None),
    ("Palo Alto GlobalProtect", "firewall", (443,), "https", "/global-protect/login.esp",
     r"GlobalProtect|Global Protect", None, None),
    ("Palo Alto PAN-OS", "firewall", (443,), "https", "/php/login.php",
     r"PAN-OS|PanWeb|valStrings", None, None),
    ("Zyxel ZLD", "firewall", (443, 80, 8443), "https", "/ext-js/app/common/zld_product_spec.js",
     r"ZLDSYSPARM_PRODUCT_NAME1", r"ZLDCONFIG_CLOUD_HELP_VERSION=([^;\r\n\"]+)", None),
    ("DrayTek Vigor", "router", (443, 80, 8080, 8443), "http", "/weblogin.htm",
     r"Vigor", None, None),
    ("Juniper J-Web (Junos)", "firewall", (443, 80, 8080), "https", "/",
     r"Juniper Web Device Manager", r'var modelphpStr\s*=\s*"([^"]+)"', None),
    ("MikroTik RouterOS", "router", (80, 443), "http", "/",
     r"Mikrotik HttpProxy|\.mikrotik\.com|RouterOS", r"RouterOS v?([0-9.]+)", None),
    ("Cisco ASA/FTD WebVPN", "firewall", (443,), "https", "/+CSCOE+/logon.html",
     r"CSCOE|webvpn|SSL VPN Service|AnyConnect", None, None),
    ("Cisco IOS-XE WebUI", "switch", (443, 80, 8443), "https", "/webui/",
     r"webui-centerpanel|IOS.?XE", None, None),
    ("Cisco Meraki", "ap", (80, 443), "https", "/",
     r"Meraki", None, None),
    ("Aruba ClearPass", "server", (443,), "https", "/tips/tipsLogin.action",
     r"ClearPass Policy Manager", None, None),
    ("Aruba Instant (IAP)", "ap", (4343, 443), "https", "/swarm.cgi",
     r"swarm|Instant|Aruba", None, None),
    ("Aruba Instant On", "ap", (443,), "https", "/",
     r"Instant On", None, None),
    ("ArubaOS-CX", "switch", (443,), "https", "/rest/v1/login-sessions",
     r"login-sessions|rest/v10|ArubaOS-CX", None, None),
    ("HPE/Aruba ProCurve Switch", "switch", (80, 443), "http", "/",
     r"HP HTTP Server|ProCurve|Aruba.{0,12}Switch", None, None),
    ("HPE/H3C Comware Switch", "switch", (80, 443), "http", "/",
     r"Web user login|Comware|H3C", None, None),
    ("HPE OfficeConnect Switch", "switch", (80, 443), "http", "/",
     r"OfficeConnect", None, None),
    ("Ubiquiti UniFi", "ap", (8443, 443, 8080), "https", "/status",
     r'"server_version"|UniFi', r'"server_version"\s*:\s*"([0-9][^"]+)"', None),
    ("Ubiquiti EdgeOS/airOS", "router", (443, 80), "https", "/",
     r"EdgeOS|EdgeMAX|airOS|airMAX", None, None),
    ("TP-Link Omada", "ap", (8043, 8088, 8843, 443, 8080), "https", "/api/info",
     r'"controllerVer"|Omada', r'"controllerVer"\s*:\s*"([0-9][^"]+)"', None),
    ("TP-Link Router", "router", (80, 443), "http", "/",
     r"Router Webserver|TP-LINK|TP-Link", None, None),
    ("Ruijie/Reyee eWeb", "ap", (80, 443), "http", "/",
     r"Ruijie|Reyee|ReyeeOS", None, None),
    ("HPE Nimble/Alletra", "nas", (443, 5392), "https", "/",
     r"Nimble|Alletra", None, None),
    ("HPE 3PAR/Primera (SSMC)", "nas", (8443, 443, 8080), "https", "/",
     r"StoreServ Management Console|3PAR|Primera", None, None),
    ("HPE MSA", "nas", (443, 80), "https", "/",
     r"Storage Management Utility", None, None),
    ("HPE StoreOnce", "nas", (443,), "https", "/storeonceservices/cluster",
     r"storeonce|SecurityException|clusterInformation", None, None),
    ("Dell PowerVault ME", "nas", (443, 80), "https", "/",
     r"PowerVault Manager", None, None),
    ("Dell EMC Unity", "nas", (443,), "https", "/api/types/basicSystemInfo/instances",
     r'"model"\s*:\s*"Unity|softwareVersion', r'"softwareVersion"\s*:\s*"([0-9.]+)"', {"X-EMC-REST-CLIENT": "true"}),
    ("Dell EMC PowerStore", "nas", (443,), "https", "/api/rest/login_session",
     r"not currently logged in|PowerStore", None, None),
    ("Dell PowerScale/Isilon (OneFS)", "nas", (8080,), "https", "/",
     r"OneFS", None, None),
    ("Dell Compellent (SC)", "nas", (3033, 443), "https", "/",
     r"Storage Center|Compellent", None, None),
    ("Dell EqualLogic (PS)", "nas", (80, 443, 3002), "http", "/",
     r"Group Manager|EqualLogic", None, None),
    ("Redfish BMC/Storage", "server", (443,), "https", "/redfish/v1/",
     r'"RedfishVersion"|"@odata\.id"\s*:\s*"/redfish', r'"FirmwareVersion"\s*:\s*"([^"]+)"', None),
]


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, req_headers=None, timeout=7, limit=120000):
    headers = {"User-Agent": "UBDEN-Cyber/1.0"}
    if req_headers:
        headers.update(req_headers)
    try:
        resp = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout, context=_ctx())
        return resp.headers, resp.read(limit).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.headers, exc.read(limit).decode("utf-8", "replace")
        except Exception:
            return exc.headers, ""
    except Exception:
        return None, None


def identify(ip, ports, timeout=6, budget=20.0):
    """Return the first matching {brand, category, version, path, port} for a host, or {}.

    Fetches per (scheme,port,path) are cached, so the many '/'-based fingerprints share one
    request instead of hammering the host once per brand. Two guards keep a black-holed or
    non-responsive host from stacking one full ``timeout`` per fingerprint: a (scheme,port)
    whose first connection refuses or times out is marked dead and every remaining
    fingerprint on it is skipped (an open port that merely 404s still answers, so it is never
    dead), and a total ``budget`` in seconds caps the wall-clock spent on the whole host."""
    cache = {}
    dead = set()
    deadline = time.monotonic() + budget

    def get(scheme, port, path, req_headers):
        key = (scheme, port, path)
        if key not in cache:
            default = 443 if scheme == "https" else 80
            url = f"{scheme}://{ip}:{port}{path}" if port != default else f"{scheme}://{ip}{path}"
            cache[key] = _fetch(url, req_headers, timeout)
        return cache[key]

    for brand, category, fp_ports, scheme, path, ident, ver_re, req_headers in _FP:
        port = next((p for p in fp_ports if p in ports), None)
        if port is None:
            continue
        if (scheme, port) in dead or time.monotonic() > deadline:
            continue
        headers, body = get(scheme, port, path, req_headers)
        if headers is None and body is None:
            # Connection refused / timed out / TLS failure: no path on this (scheme,port)
            # will answer, so don't pay another `timeout` for each remaining fingerprint.
            dead.add((scheme, port))
            continue
        if body is None:
            continue
        blob = (body or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers.items() if headers else []))
        if not re.search(ident, blob, re.I):
            continue
        version = ""
        if ver_re:
            m = re.search(ver_re, blob, re.I)
            if m:
                version = m.group(1)[:60]
        return {"brand": brand, "category": category, "version": version, "path": path, "port": port}
    return {}


# Which host ports are worth an identify() attempt at all (union of all fingerprint ports).
_TRIGGER_PORTS = {p for _, _, ports, *_ in _FP for p in ports}


def run(assets, opened, raw, events) -> None:
    """Fingerprint management UIs; write netdev_<ip>.json for each identified device."""
    raw = Path(raw)
    hits = 0
    for ip in assets:
        ports = set(opened.get(ip) or [])
        if not (ports & _TRIGGER_PORTS):
            continue
        info = identify(ip, ports)
        if info:
            hits += 1
            try:
                (raw / f"netdev_{re.sub(r'[^A-Za-z0-9._-]', '_', str(ip))[:90]}.json").write_text(
                    json.dumps({"target": str(ip), **info}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    if hits:
        events.append({"step": "netdev_fingerprint", "status": "ok",
                       "detail": f"{hits} ağ cihazı markası/sürümü kimliksiz tespit edildi"})
