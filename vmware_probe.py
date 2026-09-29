"""Unauthenticated VMware vCenter/ESXi version disclosure via the vSphere SOAP endpoint.

The vSphere Web Services SDK answers RetrieveServiceContent without authentication and
returns about.fullName / version / build (e.g. "VMware vCenter Server 6.7.0 build-19299595").
That exact build maps directly to known CVEs, so it is a clean version-disclosure finding
and, together with the SDK reachability, positively identifies the hypervisor/vCenter that
a port scan alone only guesses at. Read-only: one SOAP call, no auth, no writes.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
from pathlib import Path

_SOAP = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
         '<soap:Body><RetrieveServiceContent xmlns="urn:vim25">'
         '<_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>'
         '</soap:Body></soap:Envelope>')


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe(ip, timeout: float = 8.0) -> dict:
    """Return {product, version, build, api_version} if the host speaks vSphere, else {}."""
    ctx = _ctx()
    base = f"https://{ip}"
    try:
        req = urllib.request.Request(base + "/sdk", data=_SOAP.encode("utf-8"),
                                     headers={"Content-Type": "text/xml; charset=utf-8",
                                              "SOAPAction": '"urn:vim25/6.7"'})
        body = urllib.request.urlopen(req, timeout=timeout, context=ctx).read().decode("utf-8", "replace")
        fields = {t: (re.search(rf"<{t}>([^<]+)</{t}>", body) or (None, ""))[1]
                  for t in ("fullName", "version", "build", "apiVersion")}
        if fields.get("fullName") or fields.get("version"):
            return {"product": (fields["fullName"] or "VMware vSphere")[:160], "version": fields["version"][:40],
                    "build": fields["build"][:40], "api_version": fields["apiVersion"][:40]}
    except Exception:
        pass
    try:
        body = urllib.request.urlopen(base + "/sdk/vimServiceVersions.xml",
                                      timeout=timeout, context=ctx).read().decode("utf-8", "replace")
        versions = re.findall(r"<version>([\d.]+)</version>", body)
        if versions:
            return {"product": "VMware vSphere (SDK)", "version": versions[0], "build": "", "api_version": versions[0]}
    except Exception:
        pass
    return {}


def run(assets, opened, raw, events) -> None:
    """Probe hosts exposing 443/8443 for a vSphere SDK version, write vmware_<ip>.json."""
    raw = Path(raw)
    hits = 0
    for ip in assets:
        ports = set(opened.get(ip) or [])
        if 443 not in ports and 8443 not in ports:
            continue
        info = probe(ip)
        if info:
            hits += 1
            try:
                (raw / f"vmware_{re.sub(r'[^A-Za-z0-9._-]', '_', str(ip))[:90]}.json").write_text(
                    json.dumps({"target": str(ip), **info}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    if hits:
        events.append({"step": "vmware_version", "status": "ok",
                       "detail": f"{hits} host vSphere/vCenter sürümünü kimliksiz ifşa etti"})
