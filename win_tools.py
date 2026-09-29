"""Windows tool catalogue + installer for UBDEN uPenetrator.

Goal: bring the FULL tool set to Windows reliably, preferring direct GitHub-release
binary downloads over winget (which is often absent or fails). Every tool the probe
suite runs is either (a) downloaded here (nuclei, sslscan), (b) pip-installed
(wafw00f, fierce, theHarvester, puresnmp), (c) shipped by Windows (curl, nslookup,
tracert), or (d) covered by an Nmap NSE equivalent. Genuinely unavailable tools are
reported, never silently skipped.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# Persistent tools dir (survives venv rebuilds); binaries land in per-tool subdirs.
TOOLS_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "UBDEN" / "tools"

# pip-installable CLI + library tools (land in the venv's Scripts/site-packages).
PIP_TOOLS = [
    ("wafw00f", "wafw00f", "WAF/ürün tespiti (web)"),
    ("fierce", "fierce", "Alt alan keşfi"),
    ("theHarvester", "theHarvester", "Pasif OSINT (alt alan/e-posta)"),
    ("puresnmp", "puresnmp<2", "Saf-Python SNMP istemcisi (snmpget yerine)"),
]

# GitHub-release single-binary tools. asset: regex over release asset names.
DOWNLOAD_TOOLS = {
    "nuclei": {"repo": "projectdiscovery/nuclei",
               "asset": r"nuclei_.*_windows_amd64\.zip", "bin": "nuclei.exe"},
    "sslscan": {"repo": "rbsec/sslscan",
                "asset": r"^sslscan.*\.zip$", "bin": "sslscan.exe"},
}

# Full catalogue: exe -> how it is provided on Windows and its NSE/pure fallback.
# 'source': download | pip | builtin | nse
CATALOG = [
    {"exe": "nmap", "source": "download", "purpose": "Port/servis + ARP/MAC keşfi (Npcap)",
     "fallback": "", "note": "winget: Insecure.Nmap (Npcap için)"},
    {"exe": "nuclei", "source": "download", "purpose": "Şablon tabanlı zafiyet taraması", "fallback": ""},
    {"exe": "sslscan", "source": "download", "purpose": "TLS şifre paketi denetimi",
     "fallback": "nse: ssl-enum-ciphers"},
    {"exe": "curl", "source": "builtin", "purpose": "HTTP başlık/OPTIONS yoklaması", "fallback": ""},
    {"exe": "nslookup", "source": "builtin", "purpose": "DNS sorgusu", "fallback": ""},
    {"exe": "tracert", "source": "builtin", "purpose": "Yol izleme", "fallback": ""},
    {"exe": "traceroute", "source": "nse", "purpose": "Yol izleme (Linux adı)", "fallback": "tracert (yerleşik)"},
    {"exe": "wafw00f", "source": "pip", "purpose": "WAF tespiti", "fallback": ""},
    {"exe": "fierce", "source": "pip", "purpose": "Alt alan keşfi", "fallback": ""},
    {"exe": "theHarvester", "source": "pip", "purpose": "Pasif OSINT", "fallback": ""},
    {"exe": "snmpget", "source": "pip", "purpose": "SNMP sysDescr (puresnmp)",
     "fallback": "puresnmp (saf-Python) / nse: snmp-info"},
    {"exe": "whois", "source": "nse", "purpose": "WHOIS kaydı", "fallback": "nse: whois-ip / nslookup"},
    {"exe": "nikto", "source": "nse", "purpose": "Web sunucu denetimi",
     "fallback": "nse: http-enum,http-headers,http-title,http-security-headers"},
    {"exe": "smbclient", "source": "nse", "purpose": "SMB paylaşım listesi",
     "fallback": "nse: smb-os-discovery,smb-enum-shares"},
    {"exe": "dnsenum", "source": "pip", "purpose": "DNS/alt alan keşfi", "fallback": "fierce (pip) / nse: dns-brute"},
    {"exe": "dig", "source": "nse", "purpose": "Ayrıntılı DNS kayıtları", "fallback": "nslookup (yerleşik)"},
    {"exe": "fping", "source": "nse", "purpose": "Toplu ICMP", "fallback": "nmap -sn (ARP + MAC)"},
    {"exe": "nbtscan", "source": "nse", "purpose": "NetBIOS tarama", "fallback": "yerleşik NBSTAT probu / nbtstat"},
    {"exe": "ike-scan", "source": "nse", "purpose": "IKE/VPN yoklaması", "fallback": "nse: ike-version"},
]


def venv_scripts_dir() -> Path:
    return Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")


def _tool_bin_dirs() -> list:
    dirs = [TOOLS_DIR]
    if TOOLS_DIR.exists():
        dirs += [p for p in TOOLS_DIR.iterdir() if p.is_dir()]
    return [str(d) for d in dirs]


def ensure_path() -> None:
    """Prepend venv Scripts, the download tools dir (+subdirs), and Nmap onto PATH
    for this process so shutil.which() finds pip/downloaded/winget tools."""
    extra = [str(venv_scripts_dir())] + _tool_bin_dirs() + [
        r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep)
    for directory in extra:
        if directory and directory not in parts and Path(directory).exists():
            current = directory + os.pathsep + current
    os.environ["PATH"] = current


def _http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "UBDEN-uPenetrator/1.0",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def download_release(name: str) -> dict:
    """Download a single-binary tool from its latest GitHub release into TOOLS_DIR/<name>.

    Best-effort: returns {'tool','ok','detail'}; never raises (network/AV may block).
    """
    spec = DOWNLOAD_TOOLS.get(name)
    if not spec:
        return {"tool": name, "ok": False, "detail": "kayıtlı değil"}
    dest = TOOLS_DIR / name
    if (dest / spec["bin"]).is_file():
        return {"tool": name, "ok": True, "detail": "zaten kurulu"}
    try:
        meta = json.loads(_http_get(f"https://api.github.com/repos/{spec['repo']}/releases/latest"))
        assets = meta.get("assets", [])
        pattern = re.compile(spec["asset"], re.I)
        chosen = next((a for a in assets if pattern.search(a.get("name", ""))), None)
        if not chosen:
            return {"tool": name, "ok": False, "detail": "uygun Windows varlığı bulunamadı"}
        blob = _http_get(chosen["browser_download_url"], timeout=180)
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for member in zf.namelist():
                if member.endswith("/") or "\\" in member or member.startswith("/") or ".." in member:
                    continue
                target = dest / Path(member).name
                with zf.open(member) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        ok = (dest / spec["bin"]).is_file()
        return {"tool": name, "ok": ok,
                "detail": chosen.get("name", "") if ok else "arşivde beklenen ikili yok"}
    except Exception as exc:  # network/zip/AV — non-fatal
        return {"tool": name, "ok": False, "detail": f"{type(exc).__name__}: {exc}"}


def install_pip(python: str | None = None) -> list:
    python = python or sys.executable
    results = []
    for _, package, _ in PIP_TOOLS:
        try:
            proc = subprocess.run([python, "-m", "pip", "install", "--disable-pip-version-check", package],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=600, check=False)
            results.append({"package": package, "ok": proc.returncode == 0,
                            "detail": (proc.stderr or "").strip()[-200:] if proc.returncode else ""})
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"package": package, "ok": False, "detail": str(exc)})
    return results


def install_all() -> dict:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    pip = install_pip()
    downloads = [download_release(name) for name in DOWNLOAD_TOOLS]
    # Refresh nuclei templates once, best-effort.
    ensure_path()
    if shutil.which("nuclei"):
        try:
            subprocess.run(["nuclei", "-update-templates"], capture_output=True, timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {"pip": pip, "downloads": downloads}


def report() -> dict:
    ensure_path()
    rows = []
    for tool in CATALOG:
        rows.append({"exe": tool["exe"], "present": bool(shutil.which(tool["exe"])),
                     "source": tool["source"], "purpose": tool["purpose"],
                     "fallback": tool["fallback"]})
    present = sum(1 for r in rows if r["present"])
    return {"schema": 1, "present_count": present, "total": len(rows),
            "tools_dir": str(TOOLS_DIR), "tools": rows}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    action = argv[0] if argv else "report"
    if action == "install":
        print(json.dumps(install_all(), ensure_ascii=False))
    else:
        print(json.dumps(report(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
