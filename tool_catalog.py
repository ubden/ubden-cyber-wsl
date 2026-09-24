"""The historical tool list, with explicit installation and execution status.

Availability is checked on the running Kali system.  A package being installed
never implies that an assessment step used it.
"""
from __future__ import annotations

import argparse
import importlib.util
import importlib.metadata
import json
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    category: str
    mode: str
    package: str = ""
    executable: str = ""
    requirement: str = ""


def group(category: str, mode: str, names: str) -> list[Tool]:
    return [Tool(name, category, mode, name.lower(), name.lower()) for name in names.split()]


TOOLS = [
    *group("discovery", "automatic", "nslookup dig whois wafw00f hping3 tcpdump tcpflow tcptraceroute traceroute dnsenum dnsmap dnstracer ike-scan snmpcheck theHarvester"),
    *group("discovery", "conditional", "dsniff ettercap-gtk wireshark maltego"),
    *group("discovery", "legacy", "voipong dirbuster dns2tcp httprint os-prober"),
    *group("scanning", "automatic", "arping fierce fping nbtscan nmap onesixtyone p0f"),
    *group("scanning", "conditional", "lanmap2 yersinia"),
    *group("scanning", "legacy", "admsnmp amap autoscan cisco-ocs ciscos grabber portmap sipscan smap"),
    *group("vulnerability", "automatic", "nikto sipvicious sqlmap OpenVAS"),
    *group("vulnerability", "manual", "Burpsuite"),
    *group("vulnerability", "commercial", "Acunetix Netsparker nessus"),
    *group("vulnerability", "legacy", "cms-explorer mopest voiper warvox"),
    *group("credential", "automatic", "fcrackzip hashcat hashcat-utils hydra john medusa ncrack ophcrack"),
    *group("credential", "conditional", "chntpw bkhive samdump2"),
    *group("credential", "legacy", "cmospwd oclhashcat pack sipcrack"),
    *group("exploitation", "automatic", "Metasploit"),
    *group("exploitation", "conditional", "beef-ng set autopsy"),
    *group("exploitation", "legacy", "cymothoa mantra sapyto webslayer"),
    *group("wireless", "conditional", "aircrack-ng kismet cowpatty"),
    *group("wireless", "legacy", "mdk3 wepcrack wifitap"),
]

assert len(TOOLS) == 83, len(TOOLS)

ALIASES = {
    "nslookup": ("bind9-dnsutils", "nslookup"),
    "dig": ("bind9-dnsutils", "dig"),
    "theHarvester": ("theharvester", "theHarvester"),
    "ettercap-gtk": ("ettercap-graphical", "ettercap"),
    "Burpsuite": ("burpsuite", "burpsuite"),
    "OpenVAS": ("gvm", "gvm-check-setup"),
    "Metasploit": ("metasploit-framework", "msfconsole"),
    "beef-ng": ("beef-xss", "beef-xss"),
    "set": ("set", "setoolkit"),
    "sipvicious": ("sipvicious", "svmap"),
    "aircrack-ng": ("aircrack-ng", "aircrack-ng"),
}

REQUIREMENTS = {
    "tcpdump": "packet_capture", "tcpflow": "packet_capture",
    "p0f": "packet_capture", "wireshark": "gui_packet_capture",
    "dsniff": "physical_layer2", "ettercap-gtk": "physical_layer2",
    "arping": "physical_layer2", "lanmap2": "physical_layer2",
    "yersinia": "physical_layer2", "aircrack-ng": "monitor_mode",
    "kismet": "monitor_mode", "cowpatty": "authorized_capture",
    "OpenVAS": "gvm_feed_and_disk", "Metasploit": "approved_module",
    "Burpsuite": "gui_and_license", "maltego": "gui_and_license",
}


def resolved(tool: Tool) -> Tool:
    package, executable = ALIASES.get(tool.name, (tool.package, tool.executable))
    return Tool(tool.name, tool.category, tool.mode, package, executable,
                REQUIREMENTS.get(tool.name, ""))


CATALOG = tuple(map(resolved, TOOLS))


def version(package: str) -> str:
    if not package or not shutil.which("dpkg-query"):
        return ""
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True, text=True, timeout=3, check=False,
        )
        return result.stdout.strip()[:80] if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def package_source(package: str, installed_version: str, found: bool) -> str:
    if not found:
        return "not_installed"
    if not installed_version:
        return "PATH; paket kökeni bilinmiyor"
    if not shutil.which("apt-cache"):
        return "dpkg; APT kökeni doğrulanamadı"
    try:
        result = subprocess.run(["apt-cache", "policy", package], capture_output=True,
                                text=True, timeout=3, check=False)
        if "o=Kali" in result.stdout or any(
                "/kali kali-" in line for line in result.stdout.splitlines()):
            return "Kali APT"
        if "o=Debian" in result.stdout:
            return "Debian APT"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "dpkg; APT kökeni doğrulanamadı"


STEP_ALIASES = {
    "airodump-ng": "aircrack-ng", "aireplay-ng": "aircrack-ng",
    "gvm-check-setup": "OpenVAS", "msfconsole": "Metasploit",
    "svmap": "sipvicious", "theHarvester": "theHarvester",
}

CORE_TOOLS = ("curl", "sslscan", "nuclei", "snmpget", "paramiko")


def inventory(events: list[dict] | None = None) -> dict:
    events = events or []
    by_tool: dict[str, list[str]] = {}
    successful: dict[str, list[str]] = {}
    skipped: dict[str, list[str]] = {}
    for event in events:
        executable = event.get("tool", "")
        name = STEP_ALIASES.get(executable, executable)
        if executable and event.get("status") in ("ok", "error", "timeout", "interrupted", "auth_failed"):
            by_tool.setdefault(name, []).append(str(event.get("step", "")))
            if event.get("status") == "ok":
                successful.setdefault(name, []).append(str(event.get("step", "")))
        elif executable and event.get("status") in ("skipped", "blocked", "missing_tool"):
            detail=str(event.get("detail", ""))
            if detail:
                skipped.setdefault(name, []).append(detail)
    rows = []
    for tool in (*CATALOG, *(Tool(x, "core", "automatic", x, x) for x in CORE_TOOLS)):
        found = importlib.util.find_spec('paramiko') if tool.name=='paramiko' else shutil.which(tool.executable)
        steps = by_tool.get(tool.name, [])
        if steps:
            reason = "Adım günlüğünde çalıştırıldı"
        elif skipped.get(tool.name):
            reason = skipped[tool.name][0]
        elif not found:
            reason = "Kali paket kaynağında veya sistem PATH içinde bulunamadı"
        elif tool.mode == "legacy":
            reason = "Tarihî araç; güncel paket ve güvenli otomatik adaptör doğrulanmadı"
        elif tool.mode == "commercial":
            reason = "Ticari lisans ve göreve özgü erişim doğrulanmadı"
        elif tool.mode in ("manual", "conditional"):
            reason = "Arayüz, donanım veya ayrı kanıt ön koşulu bu görevde karşılanmadı"
        else:
            reason = "Bu görevde güvenli kapsam adaptörü veya uygun servis ön koşulu yok"
        if tool.name == 'paramiko' and found:
            try:
                package_version = importlib.metadata.version('paramiko')
            except importlib.metadata.PackageNotFoundError:
                package_version = ''
        else:
            package_version = version(tool.package) if found else ''
        rows.append({
            "name": tool.name,
            "category": tool.category,
            "mode": tool.mode,
            "package": tool.package,
            "executable": tool.executable,
            "installed": bool(found),
            "version": package_version,
            "package_source": "Python venv / pip" if tool.name=='paramiko' and found else
                              package_source(tool.package, package_version, bool(found)),
            "requirement": tool.requirement,
            "executed": bool(steps),
            "steps": steps,
            "successful_steps": successful.get(tool.name, []),
            "reason": reason,
            "status": "executed" if steps else
                      "installed_not_run" if found else "not_installed",
        })
    return {"schema": 2, "catalog_count": len(CATALOG), "tools": rows}


def install_candidates() -> list[str]:
    return sorted({tool.package for tool in CATALOG
                   if tool.mode in ("automatic", "conditional") and tool.package})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-candidates", action="store_true")
    args = parser.parse_args()
    if args.install_candidates:
        print("\n".join(install_candidates()))
    else:
        print(json.dumps(inventory(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
