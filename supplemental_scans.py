"""Small numeric-IP probes with explicit preconditions and one packet per host."""
from __future__ import annotations

import ipaddress


def run(target: str, assets: list[str], opened: dict[str, list[int]], raw,
        events: list[dict], command, profile: str) -> None:
    if profile not in ("network", "full"):
        return
    for index, value in enumerate(assets, 1):
        ip = str(ipaddress.ip_address(value))
        suffix = f"{index:03d}"
        result = command(f"fping_{suffix}", ["fping", "-c", "1", "-t", "1000", ip], raw, events, 5)
        result["target"] = ip
        ports = set(opened.get(ip, []))
        if 139 in ports or 445 in ports:
            if ":" not in ip:
                result = command(f"nbtscan_{suffix}", ["nbtscan", "-t", "1", ip], raw, events, 10)
                result["target"] = ip
            else:
                events.append({"step": f"nbtscan_{suffix}", "tool": "nbtscan", "target": ip,
                               "status": "skipped", "detail": "NetBIOS IPv4 gerektirir"})
        if ports:
            port = min(ports)
            result = command(f"hping3_{suffix}",
                             ["hping3", "-S", "-c", "1", "-p", str(port), ip],
                             raw, events, 8)
            result["target"] = ip
