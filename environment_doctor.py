"""Read-only preflight for a single UBDEN engagement; sends no target packets."""
from __future__ import annotations

import ipaddress
import os
import platform
from pathlib import Path
import shutil
import subprocess


def _check(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def inspect(meta: dict, run_dir: Path) -> dict:
    checks = []
    targets = meta.get("targets") or []
    checks.append(_check("Yetkili hedefler", "ok" if targets else "blocked",
                         f"{len(targets)} açık hedef"))
    checks.append(_check("Yetki referansı", "ok" if meta.get("authorization_reference") else "blocked",
                         "Görev kaydında var" if meta.get("authorization_reference") else "Eksik"))
    checks.append(_check("Kali/Linux çekirdeği", "ok" if os.name != "nt" else "blocked",
                         platform.release() if os.name != "nt" else "Linux ortamı gerekli"))
    snapshot = meta.get("host_snapshot") or {}
    if snapshot.get("status") == "ok":
        selected = set(meta.get("selected_interfaces") or [])
        available = set()
        for item in snapshot.get("adapters", []):
            if item.get("status") != "Up":
                continue
            for address in item.get("addresses", []):
                try:
                    ip = ipaddress.ip_address(address["address"])
                    if not (ip.is_link_local or ip.is_loopback or ip.is_unspecified):
                        available.add(item.get("index"))
                except (KeyError, TypeError, ValueError):
                    continue
        checks.append(_check("Windows adaptör seçimi",
                             "ok" if selected and selected <= available else "blocked",
                             f"Seçili: {sorted(selected)}; kullanılabilir: {sorted(available)}"))
    else:
        checks.append(_check("Windows adaptör seçimi", "skipped", "Windows köprüsü kullanılmıyor"))
    frozen = meta.get("frozen_dns") or {}
    missing = [target for target in targets if not _numeric(target) and not frozen.get(target)]
    checks.append(_check("Hedef DNS çözümlemesi", "warning" if missing else "ok",
                         "Çözümlenemeyen: " + ", ".join(missing[:10]) if missing else "Adlı hedefler sabitlendi"))
    try:
        free = shutil.disk_usage(run_dir).free
        checks.append(_check("Rapor diski", "ok" if free >= 500_000_000 else "blocked",
                             f"Boş alan: {free // 1_000_000} MB"))
    except OSError:
        checks.append(_check("Rapor diski", "blocked", "Boş alan okunamadı"))
    profile = meta.get("profile", "network")
    required_tools = ["nmap"]
    if profile != "network":
        required_tools += ["curl", "sslscan"]
    if profile in ("external", "full"):
        required_tools += ["dig", "whois"]
    for tool in required_tools:
        installed = shutil.which(tool)
        checks.append(_check(f"Araç: {tool}", "ok" if installed else "blocked",
                             installed or "Kurulu değil"))
    ad = meta.get("ad") or {}
    if ad.get("mode") == "supplied":
        fields = ("domain", "dc", "account")
        missing_ad = [field for field in fields if not ad.get(field)]
        checks.append(_check("AD test bağlamı", "blocked" if missing_ad else "ok",
                             "Eksik: " + ", ".join(missing_ad) if missing_ad else "Alan, DC ve test hesabı tanımlı"))
    elif ad.get("mode") == "joined":
        joined = bool(snapshot.get("part_of_domain"))
        checks.append(_check("AD Windows oturumu", "ok" if joined else "blocked",
                             "Etki alanına bağlı" if joined else "Etki alanı oturumu doğrulanmadı"))
    else:
        checks.append(_check("AD modülü", "skipped", "Görevde seçilmedi"))
    if os.name != "nt":
        try:
            route = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=3, check=False)
            has_route = route.returncode == 0 and any(
                line.startswith("default ") for line in route.stdout.splitlines())
        except (OSError, subprocess.TimeoutExpired):
            has_route = False
        checks.append(_check("Kali IPv4 varsayılan rota", "ok" if has_route else "warning",
                             "Mevcut" if has_route else "Yok veya okunamadı; hedef rotaları ayrıca denetlenecek"))
    return {"schema": 1, "status": "blocked" if any(c["status"] == "blocked" for c in checks)
            else "warning" if any(c["status"] == "warning" for c in checks) else "ok",
            "checks": checks, "note": "Ön kontrol hedefe paket göndermez; hedef erişimi sonraki rota ve servis adımlarında doğrulanır."}


def _numeric(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False
