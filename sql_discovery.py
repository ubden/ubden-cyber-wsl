"""One bounded, unicast SQL Browser query per authorized responsive IP."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import threading
import time


def parse_response(data: bytes) -> list[dict]:
    if len(data) < 4 or data[0] != 0x05 or len(data) > 8192:
        return []
    size = int.from_bytes(data[1:3], "little")
    if size > len(data) - 3:
        return []
    body = data[3:3 + size].decode("utf-8", errors="replace")
    instances = []
    for part in body.split(";;")[:16]:
        fields = part.split(";")
        values = dict(zip(fields[::2], fields[1::2]))
        name = re.sub(r"[\x00-\x1f<>|]", " ", values.get("InstanceName", ""))[:80]
        if not name:
            continue
        raw_port = values.get("tcp", "")
        port = int(raw_port) if raw_port.isdigit() and 1 <= int(raw_port) <= 65535 else None
        instances.append({"name": name, "tcp_port": port,
                          "version": re.sub(r"[\x00-\x1f<>|]", " ", values.get("Version", ""))[:50],
                          "server_name": re.sub(r"[\x00-\x1f<>|]", " ", values.get("ServerName", ""))[:80]})
    return instances


def query(ip: str, timeout=1.2, socket_factory=socket.socket):
    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket_factory(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.connect((ip, 1434))
        client.send(bytes([0x03]))
        response = client.recv(8193)
    instances = parse_response(response)
    return {"ip": ip, "status": "ok" if instances else "unrecognized_response",
            "instances": instances, "response_sha256": hashlib.sha256(response).hexdigest()}


def discover(assets, raw: Path, events: list, max_rate: int):
    """No broadcast, no retries, no password; one query per supplied address."""
    addresses = list(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in assets))
    if not addresses:
        return
    raw = Path(raw)
    lock = threading.Lock()
    next_send = [time.monotonic()]
    def one(ip):
        with lock:
            delay = next_send[0] - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            next_send[0] = time.monotonic() + 1 / max(1, min(int(max_rate), 500))
        try:
            result = query(ip)
        except (OSError, TimeoutError):
            return ip, None
        return ip, result
    found = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, int(max_rate)))) as pool:
        for ip, result in pool.map(one, addresses):
            if not result or result["status"] != "ok":
                continue
            path = raw / ("sql_browser_" + ip.replace(":", "_") + ".json")
            path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            found.append({"ip": ip, "instances": len(result["instances"]),
                          "evidence": str(path.relative_to(raw.parents[2]))})
    summary = {"step": "sql_browser", "tool": "UBDEN SQL Browser discovery",
               "status": "ok" if found else "no_response", "target_count": len(addresses),
               "responding_count": len(found),
               "detail": (f"UDP/1434 tek unicast istek: {len(found)}/{len(addresses)} yanıt; "
                          "yanıt yokluğu SQL Server bulunmadığını kanıtlamaz"),
               "evidence": found}
    summary_path = raw / "sql_browser_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary["output"] = str(summary_path.relative_to(raw.parents[2]))
    summary["sha256"] = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    events.append(summary)
