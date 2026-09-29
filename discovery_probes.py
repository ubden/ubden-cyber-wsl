"""Passive/active L2-L3 discovery: mDNS (Bonjour), SSDP (UPnP) and LLDP.

These protocols volunteer a device's NAME and TYPE without authentication, so they name
and classify hosts that a port scan alone leaves as "unknown" (printers, Apple/AV gear,
IoT, smart TVs, media servers, and the switches themselves). Each protocol is independent
and best-effort: a failure in one never affects the scan.

- mDNS: query 224.0.0.251:5353 for service types, collect A/PTR/SRV/TXT answers per source IP.
- SSDP: M-SEARCH 239.255.255.250:1900, read the SERVER/ST/USN headers per source IP.
- LLDP: sniff ethertype 0x88cc for ~35s (switches announce every ~30s). Needs raw L2
  capture (AF_PACKET on Linux/Kali); on Windows without a raw-capture path it is skipped.
"""
from __future__ import annotations

import json
import re
import socket
import struct
import time
from pathlib import Path


def _safe(ip: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(ip))[:90]


# ---------------------------------------------------------------- SSDP (UPnP) --

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode("ascii")


def _parse_headers(text: str) -> dict:
    out = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            out[key.strip().lower()] = value.strip()
    return out


def ssdp_scan(timeout: float = 3.0, cap: int = 4096) -> dict:
    """Return {ip: {server, st, usn, location, devices:[...]}} from SSDP responders."""
    results: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
    except OSError:
        return results
    try:
        for _ in range(2):
            try:
                sock.sendto(_SSDP_MSEARCH, ("239.255.255.250", 1900))
            except OSError:
                break
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(results) < cap:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            headers = _parse_headers(data.decode("utf-8", "replace"))
            entry = results.setdefault(ip, {"server": "", "st": "", "usn": "", "location": "", "devices": []})
            if headers.get("server") and not entry["server"]:
                entry["server"] = headers["server"][:200]
            st = headers.get("st") or headers.get("nt") or ""
            if st and st not in entry["devices"]:
                entry["devices"].append(st[:120])
            entry["st"] = entry["st"] or st[:120]
            entry["usn"] = entry["usn"] or headers.get("usn", "")[:200]
            entry["location"] = entry["location"] or headers.get("location", "")[:200]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return results


# ---------------------------------------------------------------- mDNS (Bonjour) --

def _dns_query(name: str, qtype: int = 12) -> bytes:
    """Build a minimal DNS query packet (qtype 12 = PTR)."""
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    q = b"".join(struct.pack("B", len(label)) + label.encode("ascii")
                 for label in name.split(".") if label) + b"\x00"
    return header + q + struct.pack(">HH", qtype, 1)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; return (name, next_offset)."""
    labels, jumped, orig = [], False, offset
    guard = 0
    while guard < 128:
        guard += 1
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:                      # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig = offset + 2
            offset, jumped = pointer, True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (orig if jumped else offset)


def _parse_mdns(data: bytes) -> dict:
    """Parse an mDNS response into {hostnames:[], services:[], a_records:[ip]}."""
    out = {"hostnames": [], "services": [], "a_records": []}
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        offset = 12
        for _ in range(qd):                             # skip questions
            _, offset = _read_name(data, offset)
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            if rtype == 1 and rdlen == 4:               # A — owner name is the hostname
                out["a_records"].append(".".join(str(b) for b in rdata))
                if name.lower().endswith(".local") and name not in out["hostnames"]:
                    out["hostnames"].append(name[:120])
            elif rtype == 12:                           # PTR
                target, _ = _read_name(data, offset)
                if target:
                    out["services"].append(target[:120])
            elif rtype in (33, 47, 16):                 # SRV/NSEC/TXT — the owner name is useful
                if name.endswith(".local") and name not in out["hostnames"]:
                    out["hostnames"].append(name[:120])
            offset += rdlen
    except (struct.error, IndexError):
        pass
    out["hostnames"] = list(dict.fromkeys(out["hostnames"]))[:8]
    out["services"] = list(dict.fromkeys(out["services"]))[:20]
    return out


def mdns_scan(timeout: float = 3.0, cap: int = 4096) -> dict:
    """Return {ip: {hostname, services:[...]}} from mDNS responders."""
    results: dict[str, dict] = {}
    queries = [_dns_query("_services._dns-sd._udp.local"),
               _dns_query("_http._tcp.local"), _dns_query("_ipp._tcp.local"),
               _dns_query("_workstation._tcp.local"), _dns_query("_companion-link._tcp.local")]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
    except OSError:
        return results
    try:
        for q in queries:
            try:
                sock.sendto(q, ("224.0.0.251", 5353))
            except OSError:
                break
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(results) < cap:
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                break
            except OSError:
                break
            parsed = _parse_mdns(data)
            ip = addr[0]
            entry = results.setdefault(ip, {"hostname": "", "services": []})
            host = next((h for h in parsed["hostnames"] if h.lower().endswith(".local")), "")
            if host and not entry["hostname"]:
                entry["hostname"] = host[:-6] if host.lower().endswith(".local") else host
            for svc in parsed["services"]:
                if svc not in entry["services"]:
                    entry["services"].append(svc)
            entry["services"] = entry["services"][:20]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return results


# ---------------------------------------------------------------- LLDP --

def _parse_cdp(payload: bytes) -> dict:
    """Parse Cisco CDP TLVs → device_id, software, platform, port_id, mgmt_ip."""
    info: dict = {"proto": "cdp"}
    if len(payload) < 4:
        return {}
    off = 4  # skip version(1) ttl(1) checksum(2)
    try:
        while off + 4 <= len(payload):
            ttype, tlen = struct.unpack_from(">HH", payload, off)
            if tlen < 4 or off + tlen > len(payload):
                break
            value = payload[off + 4:off + tlen]
            off += tlen
            if ttype == 0x0001:
                info["device_id"] = value.decode("utf-8", "replace")[:80]
            elif ttype == 0x0003:
                info["port_id"] = value.decode("utf-8", "replace")[:60]
            elif ttype == 0x0005:
                info["software"] = value.decode("utf-8", "replace").splitlines()[0][:200] if value else ""
            elif ttype == 0x0006:
                info["platform"] = value.decode("utf-8", "replace")[:80]
            elif ttype == 0x0002 and len(value) >= 13 and value[8] == 1:  # first addr, IPv4
                info["mgmt_ip"] = ".".join(str(b) for b in value[9:13])
    except (struct.error, IndexError):
        pass
    return info if info.get("device_id") or info.get("software") else {}


def _parse_pcap_lldp(data: bytes) -> dict:
    """Extract LLDP (ethertype 0x88cc) and Cisco CDP (LLC/SNAP OUI 00000c PID 2000) neighbors
    from a classic libpcap file (what `pktmon etl2pcap` writes)."""
    out: dict = {}
    if len(data) < 24:
        return out
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        return out
    off = 24
    while off + 16 <= len(data) and len(out) < 128:
        try:
            _s, _u, incl, _o = struct.unpack_from(end + "IIII", data, off)
        except struct.error:
            break
        off += 16
        frame = data[off:off + incl]
        off += incl
        if len(frame) >= 14 and frame[12:14] == b"\x88\xcc":
            info = _parse_lldp(frame[14:])
            if info:
                out[info.get("chassis_id") or info.get("system_name") or str(len(out))] = info
        elif len(frame) >= 22 and frame[14:17] == b"\xaa\xaa\x03" and frame[17:20] == b"\x00\x00\x0c" and frame[20:22] == b"\x20\x00":
            info = _parse_cdp(frame[22:])
            if info:
                out[info.get("device_id") or str(len(out))] = info
    return out


def _lldp_windows_pktmon(seconds: float = 40.0) -> dict:
    """Capture LLDP on Windows with the built-in pktmon (no extra software; needs admin).
    Filters ethertype 0x88cc, converts the ETL to pcap, and parses it. Returns {} if pktmon
    or etl2pcap is unavailable."""
    import os
    import subprocess
    import tempfile
    from shutil import which
    if os.name != "nt" or not which("pktmon"):
        return {}
    tmp = Path(tempfile.gettempdir())
    etl = tmp / "ubden_lldp.etl"
    pcap = etl.with_suffix(".pcap")
    for path in (etl, pcap):
        try:
            path.unlink()
        except OSError:
            pass

    def pk(*args):
        try:
            subprocess.run(["pktmon", *args], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=40, check=False)
        except Exception:
            pass

    pk("filter", "remove")
    pk("filter", "add", "--ethertype", "0x88cc")        # LLDP
    pk("filter", "add", "-m", "01:00:0C:CC:CC:CC")      # Cisco CDP
    pk("start", "--capture", "--pkt-size", "0", "--file-name", str(etl), "--comp", "nics")
    time.sleep(min(max(seconds, 10), 60))
    pk("stop")
    pk("filter", "remove")
    pk("etl2pcap", str(etl))
    out = {}
    try:
        if pcap.is_file():
            out = _parse_pcap_lldp(pcap.read_bytes())
    except OSError:
        pass
    for path in (etl, pcap):
        try:
            path.unlink()
        except OSError:
            pass
    return out


def lldp_listen(seconds: float = 35.0, cap: int = 128) -> dict:
    """Sniff LLDP (ethertype 0x88cc). On Windows uses the built-in pktmon (needs admin); on
    Linux/Kali uses a raw AF_PACKET socket. Returns {} where neither is available."""
    win = _lldp_windows_pktmon(seconds)
    if win:
        return win
    if not hasattr(socket, "AF_PACKET"):
        return {}
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88CC))
        sock.settimeout(2.0)
    except (OSError, AttributeError):
        return {}
    out: dict[str, dict] = {}
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and len(out) < cap:
            try:
                frame = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            info = _parse_lldp(frame[14:]) if len(frame) > 14 else {}
            if info:
                key = info.get("chassis_id") or info.get("system_name") or str(len(out))
                out[key] = info
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _parse_lldp(payload: bytes) -> dict:
    """Parse LLDP TLVs → chassis_id, port_id, system_name, system_desc, mgmt_ip."""
    info: dict = {}
    offset = 0
    try:
        while offset + 2 <= len(payload):
            header = struct.unpack(">H", payload[offset:offset + 2])[0]
            ttype, tlen = header >> 9, header & 0x1FF
            offset += 2
            value = payload[offset:offset + tlen]
            offset += tlen
            if ttype == 0:
                break
            elif ttype == 1 and len(value) > 1:
                info["chassis_id"] = value[1:].hex() if value[0] in (4,) else value[1:].decode("utf-8", "replace")
            elif ttype == 2 and len(value) > 1:
                info["port_id"] = value[1:].decode("utf-8", "replace")[:60]
            elif ttype == 5:
                info["system_name"] = value.decode("utf-8", "replace")[:80]
            elif ttype == 6:
                info["system_desc"] = value.decode("utf-8", "replace")[:200]
            elif ttype == 8 and len(value) >= 6 and value[1] == 1:  # mgmt address, IPv4
                info["mgmt_ip"] = ".".join(str(b) for b in value[2:6])
    except (struct.error, IndexError):
        pass
    return info


# ---------------------------------------------------------------- orchestration --

def run(assets, opened, raw, events, want_lldp: bool = True) -> None:
    """Run mDNS + SSDP (+ LLDP where supported), write per-IP JSON, emit one summary event."""
    raw = Path(raw)
    in_scope = {str(ip) for ip in assets}
    named = 0
    try:
        socket.setdefaulttimeout(4)
        ssdp = ssdp_scan()
        mdns = mdns_scan()
    except Exception as exc:
        events.append({"step": "discovery_mdns_ssdp", "status": "warn", "detail": str(exc)[:200]})
        ssdp, mdns = {}, {}
    for ip, info in ssdp.items():
        if ip in in_scope:
            try:
                (raw / f"ssdp_{_safe(ip)}.json").write_text(
                    json.dumps({"target": ip, **info}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    for ip, info in mdns.items():
        if ip in in_scope:
            if info.get("hostname"):
                named += 1
            try:
                (raw / f"mdns_{_safe(ip)}.json").write_text(
                    json.dumps({"target": ip, **info}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    lldp = {}
    if want_lldp:
        try:
            lldp = lldp_listen()
        except Exception:
            lldp = {}
        if lldp:
            try:
                (raw / "lldp_neighbors.json").write_text(
                    json.dumps({"neighbors": list(lldp.values())}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    events.append({"step": "discovery_mdns_ssdp_lldp", "status": "ok",
                   "detail": f"mDNS {len(mdns)}, SSDP {len(ssdp)}, LLDP {len(lldp)} kayıt; {named} mDNS adı"})
