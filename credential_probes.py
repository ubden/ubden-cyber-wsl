"""Sınırlı, opt-in VARSAYILAN kimlik bilgisi denemesi — bellek içi, sır sızdırmaz.

Yalnız operatör açıkça etkinleştirdiğinde (meta['default_cred_test']) ve yazılı
yetkili kapsam içinde çalışır. Tespit edilen markaya göre KAMUYA AÇIK üretici
varsayılanlarının küçük bir setini, servis başına sınırlı sayıda ve tek denemeyle
(ilk başarıda dur) dener. Sözlük/kaba-kuvvet değildir; hesap kilitlenme eşiği
altında kalınmalıdır.

Denemeler bellek içindedir (hydra/medusa gibi CLI parolayı argv/dosyaya yazmaz).
Başarıda yalnız servis + kullanıcı adı kaydedilir; parola değeri görev dosyasına
veya rapora yazılmaz (kamuya açık varsayılan olsa bile — canlı geçerli kimlik
hassastır). Sonuç analist doğrulaması bekleyen yüksek önemli bir gözlemdir.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
from pathlib import Path

BASE = Path(__file__).resolve().parent
_DB_PATH = BASE / "data" / "default_credentials.json"

# Denenebilecek servisler: port → mantıksal servis adı.
TESTABLE = {23: "telnet", 21: "ftp", 22: "ssh"}
HTTP_BASIC_PORTS = {80, 443, 8080, 8443, 10443, 8006, 5000, 5001}
PER_SERVICE_CAP = 6


def load_db(path: Path = _DB_PATH) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def select_candidates(brands, service: str, db: dict, cap: int = PER_SERVICE_CAP) -> list:
    """Markaya özel + servis + genel varsayılanları sırayla, benzersiz ve sınırlı verir."""
    out, seen = [], set()
    def push(pairs):
        for pair in pairs or []:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            key = (str(pair[0]), str(pair[1]))
            if key not in seen:
                seen.add(key)
                out.append(key)
    for family in brands or []:
        push(db.get("brands", {}).get(family))
    push(db.get("service", {}).get(service))
    push(db.get("generic"))
    return out[:cap]


# --- Bellek içi bağlanıcılar (enjekte edilebilir; testlerde sahte kullanılır) ---

def _telnet_try(ip, port, username, password, timeout):
    telnet = None
    try:
        import telnetlib  # 3.13'te kaldırıldı; varsa kullan
        telnet = telnetlib.Telnet(ip, port, timeout=timeout)
        telnet.read_until(b"login:", timeout=timeout)
        telnet.write(username.encode() + b"\r\n")
        telnet.read_until(b"assword:", timeout=timeout)
        telnet.write(password.encode() + b"\r\n")
        data = telnet.read_some().decode("utf-8", "replace").lower()
        return not any(x in data for x in ("incorrect", "fail", "denied", "login:"))
    except ImportError:
        return _telnet_try_socket(ip, port, username, password, timeout)
    except Exception:
        return False
    finally:
        try:
            if telnet:
                telnet.close()
        except Exception:
            pass


def _telnet_try_socket(ip, port, username, password, timeout):
    """telnetlib yoksa ham soket ile en iyi çaba (IAC pazarlığını reddeder)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            def refuse(buf):
                out = bytearray()
                i = 0
                while i < len(buf):
                    if buf[i] == 0xFF and i + 2 < len(buf):
                        cmd, opt = buf[i + 1], buf[i + 2]
                        resp = 252 if cmd in (251, 252) else 254  # WONT/DONT
                        out += bytes([255, resp, opt])
                        i += 3
                    else:
                        i += 1
                return bytes(out)
            data = sock.recv(2048)
            neg = refuse(data)
            if neg:
                sock.sendall(neg)
            sock.sendall(username.encode() + b"\r\n")
            try:
                sock.recv(2048)
            except socket.timeout:
                pass
            sock.sendall(password.encode() + b"\r\n")
            try:
                tail = sock.recv(2048).decode("utf-8", "replace").lower()
            except socket.timeout:
                tail = ""
            if any(x in tail for x in ("incorrect", "fail", "denied", "bad", "login")):
                return False
            return any(p in tail for p in ("#", "$", ">", "welcome"))
    except Exception:
        return False


def _ftp_try(ip, port, username, password, timeout):
    try:
        import ftplib
        with ftplib.FTP() as ftp:
            ftp.connect(ip, port, timeout=timeout)
            ftp.login(username, password)
            return True
    except Exception:
        return False


def _ssh_try(ip, port, username, password, timeout):
    try:
        import paramiko
    except ImportError:
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False,
                       banner_timeout=timeout, auth_timeout=timeout)
        return True
    except Exception:
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass


def _http_basic_try(ip, port, username, password, timeout, scheme="https"):
    """Validate HTTP Basic default creds — challenge-first to avoid false positives.

    A resource is only a Basic-auth target if it returns 401 with a Basic
    'WWW-Authenticate' challenge WITHOUT credentials. Only then do supplied creds
    that turn the 401 into a 2xx/3xx count as valid. Otherwise (a plain 200 page,
    a form login, a 403, a redirect) HTTP Basic is not in use here and we return
    False — a normal 200-serving host must never be reported as default-cred.
    """
    import base64
    import ssl
    import urllib.error
    import urllib.request
    host = f"[{ip}]" if ":" in ip else ip
    url = f"{scheme}://{host}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def probe(headers):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ctx) as resp:
                return resp.status, ""
        except urllib.error.HTTPError as exc:
            challenge = exc.headers.get("WWW-Authenticate", "") if exc.headers else ""
            return exc.code, challenge
        except Exception:
            return None, ""

    base_status, challenge = probe({"User-Agent": "UBDEN-Cyber/1.0"})
    # HTTP Basic must actually be required here (401 + Basic challenge), else N/A.
    if base_status != 401 or "basic" not in (challenge or "").lower():
        return False
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    auth_status, _ = probe({"Authorization": "Basic " + token, "User-Agent": "UBDEN-Cyber/1.0"})
    return auth_status is not None and 200 <= auth_status < 400  # challenge satisfied


_DEFAULT_CONNECTORS = {"telnet": _telnet_try, "ftp": _ftp_try, "ssh": _ssh_try,
                       "http-basic": _http_basic_try}


def _tag(ip):
    return str(ip).replace(":", "_")


def _blob_for(raw: Path, ip: str) -> str:
    """raw içindeki HTTP başlıkları ve Nmap servis ürünlerinden marka metni toplar."""
    parts = []
    for path in list(raw.glob(f"headers_{_tag(ip)}_*.txt")) + list(raw.glob(f"headers_{ip}_*.txt")):
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace")[:6000])
        except OSError:
            pass
    from xml.etree import ElementTree as ET
    for path in raw.glob("nmap_*.xml"):
        try:
            tree = ET.parse(path)
        except (ET.ParseError, OSError):
            continue
        for host in tree.findall(".//host"):
            addr = host.find("address")
            if addr is None or addr.get("addr") != ip:
                continue
            for svc in host.findall("./ports/port/service"):
                parts.append(" ".join(str(svc.get(k, "")) for k in ("name", "product", "version")))
    return " ".join(parts)


def _brands_for(raw: Path, ip: str, ports: set) -> list:
    try:
        import tech_fingerprint
        return [m["family"] for m in tech_fingerprint.identify(ports, _blob_for(raw, ip))]
    except Exception:
        return []


def run(target, assets, opened: dict, raw, events, meta, db=None,
        connectors=None, brands_by_ip=None, timeout: float = 6.0) -> None:
    """Opt-in varsayılan kimlik denemesi. Kapatıysa tek 'skipped' adımı yazar."""
    raw = Path(raw)
    if not meta.get("default_cred_test"):
        events.append({"step": "default_cred", "tool": "credential-probe", "target": target,
                       "status": "skipped",
                       "detail": "Varsayılan kimlik denemesi görevde etkinleştirilmedi"})
        return
    db = db if db is not None else load_db()
    connectors = connectors or _DEFAULT_CONNECTORS
    tested = {}          # service -> count of (host,port) tested
    succeeded = {}       # service -> [ "ip:port (user)" ]
    for ip in assets:
        ports = set(opened.get(ip, []))
        if not ports:
            continue
        brands = brands_by_ip.get(ip, []) if brands_by_ip else _brands_for(raw, ip, ports)
        jobs = []
        for port in sorted(ports):
            if port in TESTABLE:
                jobs.append((TESTABLE[port], port, TESTABLE[port]))
            elif port in HTTP_BASIC_PORTS:
                scheme = "http" if port in (80, 8080, 8006) else "https"
                jobs.append(("http-basic", port, scheme))
        for service, port, hint in jobs:
            connector = connectors.get(service)
            if not connector:
                continue
            valid = None
            for username, password in select_candidates(brands, service, db):
                try:
                    if service == "http-basic":
                        ok = connector(ip, port, username, password, timeout, hint)
                    else:
                        ok = connector(ip, port, username, password, timeout)
                except TypeError:
                    ok = connector(ip, port, username, password, timeout)
                if ok:
                    valid = username
                    break
            step = f"default_cred_{service}_{_tag(ip)}_{port}"
            tested[service] = tested.get(service, 0) + 1
            if valid is not None:
                succeeded.setdefault(service, []).append(f"{ip}:{port} ({valid})")
            if valid is not None:
                evidence = {"ip": ip, "port": port, "service": service, "username": valid,
                            "brands": brands, "valid": True,
                            "note": ("Kamuya açık üretici varsayılanı geçerli göründü; parola görev "
                                     "dosyasına yazılmadı. Analist doğrulamalı ve iş etkisini kaydetmelidir.")}
                path = raw / f"cred_default_{service}_{_tag(ip)}_{port}.json"
                path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                events.append({"step": step, "tool": "credential-probe", "target": ip,
                               "status": "review",
                               "detail": f"{service} varsayılan/zayıf kimlik geçerli (kullanıcı: {valid}); parola kaydedilmedi",
                               "output": str(path.relative_to(raw.parents[2])),
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            else:
                events.append({"step": step, "tool": "credential-probe", "target": ip,
                               "status": "ok",
                               "detail": f"{service}: denenen varsayılanlarla geçerli oturum gözlenmedi"})
    if tested:
        parts = []
        for svc in sorted(tested):
            ok = succeeded.get(svc, [])
            parts.append(f"{svc}: {tested[svc]} host denendi, {len(ok)} başarılı"
                         + (f" [{', '.join(ok[:8])}]" if ok else ""))
        any_ok = any(succeeded.values())
        events.append({"step": "default_cred_summary", "tool": "credential-probe", "target": target,
                       "status": "review" if any_ok else "ok",
                       "detail": "Varsayılan/zayıf kimlik denemesi özeti — " + " · ".join(parts)})
