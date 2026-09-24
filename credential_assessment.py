"""At most two in-memory SSH password checks for one supplied test account."""
from __future__ import annotations

import ipaddress
import base64
import hashlib
import socket
import time


def run_ssh(spec: dict, candidates: list[str], events: list[dict]) -> None:
    address = str(ipaddress.ip_address(spec["target_ip"]))
    username = str(spec["username"])
    expected = str(spec.get("host_key_sha256", ""))
    port = int(spec.get("port", 22))
    if port != 22 or not username or len(candidates) not in (1, 2) or \
            not expected.startswith('SHA256:') or len(expected) > 80:
        raise ValueError("SSH test hesabi veya iki deneme siniri gecersiz")
    try:
        import paramiko
    except ImportError:
        events.append({"step": "ssh_password_preflight", "tool": "paramiko", "target": address,
                       "status": "missing_tool", "detail": "paramiko kurulu degil"})
        return
    failed = 0
    for attempt, password in enumerate(candidates, 1):
        try:
            with socket.create_connection((address, port), timeout=3):
                pass
        except (OSError, TimeoutError):
            events.append({"step": f"ssh_password_{attempt}", "tool": "paramiko",
                           "target": address, "status": "blocked",
                           "detail": "SSH servis saglik yoklamasi basarisiz; kalan denemeler durdu"})
            break
        transport = None
        connection = None
        started = time.monotonic()
        try:
            connection = socket.create_connection((address, port), timeout=5)
            transport = paramiko.Transport(connection)
            transport.banner_timeout = 5
            transport.auth_timeout = 5
            transport.start_client(timeout=5)
            key = transport.get_remote_server_key()
            observed = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode('ascii').rstrip('=')
            if observed != expected:
                events.append({"step": f"ssh_password_{attempt}", "tool": "paramiko",
                               "target": address, "status": "blocked",
                               "detail": "SSH sunucu anahtari beklenen parmak iziyle eslesmedi"})
                break
            transport.auth_password(username, password, fallback=False)
            if not transport.is_authenticated():
                raise paramiko.AuthenticationException("authentication failed")
        except paramiko.AuthenticationException as exc:
            failed += 1
            elapsed = time.monotonic() - started
            text = str(exc).lower()
            locked = any(word in text for word in ("locked", "disabled", "too many", "rate limit"))
            events.append({"step": f"ssh_password_{attempt}", "tool": "paramiko",
                           "target": address, "status": "blocked" if locked else "auth_failed",
                           "seconds": round(elapsed, 2),
                           "detail": "Test hesabinda kilit/gecikme belirtisi" if locked or elapsed > 5 else
                                     "Test hesabi kimlik dogrulamasi basarisiz"})
            if locked or elapsed > 5 or failed >= 2:
                break
        except Exception as exc:
            events.append({"step": f"ssh_password_{attempt}", "tool": "paramiko",
                           "target": address, "status": "blocked",
                           "detail": f"SSH hatasi: {type(exc).__name__}; kalan denemeler durdu"})
            break
        else:
            events.append({"step": f"ssh_password_{attempt}", "tool": "paramiko",
                           "target": address, "status": "ok",
                           "seconds": round(time.monotonic() - started, 2),
                           "detail": "Saglanan test hesabi dogrulandi; ek deneme yapilmadi"})
            break
        finally:
            if transport is not None:
                transport.close()
            elif connection is not None:
                connection.close()
