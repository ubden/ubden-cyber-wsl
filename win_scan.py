"""Windows-native scan orchestrator for UBDEN uPenetrator (Faz 1 MVP).

Portable analogue of ``wizard.scan_target``/``wizard.run`` that runs directly on
Windows (with Npcap-backed Nmap) instead of inside Kali WSL. It reuses the exact
run-directory contract and the shared report engine, so the produced report is
identical — but because Nmap runs on the physical adapter with ARP enabled, the
on-link MAC address and vendor/device identification are actually populated
(the capability that WSL NAT could never provide).

Reused unchanged from the existing codebase:
  * wizard.freeze_scope / route_guard / resolve / excluded / is_network / is_ip /
    open_tcp_ports / safe_filename  (scope + safety gating)
  * device_inventory.build_inventory (MAC/vendor/category/role)
  * report_v2.main                  (PDF + HTML + correlation/osint/tech/cve)
New here:
  * win_proc.run  (Windows-safe process runner; no POSIX killpg)
  * ARP-enabled Nmap invocation (no --disable-arp-ping, no -Pn on-link)
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import wizard  # imports cleanly on Windows (pwd is guarded); reuse pure helpers
import device_inventory
import win_proc
try:
    import win_tools
except Exception:
    win_tools = None
try:
    import ai_analyst
except Exception:
    ai_analyst = None
try:
    import ai_operator
except Exception:
    ai_operator = None
try:
    import wifi_scan
except Exception:
    wifi_scan = None
try:
    import power_manager
except Exception:
    power_manager = None
# report_v2 is invoked as a subprocess (its main() reads sys.argv), never imported
# here, so win_scan stays importable for tests even without reportlab installed.

try:
    import host_bridge
except Exception:  # bridge is optional; scanning still works without it
    host_bridge = None
try:
    import ieee_registry
except Exception:
    ieee_registry = None

ROOT = Path(__file__).resolve().parent
VERSION = getattr(wizard, "VERSION", "5.0.0")
PROFILES = ("external", "web", "network", "full")
MAX_LANES = 6          # hard ceiling on concurrent target lanes
DEFAULT_LANES = 3      # default when the form does not specify


def is_admin() -> bool:
    """True when we can send raw packets (SYN scan, OS fingerprint, ARP)."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def scan_flags() -> list:
    """SYN + OS fingerprint when privileged (Npcap/admin); TCP connect otherwise.

    Even the unprivileged connect path still captures on-link MAC, because nmap
    does ARP host discovery before the port scan when -Pn is NOT used.
    """
    if is_admin():
        return ["-sS", "-O", "--osscan-limit"]
    return ["-sT"]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def choose_run_base() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "UBDEN-Cyber" / "Reports"
    base.mkdir(parents=True, exist_ok=True)
    return base


# --------------------------------------------------------------------------- #
# Windows host facts (adapters, ARP neighbours) — via the local PowerShell
# bridge when present, else pure-Python fallbacks.
# --------------------------------------------------------------------------- #
def windows_inventory() -> dict:
    if host_bridge is not None and host_bridge.available():
        try:
            snapshot = host_bridge.invoke("inventory", timeout=25)
            if isinstance(snapshot, dict):
                return snapshot
        except Exception:
            pass
    return {"status": "unavailable", "reason": "Windows envanter koprusu yok", "adapters": [],
            "default_routes": []}


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def test_connection(kind: str, body: dict) -> dict:
    """Read-only connection tests for the UI's 'bağlantı testi' buttons.

    LDAP bind (ad_assessment), HTTP HEAD/GET, and a single SSH auth attempt. All
    bounded, short-timeout, no scanning; secrets stay in memory (never written).
    """
    kind = (kind or "").lower()
    if kind == "ldap":
        dc = (body.get("dc") or "").strip()
        domain = (body.get("domain") or "").strip()
        user = (body.get("user") or "").strip()
        pw = body.get("password") or ""
        if not (dc and domain and user and pw):
            return {"ok": False, "detail": "DC / alan adı / kullanıcı / parola gerekli"}
        try:
            import ad_assessment
            res = ad_assessment.inspect(dc, domain, user, pw, dc if _looks_ip(dc) else None,
                                        allow_plaintext=bool(body.get("allow_plaintext")))
            ok = res.get("status") == "ok"
            return {"ok": ok, "detail": (res.get("reason") or res.get("source") or
                                         ("bağlandı, dizin okunabildi" if ok else "başarısız"))[:120]}
        except Exception as exc:
            return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:120]}
    if kind == "http":
        import ssl
        import urllib.request
        url = (body.get("url") or "").strip()
        if not url:
            return {"ok": False, "detail": "URL gerekli"}
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(url, method=method, headers={"User-Agent": "UBDEN-uPenetrator"})
                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                    server = resp.headers.get("Server", "")
                    return {"ok": True, "detail": f"HTTP {resp.status}" + (f" · {server}" if server else "")}
            except Exception as exc:
                last = f"{type(exc).__name__}: {exc}"
        return {"ok": False, "detail": last[:120]}
    if kind == "ssh":
        host = (body.get("host") or "").strip()
        user = (body.get("user") or "").strip()
        pw = body.get("password") or ""
        if not (host and user and pw):
            return {"ok": False, "detail": "host / kullanıcı / parola gerekli"}
        try:
            import paramiko
        except Exception:
            return {"ok": False, "detail": "paramiko kurulu değil"}
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=22, username=user, password=pw, timeout=8,
                           allow_agent=False, look_for_keys=False)
            client.close()
            return {"ok": True, "detail": "kimlik doğrulandı"}
        except paramiko.AuthenticationException:
            return {"ok": False, "detail": "kimlik doğrulama reddedildi (bağlantı kuruldu)"}
        except Exception as exc:
            return {"ok": False, "detail": f"{type(exc).__name__}"[:80]}
    return {"ok": False, "detail": "bilinmeyen test türü"}


def _is_real_neighbor(ip: str, mac: str) -> bool:
    """Drop multicast/broadcast ARP ghosts (224/4, 255.*, 01:00:5E/33:33/FF, I-G bit)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or str(addr) == "255.255.255.255":
        return False
    m = str(mac).replace("-", ":").upper()
    if m.startswith(("01:00:5E", "33:33", "FF:FF:FF")):
        return False
    try:
        if int(m.split(":")[0], 16) & 1:  # group/multicast bit
            return False
    except ValueError:
        return False
    return True


def arp_neighbours() -> dict:
    """Map ``{ip: {'mac','device'}}`` from the local ARP cache, ghosts filtered.

    Prefers the bridge ``neighbours`` action (Get-NetNeighbor, richer state); falls
    back to parsing ``arp -a`` which needs no admin and no PowerShell.
    """
    if host_bridge is not None and host_bridge.available():
        try:
            result = host_bridge.invoke("neighbours", timeout=25)
            if isinstance(result, dict) and result.get("status") == "ok":
                out = {}
                for row in result.get("neighbours", []):
                    ip, mac = row.get("ip"), row.get("mac")
                    if ip and mac and _is_real_neighbor(ip, mac):
                        out[ip] = {"mac": mac, "device": row.get("device", "")}
                if out:
                    return out
        except Exception:
            pass
    return _arp_table()


def _arp_table() -> dict:
    out: dict[str, dict] = {}
    if not shutil.which("arp"):
        return out
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                timeout=20, errors="replace", check=False)
    except (OSError, subprocess.TimeoutExpired):
        return out
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].count(".") == 3:
            try:
                ip = str(ipaddress.ip_address(parts[0]))
            except ValueError:
                continue
            mac = parts[1]
            if (mac.count("-") == 5 or mac.count(":") == 5) and _is_real_neighbor(ip, mac):
                out[ip] = {"mac": mac, "device": ""}
    return out


def _default_routes_fallback() -> list:
    """Best-effort default gateway(s) via `route print` when the bridge is absent,
    so the gateway is classified as a router even in standalone runs."""
    try:
        out = subprocess.run(["route", "print", "-4"], capture_output=True, text=True,
                             timeout=10, errors="replace", check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    routes = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            try:
                ipaddress.ip_address(parts[2])
                routes.append({"destination": "0.0.0.0/0", "gateway": parts[2]})
            except ValueError:
                pass
    return routes


def ensure_oui_paths(state_dir: Path) -> list:
    """Return OUI sources for vendor resolution on Windows.

    Windows Nmap ships ``nmap-mac-prefixes`` next to nmap.exe. Also refresh the
    IEEE MA-L/M/S CSVs into ``state_dir`` (best-effort, browser-UA download) since
    they are not bundled. Both are optional; without them vendor stays "Bilinmiyor".
    """
    paths = []
    nmap = shutil.which("nmap")
    if nmap:
        prefixes = Path(nmap).resolve().parent / "nmap-mac-prefixes"
        if prefixes.is_file():
            paths.append(prefixes)
    ieee_dir = state_dir / "ieee"
    if ieee_registry is not None:
        try:
            ieee_registry.refresh(ieee_dir)
        except Exception:
            pass
    for name in ("oui.csv", "mam.csv", "mas.csv"):
        candidate = ieee_dir / name
        if candidate.is_file():
            paths.append(candidate)
    bundled = ROOT / "data" / "ieee"
    for name in ("oui.csv", "mam.csv", "mas.csv"):
        candidate = bundled / name
        if candidate.is_file():
            paths.append(candidate)
    return paths


# --------------------------------------------------------------------------- #
# Meta (engagement.json, schema 8) — mirrors wizard.collect_meta's contract.
# --------------------------------------------------------------------------- #
def build_meta(form: dict, host_snapshot: dict) -> dict:
    profile = form.get("profile", "network")
    if profile not in PROFILES:
        profile = "network"
    targets = [t for t in (form.get("targets") or []) if t]
    exclusions = [e for e in (form.get("exclusions") or []) if e]
    selected = [int(i) for i in (form.get("selected_interfaces") or []) if str(i).strip().isdigit()]
    try:
        top_ports = min(max(int(form.get("top_ports", 200)), 1), 1000)
    except (TypeError, ValueError):
        top_ports = 200
    try:
        max_rate = min(max(int(form.get("max_rate", 100)), 1), 500)
    except (TypeError, ValueError):
        max_rate = 100
    ad = _ad_spec(form, host_snapshot)
    enabled = ["nmap-service", "device-inventory"]
    if profile in ("network", "full"):
        enabled += ["nse-audit", "snmp", "sql-browser", "rootdse", "network-extras", "snmp-extras"]
    if profile == "full":
        enabled += ["supplemental_network"]  # enables run_supplemental in the probe suite
    if profile in ("web", "full"):
        enabled += ["web-headers", "tls", "nikto"]
    if profile in ("external", "full"):
        enabled += ["dns-osint"]
    if ad.get("mode") != "disabled":
        enabled += ["ad"]
    # Opt-in intrusive extras: sqlmap is wired into the network/full probe suite and
    # also requires a real written authorization reference (not the placeholder).
    auth_ref = (form.get("authorization_reference") or "").strip()
    if profile in ("network", "full") and bool(form.get("sql_injection_test")) and auth_ref:
        enabled += ["sql_injection_test"]
    if profile in ("network", "full") and bool(form.get("voip_scan")):
        enabled += ["voip_scan"]
    return {
        "schema": 8, "id": str(uuid.uuid4()),
        "client": (form.get("client") or "").strip() or "Belirtilmedi",
        "project": (form.get("project") or "").strip() or "Windows-native degerlendirme",
        "authorization_reference": (form.get("authorization_reference") or "").strip() or "Belirtilmedi",
        "product": "UBDEN Cyber Security Systems",
        "product_owner": "UBDEN®",
        "tester": (form.get("tester") or "").strip() or "Belirtilmedi",
        "targets": targets, "exclusions": exclusions,
        "frozen_dns": {}, "address_budget": {},
        "selected_interfaces": selected,
        "network_mode": "windows-native",
        "profile": profile,
        "enabled_modules": enabled, "allowed_techniques": enabled,
        "auth_probes": [], "role_scenarios": [], "password_probes": [],
        "ad": ad,
        "web": {"base": (form.get("web_url") or "").strip(),
                "swagger": (form.get("swagger_url") or "").strip()},
        "browser_enabled": False,
        "default_cred_test": bool(form.get("default_cred_test")),
        "wireless": {"enabled": False},
        "host_snapshot": host_snapshot if isinstance(host_snapshot, dict) else {},
        "limits": {"max_online_failures_per_test_account_service": 2,
                   "max_exploit_attempts_per_finding_host": 1},
        "ai_enabled": bool((form.get("claude_api_key") or "").strip()),
        "ai_raw_evidence": bool(form.get("claude_raw")),
        "nuclei_templates": None, "nuclei_profile": "none", "nuclei_template_count": 0,
        "max_rate": max_rate, "top_ports": top_ports,
        "started_at": now(), "status": "planned", "tool_version": VERSION,
        "engine": "uPenetrator-win",
    }


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
def _ad_spec(form: dict, host_snapshot: dict) -> dict:
    """Build meta['ad']: supplied (LDAP creds given), joined (host is domain member),
    else disabled. The password is NOT stored here — it is passed separately."""
    dc = (form.get("ad_dc") or "").strip()
    domain = (form.get("ad_domain") or "").strip()
    user = (form.get("ad_user") or "").strip()
    if dc and domain and user and (form.get("ad_pass") or ""):
        return {"mode": "supplied", "dc": dc, "domain": domain, "account": user,
                "allow_plaintext": bool(form.get("ad_allow_plaintext"))}
    if isinstance(host_snapshot, dict) and host_snapshot.get("part_of_domain"):
        return {"mode": "joined", "domain": host_snapshot.get("domain", "")}
    return {"mode": "disabled"}


def _ports_arg(meta: dict) -> list:
    if meta["profile"] == "web":
        return ["-p", "80,443,8080,8443"]
    return ["--top-ports", str(meta["top_ports"])]


# High-value ports for the connect-scan augmentation (VoIP/SIP/SCCP, web, mgmt, remote).
_AUGMENT_PORTS = ("21,22,23,25,53,80,81,110,143,161,443,445,515,554,631,993,995,1720,1723,"
                  "2000,2427,3389,5060,5061,5222,5432,7070,8000,8080,8443,9100")


def _connect_scan_augment(target, assets, meta, raw, events, progress, open_ports):
    """A TCP connect (-sT) pass over high-value ports, merged into open_ports.

    A privileged SYN scan (-sS) often comes back 'filtered' for hosts behind a routed
    firewall (e.g. VoIP phones on other VLANs), so those live hosts end up with zero ports
    and never get classified/probed. A connect scan uses the OS TCP stack and traverses
    routing/NAT/firewall like ordinary traffic — which is what a full connect scanner sees
    (SIP 5060 + SCCP 2000 on IP phones, web/mgmt elsewhere). Purely additive.
    """
    if not shutil.which("nmap") or not assets:
        return
    ipv6 = ["-6"] if any(":" in a for a in assets) else []
    xml = raw / "nmap_connect.xml"
    base = ["nmap"] + ipv6 + ["-n", "-sT", "-sV", "--version-light", "-T3",
                              "--max-rate", str(meta["max_rate"]), "--max-retries", "1",
                              "--host-timeout", "8m", "-p", _AUGMENT_PORTS, "-oX", str(xml)]
    if wizard.is_network(target):
        argv = base + [target]
    else:
        listf = raw / "connect_targets.txt"
        listf.write_text("\n".join(assets) + "\n", encoding="ascii")
        argv = base + ["-iL", str(listf)]
    progress(f"{target}: TCP connect dogrulama taramasi (SYN'in kacirdigi VoIP/servis portlari)", "info")
    try:
        win_proc.run("nmap_connect", argv, raw, events,
                     timeout=min(86400, max(900, len(assets) * 5 + 600)),
                     on_tick=lambda n, e, t: progress(f"{n}: {int(e)}s / {int(t)}s", "tick"))
    except Exception as exc:
        events.append({"step": "connect_augment", "target": target, "status": "warn", "detail": str(exc)[:200]})
        return
    try:
        merged = wizard.open_tcp_ports_by_host(xml, assets)
    except Exception:
        merged = {}
    for ip, extra in merged.items():
        if extra:
            open_ports[ip] = sorted(set(open_ports.get(ip, [])) | set(extra))


def _scan_scope(target, assets, meta, raw, events, progress):
    """One ARP-enabled Nmap pass (no -Pn/--disable-arp-ping) → ports + on-link MAC.

    Writing the MAC and ports into the SAME nmap_*.xml is required because
    device_inventory overwrites per-IP by filename order.
    """
    ipv6 = ["-6"] if any(":" in a for a in assets) else []
    ports = _ports_arg(meta)
    flags = scan_flags()  # -sS -O when privileged (Npcap/admin), else -sT; both keep ARP MAC
    if wizard.is_network(target):
        name = "nmap_cidr"
        argv = (["nmap"] + ipv6 + ["-n"] + flags + ["-sV", "--version-light", "-T3",
                "--stats-every", "10s", "--max-rate", str(meta["max_rate"]),
                "--max-retries", "1", "--host-timeout", "10m"] + ports +
                ["-oX", str(raw / f"{name}.xml"), target])
        progress(f"{target}: ARP + servis taramasi (Npcap ile MAC yakalanir)", "info")
        win_proc.run(name, argv, raw, events,
                     timeout=min(86400, max(1800, len(assets) * 8 + 1200)),
                     on_tick=lambda n, e, t: progress(f"{n}: {int(e)}s / {int(t)}s", "tick"))
        open_ports = wizard.open_tcp_ports_by_host(raw / f"{name}.xml", assets)
        _connect_scan_augment(target, assets, meta, raw, events, progress, open_ports)
    else:
        open_ports = {}
        for ip in assets:
            key = wizard.safe_filename(ip)
            name = f"nmap_{key}"
            argv = (["nmap"] + (["-6"] if ":" in ip else []) + ["-n"] + flags +
                    ["-sV", "--version-light", "-T3", "--stats-every", "10s",
                     "--max-rate", str(meta["max_rate"]), "--max-retries", "1",
                     "--host-timeout", "8m"] + ports + ["-oX", str(raw / f"{name}.xml"), ip])
            progress(f"{ip}: ARP + servis taramasi", "info")
            win_proc.run(name, argv, raw, events, timeout=600,
                         on_tick=lambda n, e, t: progress(f"{n}: {int(e)}s / {int(t)}s", "tick"))
            open_ports[ip] = wizard.open_tcp_ports(raw / f"{name}.xml")
        _connect_scan_augment(target, assets, meta, raw, events, progress, open_ports)
    return open_ports


def scan_target(target, meta, root, events, progress):
    folder = root / "targets" / wizard.safe_filename(target)
    raw = folder / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    exclusions = meta["exclusions"]
    # Resolve to in-scope assets (mirrors wizard.scan_target's gating).
    if wizard.is_network(target):
        net = ipaddress.ip_network(target)
        if (net.version == 4 and net.prefixlen < 24) or (net.version == 6 and net.prefixlen < 120):
            events.append({"step": "scope", "target": target, "status": "blocked",
                           "detail": "CIDR siniri asildi (min /24)"})
            progress(f"{target}: kapsam disi (CIDR cok genis)", "warn")
            return
        assets = [str(ip) for ip in net.hosts() if not wizard.excluded(str(ip), exclusions)]
    elif wizard.is_ip(target):
        assets = [] if wizard.excluded(target, exclusions) else [target]
    else:
        try:
            current = wizard.resolve(target)
        except socket.gaierror as exc:
            events.append({"step": "dns", "target": target, "status": "error", "detail": str(exc)})
            progress(f"{target}: DNS cozulemedi", "warn")
            return
        assets = [x for x in current if not wizard.excluded(x, exclusions)]
        (raw / "dns_resolution.json").write_text(
            json.dumps({"host": target, "addresses": assets, "at": now()}, indent=2), encoding="utf-8")
        if len(assets) > 16:
            events.append({"step": "scope", "target": target, "status": "blocked",
                           "detail": "16 uzeri DNS adresi; IP bazinda daraltin"})
            return
    if not assets:
        events.append({"step": "scope", "target": target, "status": "blocked",
                       "detail": "Tum adresler haric tutulmus"})
        progress(f"{target}: taranacak adres yok", "warn")
        return
    # Route-scope guard for single hosts (reused; os.name=='nt' branch uses the bridge).
    if not wizard.is_network(target) and meta.get("selected_interfaces"):
        try:
            assets = wizard.route_guard(assets, meta["selected_interfaces"], raw, events, target)
        except Exception:
            pass
        if not assets:
            events.append({"step": "route_scope_empty", "target": target, "status": "blocked",
                           "detail": "Secilen adaptor uzerinden kapsam ici IP yok"})
            progress(f"{target}: secilen adaptor uzerinden erisim yok", "warn")
            return
    progress(f"{target}: {len(assets)} adres taraniyor", "info")
    open_ports = _scan_scope(target, assets, meta, raw, events, progress)
    # Narrow the per-host probe suite to LIVE hosts (those with an open port) for a
    # CIDR sweep, so SNMP/NetBIOS/web probes don't run against all 254 addresses.
    if wizard.is_network(target):
        probe_assets = [ip for ip in assets if open_ports.get(ip)]
    else:
        probe_assets = assets
    # Full tool breadth (NSE audit, platform ports, SNMP/SQL/RootDSE, network & SNMP
    # extras, credential probes, supplemental, HTTP/TLS/nikto/nuclei, DNS/OSINT) via
    # the SAME suite the Kali wizard runs; absent tools are recorded as missing_tool.
    progress(f"{target}: {len(probe_assets)} canli hostta servis/guvenlik problari (tum araclar)", "info")
    try:
        wizard.run_probe_suite(target, meta, root, raw, events, probe_assets, open_ports)
    except Exception as exc:
        events.append({"step": "probe_suite_error", "target": target, "status": "error",
                       "detail": f"{type(exc).__name__}: {exc}"})
        progress(f"{target}: prob paketi hatasi - {exc}", "warn")


def run_scan(form: dict, progress=None) -> dict:
    """Run a full Windows-native engagement and render the report.

    Returns ``{'run_dir', 'report_html', 'device_summary', 'status'}``.
    """
    def emit(line, level="info", lane=None):
        if progress:
            try:
                progress(line, level, lane)
            except TypeError:
                try:
                    progress(line, level)  # older 2-arg progress callback
                except Exception:
                    pass
            except Exception:
                pass

    if win_tools is not None:
        win_tools.ensure_path()  # make pip/winget-installed CLIs discoverable via which()
    # Long, wide scans must not be interrupted by sleep/throttling: keep awake and
    # switch to a high-performance plan for the duration (restored before return).
    prev_power_scheme = ""
    if power_manager is not None:
        try:
            power_manager.stay_awake()
            prev_power_scheme = power_manager.high_performance()
        except Exception:
            prev_power_scheme = ""
    host_snapshot = windows_inventory()
    # Ensure the default gateway is known even without the bridge, so it classifies
    # as a router in the device inventory (standalone runs otherwise miss it).
    if isinstance(host_snapshot, dict) and not host_snapshot.get("default_routes"):
        fallback = _default_routes_fallback()
        if fallback:
            host_snapshot["default_routes"] = fallback
    meta = build_meta(form, host_snapshot)
    emit("Kapsam donduruluyor (DNS/adres butcesi)", "info")
    try:
        wizard.freeze_scope(meta)
    except Exception as exc:
        emit(f"Kapsam dondurma uyarisi: {exc}", "warn")
    meta["scope_frozen_at"] = now()

    base = choose_run_base()
    label = wizard.safe_filename((meta.get("project") or "UBDEN") + "_" +
                                 dt.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + meta["id"][:8])
    root = base / label
    (root / "targets").mkdir(parents=True, exist_ok=True)

    # Concurrency: run targets in parallel lanes. The shared packet-rate budget is
    # SPLIT across active lanes (per_lane = max_rate // lanes) so parallel scans do
    # not exceed the engagement rate cap or trip IDS. Credential/lockout-sensitive
    # work stays per-target (one lane = one target), so no host sees parallel auth.
    targets = list(meta["targets"])
    try:
        requested = int(form.get("lanes", 0))
    except (TypeError, ValueError):
        requested = 0
    # Default lanes adapt to CPU cores for wide multi-subnet scope; the form can
    # override. The shared rate governor keeps total packets under the cap.
    auto_default = max(DEFAULT_LANES, min(MAX_LANES, (os.cpu_count() or 4) // 2))
    lanes = requested if requested > 0 else auto_default
    lanes = max(1, min(lanes, MAX_LANES, len(targets) or 1))
    per_lane_rate = max(1, meta["max_rate"] // lanes)
    meta["concurrency"] = {"lanes": lanes, "per_lane_max_rate": per_lane_rate,
                           "total_max_rate": meta["max_rate"]}

    events: list = []
    # Persist meta + host snapshot up front (engagement.json is the hard dependency).
    _atomic_json(root / "engagement.json", meta)
    _atomic_json(root / "HOST_CAPABILITIES.json", host_snapshot)

    # Per-lane state for the live multi-lane panel + job ledger.
    lane_states: dict[str, dict] = {}
    lane_events: dict[str, list] = {}
    ledger_lock = threading.Lock()
    stop_monitor = threading.Event()

    def lane_snapshot(tid, state, done=False):
        evs = lane_events.get(tid, [])
        last = evs[-1] if evs else {}
        emit("", "lane", {"id": tid, "target": state["target"],
                          "step": last.get("step", state.get("phase", "hazirlaniyor")),
                          "status": "bitti" if done else state.get("phase", "calisiyor"),
                          "steps": len(evs),
                          "ok": sum(1 for e in evs if e.get("status") == "ok"),
                          "issues": sum(1 for e in evs if e.get("status") in
                                        ("error", "timeout", "blocked", "missing_tool"))})

    def _checkpoint():
        # Flush a partial steps.json so an interrupted long scan keeps its evidence.
        try:
            with ledger_lock:
                partial = []
                for index, target in enumerate(targets):
                    partial.extend(lane_events.get(f"L{index + 1}", []))
            _atomic_json(root / "steps.json", partial)
        except Exception:
            pass

    def monitor():
        ticks = 0
        while not stop_monitor.wait(1.2):
            ticks += 1
            with ledger_lock:
                for tid, state in lane_states.items():
                    if not state.get("done"):
                        lane_snapshot(tid, state)
            if ticks % 8 == 0:  # ~every 10s: checkpoint evidence to disk
                _checkpoint()

    def run_lane(index, target):
        tid = f"L{index + 1}"
        state = {"target": target, "phase": "kesif", "done": False,
                 "started_at": now()}
        evs: list = []
        with ledger_lock:
            lane_states[tid] = state
            lane_events[tid] = evs
        lane_meta = dict(meta)
        lane_meta["max_rate"] = per_lane_rate

        def lane_progress(line, level="info", lane=None):
            if line:
                emit(f"[{tid} {target}] {line}", level)
            with ledger_lock:
                lane_snapshot(tid, state)
        emit(f"{target}: serit {tid} basladi", "info")
        try:
            scan_target(target, lane_meta, root, evs, lane_progress)
        except Exception as exc:  # one lane must not abort the run
            evs.append({"step": "target_error", "target": target, "status": "error",
                        "detail": f"{type(exc).__name__}: {exc}"})
            emit(f"[{tid} {target}] hata - {exc}", "warn")
        finally:
            state["done"] = True
            state["finished_at"] = now()
            with ledger_lock:
                lane_snapshot(tid, state, done=True)

    emit(f"Es zamanli yurutme: {lanes} serit, serit basi {per_lane_rate} paket/sn "
         f"(toplam ~{meta['max_rate']})", "info")
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    with ThreadPoolExecutor(max_workers=lanes) as pool:
        list(pool.map(lambda pair: run_lane(*pair), list(enumerate(targets))))
    stop_monitor.set()
    monitor_thread.join(timeout=3)

    # Merge lane events in deterministic target order → steps.json.
    for index, target in enumerate(targets):
        events.extend(lane_events.get(f"L{index + 1}", []))

    # Execution ledger (concurrency timeline) for the report/audit.
    ledger = {"schema": 1, "concurrency": meta["concurrency"],
              "lanes": [{"id": f"L{i + 1}", "target": t,
                         "started_at": lane_states.get(f"L{i + 1}", {}).get("started_at"),
                         "finished_at": lane_states.get(f"L{i + 1}", {}).get("finished_at"),
                         "steps": len(lane_events.get(f"L{i + 1}", [])),
                         "issues": sum(1 for e in lane_events.get(f"L{i + 1}", [])
                                       if e.get("status") in ("error", "timeout", "blocked", "missing_tool"))}
                        for i, t in enumerate(targets)]}
    _atomic_json(root / "UBDEN_EXECUTION.json", ledger)

    # Device inventory with real Windows L2 data → MAC/vendor/category populated.
    emit("Cihaz envanteri olusturuluyor (MAC/uretici/kategori)", "info")
    state_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "UBDEN"
    oui_paths = ensure_oui_paths(state_dir)
    neighbours = arp_neighbours()
    try:
        summary = device_inventory.build_inventory(root, meta, neighbours=neighbours,
                                                   oui_paths=oui_paths or None)
        events.append({"step": "device_inventory", "status": "ok",
                       "detail": f"{summary['host_count']} cihaz; {summary['mac_count']} MAC; "
                                 f"{summary['unknown_count']} siniflandirilmamis",
                       "output": "DEVICE_INVENTORY.json"})
        emit(f"Cihaz envanteri: {summary['host_count']} cihaz, {summary['mac_count']} MAC", "info")
    except Exception as exc:
        summary = {"host_count": 0, "mac_count": 0}
        events.append({"step": "device_inventory", "status": "error", "detail": str(exc)})
        emit(f"Cihaz envanteri hatasi: {exc}", "warn")

    # Active Directory assessment (joined = local domain via bridge; supplied = LDAP
    # bind). Password passed in-memory only, never written to meta/report.
    if meta.get("ad", {}).get("mode") != "disabled":
        emit("Active Directory değerlendirmesi", "info")
        try:
            wizard.run_ad_module(root, meta, {"password": form.get("ad_pass") or ""}, events)
        except Exception as exc:
            events.append({"step": "ad_assessment", "status": "error", "detail": str(exc)})
            emit(f"AD değerlendirme hatası: {exc}", "warn")

    # Agentic Claude AI operator (opt-in via API key): allowlisted follow-up checks +
    # deep per-domain analysis → AI-assessed draft findings in the report. Minimizes
    # analyst work. Key stays in memory; findings remain drafts (human sign-off distinct).
    ai_key = (form.get("claude_api_key") or "").strip()
    if ai_key and ai_operator is not None:
        emit("Claude AI operatör çalışıyor (takip kontrolleri + derin analiz)", "info")
        try:
            ai_operator.run(root, meta, events, {
                "key": ai_key,
                "model": form.get("claude_model") or os.environ.get("UBDEN_AI_MODEL") or ai_operator.DEFAULT_MODEL,
                "deep_model": form.get("claude_deep_model") or os.environ.get("UBDEN_AI_DEEP_MODEL") or ai_operator.DEFAULT_DEEP_MODEL,
                "raw": bool(form.get("claude_raw")),
                "enable_actions": form.get("ai_actions", True) is not False,
            }, progress=emit)
        except Exception as exc:
            emit(f"AI operatör hatası (rapor devam ediyor): {exc}", "warn")

    # Wi-Fi visibility (test machine's adapter, if any) — passive, no monitor mode.
    if wifi_scan is not None:
        try:
            wdata = wifi_scan.run(root, events)
            if wdata.get("available"):
                emit(f"Wi-Fi: {wdata.get('network_count', 0)} SSID / {wdata.get('ap_count', 0)} BSSID görüldü", "info")
        except Exception as exc:
            emit(f"Wi-Fi taraması atlandı: {exc}", "warn")

    meta["status"] = "completed"
    meta["finished_at"] = now()
    _atomic_json(root / "engagement.json", meta)
    _atomic_json(root / "steps.json", events)

    emit("Rapor olusturuluyor (PDF + HTML)", "info")
    try:
        result = subprocess.run([sys.executable, str(ROOT / "report_v2.py"), str(root)],
                                capture_output=True, text=True, errors="replace",
                                timeout=1800, check=False)
        if result.returncode == 0:
            status = "completed"
        else:
            status = "report_error"
            emit("Rapor uretimi hata dondu: " + (result.stderr or "").strip()[:300], "warn")
    except (OSError, subprocess.TimeoutExpired) as exc:
        status = "report_error"
        emit(f"Rapor hatasi: {exc}", "warn")

    if _install_webui(root):
        emit("Rapor gezgini (webui) klasore kopyalandi: webui/start.cmd", "info")

    if power_manager is not None and prev_power_scheme:
        try:
            power_manager.restore_scheme(prev_power_scheme)
        except Exception:
            pass
    report_html = root / "REPORT.html"
    emit("Tamamlandi", "done")
    # Clear completion banner to the server console (the elevated window), since the
    # web server keeps running (serve_forever) and would otherwise show no "done".
    line = "=" * 64
    if report_html.is_file():
        print(f"\n{line}\n  [OK] RAPOR HAZIR: {report_html}\n"
              f"  Cihaz: {summary.get('host_count', 0)} · MAC: {summary.get('mac_count', 0)} · "
              f"Durum: {status}\n  Tarayicidan acabilir veya klasoru inceleyebilirsiniz.\n{line}\n",
              flush=True)
    else:
        print(f"\n{line}\n  [!] Rapor uretilemedi (durum: {status}); gorev klasoru: {root}\n{line}\n",
              flush=True)
    return {"run_dir": str(root), "report_html": str(report_html) if report_html.is_file() else "",
            "device_summary": summary, "status": status}


def _atomic_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _install_webui(root: Path) -> bool:
    """Copy the offline report viewer into the run folder so the report is self-contained.

    Additive and best-effort: a failure here never affects the scan or the report. The
    viewer's own review state lives in <run>/.webui, not inside <run>/webui, so replacing
    the app files never discards analyst edits.
    """
    source = ROOT / "webui"
    if not (source / "serve.py").is_file():
        return False
    dest = root / "webui"
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "test_webui.py", ".webui")
    try:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(source, dest, ignore=ignore)
        return True
    except OSError:
        return False
