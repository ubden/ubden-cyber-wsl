"""SMB share enumeration and permission review (Windows-native, read-only).

Lists a host's shares with `net view \\host /all`, then reads the NTFS ACL of each
NON-default share to flag ones a low-privileged principal (Everyone / Authenticated Users /
Domain Users) can write to — a common lateral-movement and data-exposure path (e.g. a `scr`
share with Domain Users:Modify). Uses the operator's current logon session (works when the
box is domain-joined or launched with `runas /netonly`); best-effort and never raises.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

_DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON"}
_WRITE_RE = re.compile(r"FullControl|Modify|Write", re.I)
_LOWPRIV_RE = re.compile(r"Everyone|Authenticated Users|Domain Users|\bUsers\b|BUILTIN\\Users", re.I)


def _run(argv, timeout):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def list_shares(host, timeout=25):
    """Return [share_name] from `net view`. Windows only."""
    if os.name != "nt":
        return []
    proc = _run(["net", "view", rf"\\{host}", "/all"], timeout)
    if not proc or proc.returncode != 0:
        return []
    shares = []
    for line in proc.stdout.splitlines():
        # columns: "<name>   Disk   ...". Share names have no spaces; take the first token of
        # lines that look like share rows (contain "Disk"/"Disk " type marker).
        m = re.match(r"^(\S+)\s+(Disk|Disk\s|Print|IPC)", line)
        if m:
            shares.append(m.group(1))
    return shares


def share_ntfs_acl(host, share, timeout=15):
    r"""Return [(identity, rights)] Allow ACEs for \\host\share via Get-Acl. Windows only."""
    if os.name != "nt":
        return []
    ps = (f"try{{(Get-Acl -LiteralPath '\\\\{host}\\{share}').Access | "
          "Where-Object {$_.AccessControlType -eq 'Allow'} | "
          "ForEach-Object {\"$($_.IdentityReference)|$($_.FileSystemRights)\"}}catch{}")
    proc = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout)
    out = []
    if proc and proc.stdout:
        for line in proc.stdout.splitlines():
            ident, _, rights = line.partition("|")
            if ident.strip():
                out.append((ident.strip(), rights.strip()))
    return out


def run(assets, opened, raw, events) -> None:
    """Enumerate shares on hosts with 445 open; write share_<ip>.json with any non-default
    share and its low-privilege-writable ACEs."""
    if os.name != "nt":
        events.append({"step": "share_enum", "status": "skipped",
                       "detail": "Paylaşım envanteri Windows-native yolda çalışır (net view / Get-Acl)."})
        return
    raw = Path(raw)
    hits = 0
    for ip in assets:
        if 445 not in set(opened.get(ip) or []):
            continue
        shares = list_shares(ip)
        if not shares:
            continue
        records = []
        for share in shares:
            if share.upper() in _DEFAULT_SHARES or share.endswith("$"):
                continue
            acl = share_ntfs_acl(ip, share)
            risky = [f"{i}: {r}" for i, r in acl if _WRITE_RE.search(r) and _LOWPRIV_RE.search(i)]
            records.append({"share": share, "acl": [f"{i}: {r}" for i, r in acl][:20],
                            "low_priv_writable": risky})
        if records:
            hits += 1
            try:
                (raw / f"share_{re.sub(r'[^A-Za-z0-9._-]', '_', str(ip))[:90]}.json").write_text(
                    json.dumps({"target": str(ip), "shares": [s for s in shares if s.upper() not in _DEFAULT_SHARES],
                                "non_default": records}, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
    if hits:
        events.append({"step": "share_enum", "status": "ok",
                       "detail": f"{hits} hostta varsayılan-dışı paylaşım listelendi"})
