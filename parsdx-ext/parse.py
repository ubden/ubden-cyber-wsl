"""Parse offensive-tool output (from attack.py's evidence files) into normalized findings.

Bridges raw tool text -> structured finding dicts that score.py / attck.py / emit.py consume.
Each parser is regex-based and self-tested against representative real output, so it works
offline. A normalized finding carries the substance; score fills CVSS, emit maps to UBDEN.
"""
from __future__ import annotations

import os
import re
import sys

# ---- individual tool parsers -------------------------------------------------


def parse_certipy(text: str) -> list[dict]:
    """certipy find -vulnerable -stdout -> one finding per (template, ESC)."""
    findings = []
    current_tpl = None
    for line in text.splitlines():
        m = re.search(r"Template Name\s*:\s*(.+)", line)
        if m:
            current_tpl = m.group(1).strip()
            continue
        esc = re.search(r"\b(ESC\d+)\b\s*:\s*(.+)", line)
        if esc:
            findings.append({
                "type": "adcs_esc",
                "title": f"AD CS {esc.group(1)} — abusable certificate template"
                         + (f" ({current_tpl})" if current_tpl else ""),
                "asset": current_tpl or "AD CS",
                "technique": "T1649",  # Steal or Forge Authentication Certificates
                "root_cause": f"{esc.group(1)}: {esc.group(2).strip()}",
                "description": f"Certipy flagged {esc.group(1)} on template "
                               f"'{current_tpl or '?'}': {esc.group(2).strip()}",
                "impact": "A low-privileged user can enroll a certificate that authenticates as a "
                          "privileged principal, leading to domain privilege escalation.",
                "recommendation": "Remove client-authentication EKU or enrollee-supplied-subject on "
                                  "the template, restrict enrollment rights, enable manager approval, "
                                  "and enforce CA enrollment restrictions.",
            })
    return findings


def parse_kerberoast(text: str) -> list[dict]:
    """GetUserSPNs -request -> one finding per roastable service account with a TGS hash.
    Matches BOTH RC4 (etype 23: `$krb5tgs$23$*user$realm$...`) and AES (etype 17/18:
    `$krb5tgs$18$user$realm$*spn*$...`) — AES is the modern AD default, so RC4-only misses most."""
    findings = []
    for m in re.finditer(r"\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$*]+)\$", text):
        user, realm = m.group(1), m.group(2)
        findings.append({
            "type": "kerberoast",
            "title": f"Kerberoastable service account: {user}",
            "asset": f"{realm}\\{user}",
            "technique": "T1558.003",  # Kerberoasting
            "root_cause": "SPN set on a user account whose password is crackable offline.",
            "description": f"A TGS was requested for SPN account '{user}' in {realm}; the ticket is "
                           f"encrypted with the account's password hash and can be cracked offline.",
            "impact": "If the service-account password is weak, an attacker recovers it offline "
                      "(no lockout risk) and gains that account's privileges.",
            "recommendation": "Use 25+ char random passwords or gMSAs for service accounts; remove "
                              "unnecessary SPNs; monitor TGS requests.",
        })
    return findings


def parse_asrep(text: str) -> list[dict]:
    """GetNPUsers -> one finding per AS-REP-roastable account."""
    findings = []
    # RC4 (etype 23): `$krb5asrep$23$user@REALM:hash`  ·  AES (17/18): `$krb5asrep$18$user$REALM$...`
    # Separator between user and realm is '@' for RC4 but '$' for AES — accept both, or AES is lost.
    for m in re.finditer(r"\$krb5asrep\$\d+\$([^@$\s]+)[@$]([^:@$\s]+)", text):
        user, realm = m.group(1), m.group(2)
        findings.append({
            "type": "asrep_roast",
            "title": f"AS-REP roastable account: {user}",
            "asset": f"{realm}\\{user}",
            "technique": "T1558.004",  # AS-REP Roasting
            "root_cause": "Kerberos pre-authentication disabled on the account.",
            "description": f"Account '{user}' in {realm} has 'Do not require Kerberos preauth' set; an "
                           f"AS-REP encrypted with its password hash was obtained without any credential.",
            "impact": "An unauthenticated attacker recovers the password offline if it is weak.",
            "recommendation": "Enable Kerberos pre-authentication for all accounts; strong passwords.",
        })
    return findings


def parse_nxc_authmatrix(text: str) -> list[dict]:
    """nxc smb ... -> findings where a credential grants local admin (Pwn3d!)."""
    findings = []
    for line in text.splitlines():
        if "(Pwn3d!)" not in line:
            continue
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        cred = re.search(r"\\?([^\s\\]+):", line)
        host_ip = ip.group(1) if ip else "?"
        findings.append({
            "type": "local_admin",
            "title": f"Credential grants local administrator on {host_ip}",
            "asset": host_ip,
            "technique": "T1078.002",  # Valid Accounts: Domain Accounts
            "root_cause": "Credential reuse / over-privileged account grants local admin on this host.",
            "description": f"NetExec reported 'Pwn3d!' for the supplied credential on {host_ip}, i.e. "
                           f"the account is a local administrator there.",
            "impact": "Local admin enables credential dumping (LSASS/SAM) and lateral movement toward "
                      "Domain Admin.",
            "recommendation": "Enforce LAPS (unique local-admin passwords), tier admin accounts, and "
                              "remove unnecessary local-admin membership.",
        })
    return findings


def parse_coercer(text: str) -> list[dict]:
    """coercer scan -> finding per host with an exposed coercion method."""
    findings = []
    seen = set()
    for line in text.splitlines():
        # Skip negatives FIRST: Coercer prints "[-] host is NOT vulnerable to X" — matching bare
        # 'vulnerable' there would fabricate a Critical finding. Then require an affirmative signal.
        if re.search(r"not\s+vulnerable", line, re.I):
            continue
        if not re.search(r"ERROR_BAD_NETPATH|Attack has worked|\bvulnerable\b", line, re.I):
            continue
        meth = re.search(r"\b(EfsRpc\w+|MS-[A-Za-z]+|DFSCoerce|PetitPotam|PrinterBug|\w+Coerce)\b", line)
        host = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        host_ip = host.group(1) if host else None
        key = (host_ip or "?", meth.group(1) if meth else "coercion")
        if meth and key not in seen:  # dedupe per (host, method)
            seen.add(key)
            findings.append({
                "type": "coercion",
                "title": f"Authentication coercion exposed: {meth.group(1)}"
                         + (f" on {host_ip}" if host_ip else ""),
                "asset": host_ip or "domain hosts",
                "technique": "T1187",  # Forced Authentication
                "root_cause": f"RPC method {meth.group(1)} allows forcing machine authentication.",
                "description": f"Coercer's read-only scan found {meth.group(1)} reachable; a host can be "
                               f"coerced to authenticate to an attacker, enabling NTLM relay (e.g. to AD CS).",
                "impact": "Coercion + relay to AD CS (ESC8) or LDAP can yield domain compromise.",
                "recommendation": "Patch, enable SMB/LDAP signing + EPA, disable unused RPC (Spooler), "
                                  "and restrict where machine accounts can authenticate.",
            })
    return findings


# ---- aggregate over a run folder --------------------------------------------

# Fixed single-file evidence (one DC-target file each).
_FIXED_PARSERS = {
    "adcs_find.txt": parse_certipy,
    "kerberoast.txt": parse_kerberoast,
    "asrep_roast.txt": parse_asrep,
    "coerce_scan.txt": parse_coercer,
}
# Per-host evidence: attack.py writes one file per host (auth_matrix_<host>.txt), so we must GLOB.
# (The old code looked for a single "auth_matrix.txt" and silently lost every local-admin finding.)
_GLOB_PARSERS = {
    "auth_matrix_*.txt": parse_nxc_authmatrix,
    "auth_matrix.txt": parse_nxc_authmatrix,  # back-compat if a single file ever appears
}


def parse_run(run_dir: str) -> list[dict]:
    """Read attack.py evidence files under <run_dir>/parsdx and return normalized findings,
    each tagged with the evidence file it came from. Handles per-host (globbed) evidence."""
    import glob
    pdir = os.path.join(run_dir, "parsdx")
    out, seen_paths = [], set()

    def _consume(path, fn):
        if path in seen_paths or not os.path.isfile(path):
            return
        seen_paths.add(path)
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            return
        rel = os.path.join("parsdx", os.path.basename(path))
        for f in fn(text):
            f["evidence"] = rel
            out.append(f)

    for fname, fn in _FIXED_PARSERS.items():
        _consume(os.path.join(pdir, fname), fn)
    for pattern, fn in _GLOB_PARSERS.items():
        for path in sorted(glob.glob(os.path.join(pdir, pattern))):
            _consume(path, fn)
    return out


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    certipy = """Certificate Templates
  0
    Template Name                       : UserAuth
    [!] Vulnerabilities
      ESC1                              : 'CORP.LOCAL\\\\Domain Users' can enroll and supply subject
  1
    Template Name                       : WebServer
    [!] Vulnerabilities
      ESC8                              : Web enrollment is enabled and vulnerable to NTLM relay
"""
    cf = parse_certipy(certipy)
    check("certipy: 2 ESC findings", len(cf) == 2)
    check("certipy: ESC1 mapped to template UserAuth", cf[0]["asset"] == "UserAuth" and "ESC1" in cf[0]["root_cause"])
    check("certipy: ATT&CK T1649", cf[0]["technique"] == "T1649")

    krb = "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01:1433*$abcdef0123..."
    kf = parse_kerberoast(krb)
    check("kerberoast RC4 parsed", len(kf) == 1 and kf[0]["asset"] == "CORP.LOCAL\\svc_sql")
    krb_aes = "$krb5tgs$18$websvc$CORP.LOCAL$*HTTP/web01*$0011aabb..."
    kf_aes = parse_kerberoast(krb_aes)
    check("kerberoast AES (etype 18) parsed", len(kf_aes) == 1 and kf_aes[0]["asset"] == "CORP.LOCAL\\websvc")

    asrep = "$krb5asrep$23$jdoe@CORP.LOCAL:aabbcc..."
    af = parse_asrep(asrep)
    check("asrep RC4 parsed", len(af) == 1 and af[0]["asset"] == "CORP.LOCAL\\jdoe")
    af_aes = parse_asrep("$krb5asrep$18$muser$CORP.LOCAL$00aabbccdd...")
    check("asrep AES (etype 18) parsed", len(af_aes) == 1 and af_aes[0]["asset"] == "CORP.LOCAL\\muser")

    nxc = ("SMB  10.0.0.20  445  FILE01  [+] corp.local\\svc_test:S3cret! (Pwn3d!)\n"
           "SMB  10.0.0.21  445  WEB01   [-] corp.local\\svc_test:S3cret! STATUS_LOGON_FAILURE")
    nf = parse_nxc_authmatrix(nxc)
    check("nxc: only Pwn3d! host becomes a finding", len(nf) == 1 and nf[0]["asset"] == "10.0.0.20")

    co = "[-] 10.0.0.10 EfsRpcOpenFileRaw (\\\\attacker\\x) : ERROR_BAD_NETPATH"
    cof = parse_coercer(co)
    check("coercer real signal (ERROR_BAD_NETPATH) parsed", len(cof) >= 1 and cof[0]["type"] == "coercion")
    check("coercer skips 'NOT vulnerable' (no false positive)",
          len(parse_coercer("[-] 10.0.0.5 is NOT vulnerable to PetitPotam (MS-EFSR)")) == 0)
    check("coercer dedupes per (host, method)",
          len(parse_coercer("10.0.0.10 EfsRpcOpenFileRaw ERROR_BAD_NETPATH\n"
                            "10.0.0.10 EfsRpcOpenFileRaw ERROR_BAD_NETPATH")) == 1)

    # aggregate over a temp run folder — MUST read PER-HOST auth_matrix_<host>.txt (regression guard)
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "parsdx"))
        open(os.path.join(d, "parsdx", "kerberoast.txt"), "w").write(krb)
        open(os.path.join(d, "parsdx", "auth_matrix_10.0.0.20.txt"), "w").write(nxc)
        open(os.path.join(d, "parsdx", "auth_matrix_10.0.0.21.txt"), "w").write(
            "SMB 10.0.0.21 445 SQL01 [+] corp.local\\svc:P (Pwn3d!)")
        allf = parse_run(d)
        types = [f["type"] for f in allf]
        check("parse_run reads per-host auth_matrix files (regression)",
              types.count("local_admin") == 2 and "kerberoast" in types)
        check("parse_run tags each finding with its real evidence file",
              all("evidence" in f and f["evidence"].startswith("parsdx/") for f in allf))

    total = 13
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    if len(sys.argv) == 2:
        import json
        print(json.dumps(parse_run(sys.argv[1]), indent=2, ensure_ascii=False))
    else:
        print("usage: parse.py <run_dir>  |  parse.py --self-test")
