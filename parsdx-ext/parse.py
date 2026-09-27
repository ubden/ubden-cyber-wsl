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


# Groups that already hold the privilege an ESC would grant. "Enterprise Admins can rewrite a
# template" is not a finding -- it is what Enterprise Admins are. certipy cannot know this and
# flags it anyway, so the filtering has to happen here.
PRIVILEGED_PRINCIPALS = (
    "domain admins", "enterprise admins", "administrators", "domain controllers",
    "enterprise domain controllers", "system", "enterprise read-only domain controllers",
)

# ESC classes are not one severity. Direct = a low-privileged enrollment yields a certificate that
# authenticates as a privileged principal. Chain = a further step is required. ACL = the finding is
# "this object is writable", whose weight depends on who can write it.
ESC_KIND = {
    "ESC1": "direct", "ESC6": "direct", "ESC8": "direct", "ESC11": "direct",
    "ESC2": "chain", "ESC3": "chain", "ESC9": "chain", "ESC10": "chain",
    "ESC13": "chain", "ESC14": "chain", "ESC15": "chain", "ESC16": "chain", "ESC17": "chain",
    "ESC4": "acl", "ESC5": "acl", "ESC7": "acl",
}
# ESC4 is "this template can be REWRITTEN by someone who should not be able to". The rights that
# grant that are ownership and DACL/owner/generic writes. "Write Property Enroll" is NOT one of
# them -- it is the enrollment permission expressed as a property write, and including it turned
# three stock templates (Machine/EFS/User, enrollable by Domain Computers/Domain Users as designed)
# into High findings. Measured 2026-09-27.
_CTRL_HEADERS = ("Owner", "Full Control Principals", "Write Owner Principals",
                 "Write Dacl Principals", "Write Property Principals")


def _principals(block: str, header: str) -> list[str]:
    """certipy prints a principal list as one value line plus deeply-indented continuation lines."""
    m = re.search(rf"{re.escape(header)}\s*:\s*(.+(?:\n\s{{28,}}\S.*)*)", block)
    if not m:
        return []
    return [x.strip() for x in m.group(1).split("\n") if x.strip()]


def _unprivileged(principals: list[str]) -> list[str]:
    return [p for p in principals
            if not any(k in p.lower() for k in PRIVILEGED_PRINCIPALS)]


def parse_certipy(text: str) -> list[dict]:
    """certipy find -vulnerable -stdout -> findings, with the noise separated from the vulnerability.

    A stock CA makes certipy shout. Measured 2026-09-27 against a freshly installed Windows Server
    2025 Enterprise CA: 47 ESC lines, of which 23 sat on DISABLED templates (cannot be enrolled at
    all), 12 were ESC4 "template is owned by user" where the owner is Enterprise Admins, and 7 were
    enrollable only by privileged groups. Exactly ONE -- the ESC1 we deliberately planted -- was
    reachable by a low-privileged user. Emitting all 47 as Critical is severity inflation that would
    destroy a client report, so each ESC is classified by (a) whether the template is enabled and
    (b) whether a NON-privileged principal actually holds the right the ESC depends on.
    Nothing is discarded: what is filtered out is summarised in one hygiene finding and the full
    certipy output stays in the evidence file.
    """
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    findings = []
    suppressed = {"disabled": [], "privileged_only": []}

    for block in re.split(r"(?=^\s*(?:Template Name|CA Name)\s+:)", text, flags=re.M):
        escs = re.findall(r"\b(ESC\d+)\b\s*:\s*(.+)", block)
        if not escs:
            continue
        tm = re.search(r"Template Name\s*:\s*(.+)", block)
        cm = re.search(r"CA Name\s*:\s*(.+)", block)
        name = (tm or cm).group(1).strip() if (tm or cm) else "AD CS"
        is_ca = tm is None and cm is not None
        enabled = (re.search(r"Enabled\s*:\s*(\w+)", block) or [None, "True"])[1]

        enroll_unpriv = _unprivileged(_principals(block, "Enrollment Rights"))
        ctrl = []
        for h in _CTRL_HEADERS:
            ctrl += _principals(block, h)
        ctrl_unpriv = _unprivileged(ctrl)

        for esc, detail in escs:
            detail = detail.strip()
            kind = ESC_KIND.get(esc, "chain")

            # A disabled template cannot be enrolled, so no ESC on it is reachable.
            if not is_ca and enabled == "False":
                suppressed["disabled"].append(f"{name}:{esc}")
                continue
            # The right the ESC depends on is held only by principals who are already privileged.
            # ⚠️ Suppress ONLY on positive evidence. If certipy printed no principal list at all we
            # cannot tell who holds the right, and "no data" must never read as "not exploitable" --
            # that is the silent-zero failure this whole toolkit exists to avoid. Keep the finding.
            holders = ctrl if kind == "acl" else _principals(block, "Enrollment Rights")
            holder_unpriv = ctrl_unpriv if kind == "acl" else enroll_unpriv
            if holders and not holder_unpriv:
                suppressed["privileged_only"].append(f"{name}:{esc}")
                continue

            ftype = {"direct": "adcs_esc_direct", "chain": "adcs_esc_chain",
                     "acl": "adcs_esc_acl"}[kind]
            who = ", ".join(sorted(set(holder_unpriv))[:3]) or "principals not reported by certipy"
            findings.append({
                "type": ftype,
                "title": f"AD CS {esc} on {'CA' if is_ca else 'template'} '{name}'",
                "asset": name,
                "technique": "T1649",  # Steal or Forge Authentication Certificates
                "root_cause": f"{esc}: {detail}",
                "description": f"Certipy flagged {esc} on {'CA' if is_ca else 'template'} '{name}': "
                               f"{detail} " + (
                                   f"The right this depends on is held by a non-privileged principal "
                                   f"({who}), so it is reachable by an ordinary domain user."
                                   if holder_unpriv else
                                   "Certipy did not report which principals hold this right, so it "
                                   "could NOT be ruled out - verify the ACL by hand."),
                "impact": "A low-privileged user can obtain a certificate that authenticates as a "
                          "privileged principal, leading to domain privilege escalation."
                          if kind == "direct" else
                          "The flagged object can be abused toward privileged certificate issuance; "
                          "a further step is required to reach domain compromise.",
                "recommendation": "Remove enrollee-supplied-subject or the client-authentication "
                                  "EKU, restrict enrollment and object-control rights to "
                                  "administrative groups, and enable manager approval.",
                "evidence_principals": sorted(set(holder_unpriv)),
            })

    n_dis, n_priv = len(suppressed["disabled"]), len(suppressed["privileged_only"])
    if n_dis or n_priv:
        findings.append({
            "type": "adcs_hygiene",
            "title": f"AD CS: {n_dis + n_priv} certipy flags not reachable by a low-privileged user",
            "asset": "AD CS",
            "technique": "T1649",
            "root_cause": "certipy flags every ESC condition regardless of whether an unprivileged "
                          "principal can reach it.",
            "description": f"{n_dis} flag(s) sit on DISABLED templates (they cannot be enrolled) and "
                           f"{n_priv} are held only by already-privileged groups (Domain/Enterprise "
                           f"Admins). Listed for completeness, not as exploitable findings. "
                           f"Disabled: {', '.join(suppressed['disabled'][:8])}"
                           f"{' ...' if n_dis > 8 else ''}. "
                           f"Privileged-only: {', '.join(suppressed['privileged_only'][:8])}"
                           f"{' ...' if n_priv > 8 else ''}.",
            "impact": "No direct impact: an attacker without existing privilege cannot use these.",
            "recommendation": "Remove or disable unused templates and review ownership during "
                              "routine AD CS hygiene.",
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

    # Fixture shaped like real `certipy find -vulnerable -stdout` on a stock Enterprise CA:
    # one genuinely reachable ESC1, one disabled template, one ESC4 owned only by Enterprise Admins.
    certipy = """Certificate Templates
  0
    Template Name                       : UserAuth
    Enabled                             : True
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CORP.LOCAL\\Domain Users
      Object Control Permissions
        Owner                           : CORP.LOCAL\\Enterprise Admins
    [!] Vulnerabilities
      ESC1                              : 'CORP.LOCAL\\Domain Users' can enroll and supply subject
  1
    Template Name                       : OldWebServer
    Enabled                             : False
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CORP.LOCAL\\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject
  2
    Template Name                       : Machine
    Enabled                             : True
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CORP.LOCAL\\Domain Computers
      Object Control Permissions
        Owner                           : CORP.LOCAL\\Enterprise Admins
        Write Dacl Principals           : CORP.LOCAL\\Domain Admins
                                          CORP.LOCAL\\Enterprise Admins
        Write Property Enroll           : CORP.LOCAL\\Domain Computers
    [!] Vulnerabilities
      ESC4                              : Template is owned by user.
"""
    cf = parse_certipy(certipy)
    real = [f for f in cf if f["type"] != "adcs_hygiene"]
    hyg = [f for f in cf if f["type"] == "adcs_hygiene"]
    check("certipy: only the reachable ESC1 is a finding", len(real) == 1 and real[0]["asset"] == "UserAuth")
    check("certipy: ESC1 typed as direct (Critical)", real[0]["type"] == "adcs_esc_direct")
    check("certipy: ATT&CK T1649", real[0]["technique"] == "T1649")
    check("certipy: disabled template suppressed", "OldWebServer:ESC1" in hyg[0]["description"])
    check("certipy: ESC4 owned only by admins suppressed", "Machine:ESC4" in hyg[0]["description"])
    check("certipy: 'Write Property Enroll' is NOT template control",
          all("Machine" not in f["asset"] for f in real))
    check("certipy: suppressed ones are reported, not hidden", len(hyg) == 1 and "2 certipy flags" in hyg[0]["title"])
    # No principal list at all must NOT read as "not exploitable" -- keep it and say so.
    bare = parse_certipy("    Template Name : UserAuth\n      ESC1 : enrollee supplies subject")
    bare_real = [f for f in bare if f["type"] != "adcs_hygiene"]
    check("certipy: missing principal data keeps the finding (no silent drop)", len(bare_real) == 1)
    check("certipy: says the ACL could not be ruled out", "could NOT be ruled out" in bare_real[0]["description"])

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

    total = 19
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
