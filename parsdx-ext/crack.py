"""Offline hash-cracking helper for kerberoast / AS-REP loot.

We collect roastable hashes; the natural next step (what linWinPwn/NetExec do) is to crack them
OFFLINE — no network, no lockout risk, entirely safe. This does NOT auto-run hashcat blindly:
it (1) extracts the collected hashes into ready-to-crack .hash files and prints the exact hashcat/
john commands, and (2) ingests the operator's crack results (hashcat `--show`) back into findings
as CRACKED credentials (a much stronger finding than "roastable").

    python3 crack.py <run_dir>                       # prepare .hash files + print crack commands
    python3 crack.py <run_dir> --results show.txt     # ingest cracked results -> findings JSON
    python3 crack.py --self-test
"""
from __future__ import annotations

import json
import os
import re
import sys

TGS_RE = re.compile(r"\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$*]+)\$")       # (user, realm)
ASREP_RE = re.compile(r"\$krb5asrep\$\d+\$([^@$\s]+)[@$]([^:@$\s]+)")  # (user, realm)
HASHLINE_RE = re.compile(r"(\$krb5(?:tgs|asrep)\$\S+)")

# hashcat modes
MODE = {"kerberoast": 13100, "asrep": 18200}


def extract(run_dir: str) -> dict:
    """Return {'kerberoast': [(account, hashline)], 'asrep': [...]} from collected evidence."""
    pdir = os.path.join(run_dir, "parsdx")
    out = {"kerberoast": [], "asrep": []}
    for kind, fname, rx in (("kerberoast", "kerberoast.txt", TGS_RE),
                            ("asrep", "asrep_roast.txt", ASREP_RE)):
        path = os.path.join(pdir, fname)
        if not os.path.isfile(path):
            continue
        for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
            hm = HASHLINE_RE.search(line)
            am = rx.search(line)
            if hm and am:
                out[kind].append((f"{am.group(2)}\\{am.group(1)}", hm.group(1)))
    return out


def prepare(run_dir: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> dict:
    """Write ready-to-crack .hash files and return the exact offline crack commands per kind."""
    data = extract(run_dir)
    hdir = os.path.join(run_dir, "parsdx", "hashes")
    os.makedirs(hdir, exist_ok=True)
    try:
        os.chmod(hdir, 0o700)
    except OSError:
        pass
    cmds = {}
    for kind, items in data.items():
        if not items:
            continue
        hf = os.path.join(hdir, f"{kind}.hash")
        with open(hf, "w", encoding="utf-8") as fh:
            fh.write("\n".join(h for _, h in items) + "\n")
        try:
            os.chmod(hf, 0o600)
        except OSError:
            pass
        cmds[kind] = {
            "count": len(items),
            "file": os.path.relpath(hf, run_dir),
            "hashcat": f"hashcat -m {MODE[kind]} {hf} {wordlist}",
            "hashcat_show": f"hashcat -m {MODE[kind]} {hf} --show",
            "john": f"john --format=krb5{'tgs' if kind=='kerberoast' else 'asrep'} --wordlist={wordlist} {hf}",
        }
    return cmds


def ingest_cracked(run_dir: str, show_file: str) -> list[dict]:
    """Read a hashcat `--show` (hash:password) output and turn each cracked hash into a finding.
    Maps the cracked hash back to its account using the collected evidence. OFFLINE only."""
    data = extract(run_dir)
    hash_to_account = {}
    for kind, items in data.items():
        for account, hashline in items:
            hash_to_account[hashline] = (kind, account)
    findings = []
    for line in open(show_file, encoding="utf-8", errors="replace").read().splitlines():
        if ":" not in line:
            continue
        # hashcat --show = "<hash>:<password>"; the hash itself contains ':' (SPN port), so split on
        # the LAST ':' to peel the password, THEN match the hash on the left part.
        left, pw = line.rsplit(":", 1)
        pw = pw.strip()
        hm = HASHLINE_RE.search(left)
        if not hm:
            continue
        hashline = hm.group(1)
        kind, account = hash_to_account.get(hashline, ("kerberoast", "?"))
        findings.append({
            "type": "cracked_credential",
            "title": f"Service-account password CRACKED offline: {account}",
            "asset": account,
            "technique": "T1110.002",  # Password Cracking
            "root_cause": "Weak password on a roastable account allowed offline recovery.",
            "description": f"The {kind} hash for '{account}' was cracked offline (no network / no lockout). "
                           "The account's cleartext password is now known.",
            "impact": "Attacker gains this account's privileges directly — often lateral movement or "
                      "privilege escalation toward Domain Admin.",
            "recommendation": "Set a 25+ character random password or migrate to a gMSA; rotate now.",
            "severity": "high",
            "cracked": True,
        })
    out = os.path.join(run_dir, "parsdx", "cracked.json")
    json.dump(findings, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    return findings


def _self_test() -> int:
    import tempfile
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    with tempfile.TemporaryDirectory() as d:
        pdir = os.path.join(d, "parsdx"); os.makedirs(pdir)
        open(os.path.join(pdir, "kerberoast.txt"), "w").write(
            "SPN row\n$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01*$deadbeef00\n"
            "$krb5tgs$18$websvc$CORP.LOCAL$*HTTP/web01*$aa11bb22\n")
        open(os.path.join(pdir, "asrep_roast.txt"), "w").write("$krb5asrep$18$jdoe$CORP.LOCAL$ccdd\n")

        ex = extract(d)
        check("extract kerberoast (RC4+AES) both", len(ex["kerberoast"]) == 2)
        check("extract asrep AES", len(ex["asrep"]) == 1 and ex["asrep"][0][0] == "CORP.LOCAL\\jdoe")

        cmds = prepare(d, wordlist="/wl.txt")
        check("hash files written", os.path.isfile(os.path.join(pdir, "hashes", "kerberoast.hash")))
        check("hashcat mode 13100 for kerberoast", "-m 13100" in cmds["kerberoast"]["hashcat"])
        check("hashcat mode 18200 for asrep", "-m 18200" in cmds["asrep"]["hashcat"])
        check("hash file 0600", oct(os.stat(os.path.join(pdir, "hashes", "kerberoast.hash")).st_mode)[-3:] == "600")

        # ingest a mock hashcat --show output
        show = os.path.join(d, "show.txt")
        open(show, "w").write("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01*$deadbeef00:Summer2026!\n")
        cracked = ingest_cracked(d, show)
        check("ingest maps cracked hash -> account", len(cracked) == 1 and cracked[0]["asset"] == "CORP.LOCAL\\svc_sql")
        check("cracked finding type + high sev", cracked[0]["type"] == "cracked_credential" and cracked[0]["severity"] == "high")

    total = 8
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


def main(argv=None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--self-test" in args:
        return _self_test()
    if not args:
        print("usage: crack.py <run_dir> [--results show.txt] | crack.py --self-test"); return 0
    run_dir = args[0]
    if "--results" in args:
        sf = args[args.index("--results") + 1]
        c = ingest_cracked(run_dir, sf)
        print(f"ingested {len(c)} cracked credential(s) -> parsdx/cracked.json")
        return 0
    cmds = prepare(run_dir)
    if not cmds:
        print("no kerberoast/asrep hashes collected yet (run the offensive pass first)."); return 0
    print("# Ready-to-crack hash files written under parsdx/hashes/. Run OFFLINE with your wordlist:")
    for kind, c in cmds.items():
        print(f"\n[{kind}] {c['count']} hash(es) -> {c['file']}")
        print(f"  {c['hashcat']}")
        print(f"  (then: {c['hashcat_show']}  -> save to show.txt)")
    print("\n# Feed results back in:  python3 crack.py <run_dir> --results show.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
