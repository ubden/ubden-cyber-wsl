"""Coverage matrix for the PARSDX report layer.

Beats a "wide but shallow" competitor report by declaring, up front, every check a proper
internal AD/network assessment should cover, then marking each tested / passed / skipped by
cross-referencing the executed step events (UBDEN steps.json + our parsdx_steps.json).
Shows thoroughness explicitly instead of an undocumented pile of scan output.
"""
from __future__ import annotations

import json
import os
import sys

# id, category, title, step-name prefixes (from UBDEN + parsdx) that satisfy the check.
CHECKS = [
    ("NET-01", "Network", "Host discovery", ["discover", "nmap_sn", "discovery"]),
    ("NET-02", "Network", "Port & service enumeration", ["nmap", "port_"]),
    ("NET-03", "Network", "TLS/SSL configuration", ["tls_", "ssl", "sslscan", "audit_ssl"]),
    ("NET-04", "Network", "SNMP exposure", ["snmp"]),
    ("NET-05", "Network", "SMB exposure / signing", ["nbtscan", "smb", "auth_matrix", "share_triage"]),
    ("WEB-01", "Web", "HTTP headers & methods", ["headers_", "methods_"]),
    ("WEB-02", "Web", "Web vuln scan (nuclei/nikto)", ["nuclei", "nikto"]),
    ("AD-01", "Active Directory", "Domain/DC inventory", ["ad_", "AD_ASSESSMENT", "bloodhound"]),
    ("AD-02", "Active Directory", "Password/lockout policy", ["lockout", "pass_pol", "policy"]),
    ("AD-03", "Active Directory", "Kerberoasting", ["kerberoast"]),
    ("AD-04", "Active Directory", "AS-REP roasting", ["asrep"]),
    ("AD-05", "Active Directory", "Attack-path analysis (BloodHound)", ["bloodhound"]),
    ("AD-06", "Active Directory", "AD CS (certificate services) abuse", ["adcs", "certipy"]),
    ("AD-07", "Active Directory", "Authentication coercion exposure", ["coerce", "coercer"]),
    ("AD-08", "Active Directory", "Local-admin / credential reuse map", ["auth_matrix", "pwn"]),
    ("AD-09", "Active Directory", "Share secret hunting", ["share_triage", "spider", "snaffler"]),
    ("CRED-01", "Credentials", "Credentialed access validation", ["ssh_password", "auth_matrix"]),
]

_DONE_STATUSES = {"ok", "completed", "success", "attempted"}


def _load_steps(run_dir: str) -> list[dict]:
    steps = []
    for rel in ("steps.json", os.path.join("parsdx", "parsdx_steps.json")):
        path = os.path.join(run_dir, rel)
        data = None
        try:
            data = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, list):
            steps.extend(data)
    return steps


def build_matrix(run_dir: str) -> dict:
    steps = _load_steps(run_dir)
    executed = [(str(s.get("step", "")).lower(), str(s.get("status", "")).lower())
                for s in steps if isinstance(s, dict)]
    rows = []
    for cid, cat, title, prefixes in CHECKS:
        hits = [(name, st) for name, st in executed if any(name.startswith(p.lower()) for p in prefixes)]
        if not hits:
            status = "skipped"
        elif any(st in _DONE_STATUSES for _, st in hits):
            status = "tested"
        else:
            status = "attempted"
        rows.append({"id": cid, "category": cat, "title": title, "status": status,
                     "evidence_steps": [n for n, _ in hits]})
    tallies = {}
    for r in rows:
        tallies[r["status"]] = tallies.get(r["status"], 0) + 1
    return {"schema": 1, "total_checks": len(CHECKS), "tallies": tallies, "checks": rows}


def render_markdown(matrix: dict) -> str:
    lines = ["## Kapsam Matrisi (Coverage Matrix)", "",
             f"Toplam kontrol: {matrix['total_checks']} — " +
             ", ".join(f"{k}: {v}" for k, v in sorted(matrix["tallies"].items())), "",
             "| ID | Kategori | Kontrol | Durum |", "|---|---|---|---|"]
    label = {"tested": "✅ Test edildi", "attempted": "⚠️ Denendi", "skipped": "⬜ Kapsam dışı/atlandı"}
    for r in matrix["checks"]:
        lines.append(f"| {r['id']} | {r['category']} | {r['title']} | {label.get(r['status'], r['status'])} |")
    return "\n".join(lines)


def write_matrix(run_dir: str) -> tuple[str, str]:
    matrix = build_matrix(run_dir)
    pdir = os.path.join(run_dir, "parsdx")
    os.makedirs(pdir, exist_ok=True)
    jpath = os.path.join(pdir, "COVERAGE_MATRIX.json")
    mpath = os.path.join(pdir, "COVERAGE_MATRIX.md")
    json.dump(matrix, open(jpath, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    open(mpath, "w", encoding="utf-8").write(render_markdown(matrix))
    return jpath, mpath


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        json.dump([{"step": "nmap_10.0.0.10", "status": "ok"},
                   {"step": "tls_10.0.0.10", "status": "ok"},
                   {"step": "nuclei_web", "status": "ok"}],
                  open(os.path.join(d, "steps.json"), "w"))
        os.makedirs(os.path.join(d, "parsdx"))
        json.dump([{"step": "kerberoast", "status": "ok"},
                   {"step": "adcs_find", "status": "ok"},
                   {"step": "coerce_scan", "status": "error"}],
                  open(os.path.join(d, "parsdx", "parsdx_steps.json"), "w"))
        m = build_matrix(d)
        byid = {r["id"]: r for r in m["checks"]}
        check("port scan tested", byid["NET-02"]["status"] == "tested")
        check("kerberoast tested from parsdx", byid["AD-03"]["status"] == "tested")
        check("adcs tested", byid["AD-06"]["status"] == "tested")
        check("coercion errored -> attempted", byid["AD-07"]["status"] == "attempted")
        check("snmp not run -> skipped", byid["NET-04"]["status"] == "skipped")
        check("tallies sum to total", sum(m["tallies"].values()) == m["total_checks"])
        md = render_markdown(m)
        check("markdown renders table", "Kapsam Matrisi" in md and "| AD-03 |" in md)
        jp, mp = write_matrix(d)
        check("writes json+md", os.path.exists(jp) and os.path.exists(mp))

    total = 8
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
