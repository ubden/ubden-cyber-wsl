"""Fold PARSDX findings back into UBDEN's report.

Maps our normalized+scored findings to UBDEN's finding schema and writes them into
`review.json['findings']`. To land as VERIFIED (not draft), UBDEN requires: status
'doğrulandı', the 7 required text fields non-empty, and the evidence file present in-run
with a matching SHA-256 (see analyst_review.verified_finding). We satisfy all of that when
the evidence file exists; otherwise we write it as 'taslak' (draft) honestly.

After writing, run `report_v2.py <run_dir>` to regenerate the PDFs/HTML with our findings.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

_REQUIRED = ("title", "asset", "description", "impact", "recommendation", "reproduction", "reviewed_by")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def to_ubden_finding(f: dict, run_dir: str, idx: int) -> dict:
    """Map a normalized PARSDX finding to UBDEN's finding schema."""
    evidence_rel = f.get("evidence", "")
    evidence_abs = os.path.join(run_dir, evidence_rel) if evidence_rel else ""
    # Mirror UBDEN's verified_finding/evidence() gate so we never mark 'verified' something report_v2
    # will silently demote: real file, no symlink, not absolute, no '..', <= 25 MB.
    have_evidence = bool(evidence_rel) and os.path.isfile(evidence_abs) and not os.path.islink(evidence_abs) \
        and not os.path.isabs(evidence_rel) and ".." not in evidence_rel.replace("\\", "/").split("/")
    if have_evidence:
        try:
            have_evidence = os.path.getsize(evidence_abs) <= 25 * 1024 * 1024
        except OSError:
            have_evidence = False
    reproduction = (f.get("reproduction")
                    or (f"Kanıt dosyası: {evidence_rel}. " if evidence_rel else "")
                    + f.get("description", ""))
    finding = {
        "id": f"PX-{idx:03d}",
        "title": f.get("title", "Başlıksız bulgu"),
        "severity": (f.get("severity") or "info").lower(),
        "status": "taslak",
        "asset": f.get("asset", ""),
        "affected_assets": f.get("affected_assets", []),
        "description": f.get("description", ""),
        "impact": f.get("impact", ""),
        "recommendation": f.get("recommendation", ""),
        "evidence": evidence_rel,
        "evidence_sha256": _sha256(evidence_abs) if have_evidence else "",
        "evidence_items": [],
        "reference": f.get("reference", ""),
        "cvss": f.get("cvss", ""),
        "reproduction": reproduction,
        "reviewed_by": "PARSDX",
        "category": f.get("category", "Active Directory"),
        "access_point": f.get("access_point", "İç Ağ"),
        "user_profile": f.get("user_profile", "Kurum Çalışanı / düşük yetkili"),
        "root_cause": f.get("root_cause", ""),
        "remediation_priority": f.get("remediation_priority", ""),
        "retest_status": "",
        "disposition_reason": "",
        "attack_technique": f.get("technique", ""),
        "attack_technique_name": f.get("attack_technique_name", ""),
    }
    # Promote to verified only if evidence is real and all required fields are filled.
    if have_evidence and all(finding.get(k) for k in _REQUIRED):
        finding["status"] = "doğrulandı"
    return finding


def load_review(run_dir: str) -> dict:
    path = os.path.join(run_dir, "review.json")
    try:
        data = json.load(open(path, encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("findings", [])
            return data
    except (OSError, ValueError):
        pass
    return {"schema": 3, "analyst_summary": "", "reviewer": "PARSDX",
            "approved_at": "", "cases": [], "findings": []}


def emit_findings(run_dir: str, findings: list[dict]) -> dict:
    """Write findings into review.json (dedupe by title). Returns counts."""
    review = load_review(run_dir)
    existing = {f.get("title") for f in review.get("findings", []) if isinstance(f, dict)}
    start = len(review["findings"])
    verified = added = 0
    for f in findings:
        if f.get("title") in existing:
            continue
        uf = to_ubden_finding(f, run_dir, start + added + 1)
        review["findings"].append(uf)
        existing.add(uf["title"])
        added += 1
        if uf["status"] == "doğrulandı":
            verified += 1
    os.umask(0o077)
    rpath = os.path.join(run_dir, "review.json")
    with open(rpath, "w", encoding="utf-8") as fh:
        json.dump(review, fh, indent=2, ensure_ascii=False)
    try:
        os.chmod(rpath, 0o600)  # review.json can hold sensitive finding detail
    except OSError:
        pass
    return {"added": added, "verified": verified, "draft": added - verified,
            "total_in_review": len(review["findings"])}


def regenerate_report(run_dir: str) -> int:
    """Re-run UBDEN's report_v2.py to fold our findings into the PDFs/HTML."""
    report = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report_v2.py")
    if not os.path.exists(report):
        print(f"[emit] report_v2.py not found at {report}; skipping regen")
        return 1
    return subprocess.run([sys.executable, report, run_dir]).returncode


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "parsdx"))
        ev = os.path.join(d, "parsdx", "kerberoast.txt")
        open(ev, "w").write("$krb5tgs$23$*svc_sql$CORP.LOCAL$...")
        f_with = {"type": "kerberoast", "title": "Kerberoastable: svc_sql", "asset": "CORP\\svc_sql",
                  "description": "d", "impact": "i", "recommendation": "r", "root_cause": "rc",
                  "severity": "high", "cvss": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                  "evidence": "parsdx/kerberoast.txt", "technique": "T1558.003"}
        f_noev = {"type": "asrep_roast", "title": "AS-REP: jdoe", "asset": "CORP\\jdoe",
                  "description": "d", "impact": "i", "recommendation": "r", "severity": "high",
                  "evidence": "parsdx/missing.txt"}
        res = emit_findings(d, [f_with, f_noev])
        check("both findings added", res["added"] == 2)
        check("one verified (has evidence)", res["verified"] == 1)
        check("one draft (missing evidence)", res["draft"] == 1)

        review = json.load(open(os.path.join(d, "review.json")))
        byid = {f["id"]: f for f in review["findings"]}
        v = byid["PX-001"]
        check("verified finding status doğrulandı", v["status"] == "doğrulandı")
        check("evidence_sha256 matches file", v["evidence_sha256"] == _sha256(ev))
        check("required fields filled + reviewed_by PARSDX", all(v[k] for k in _REQUIRED) and v["reviewed_by"] == "PARSDX")
        check("draft finding is taslak", byid["PX-002"]["status"] == "taslak")

        # idempotent: re-emit same titles doesn't duplicate
        res2 = emit_findings(d, [f_with, f_noev])
        check("dedupe by title on re-emit", res2["added"] == 0)

    total = 8
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
