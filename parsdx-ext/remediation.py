"""Prioritized remediation roadmap (Turkish, client-facing).

A shallow report lists findings and gives generic advice. A good one tells the client WHAT TO FIX
FIRST. This groups findings by root cause, ranks by severity, flags quick wins, and writes a
"Düzeltme Yol Haritası" the client's IT can act on in order.
"""
from __future__ import annotations

import os
import sys

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "info": 0, "": 0}

# Finding types that are cheap to fix AND high impact = "quick wins".
_QUICK_WIN_TYPES = {"default_creds", "unauth_smb", "gpp_password", "weak_pw_policy", "asrep_roast"}


def _sev(f):
    return _SEV_RANK.get((f.get("severity") or "").lower(), 0)


def build_roadmap(findings: list[dict]) -> dict:
    """Group findings by root cause, ranked most-severe first."""
    groups: dict[str, dict] = {}
    for f in findings:
        # group key = recommendation (the fix) so findings sharing one fix collapse into one action
        key = (f.get("recommendation") or f.get("root_cause") or f.get("type") or "other").strip()
        g = groups.setdefault(key, {"fix": key, "max_sev": 0, "count": 0, "assets": [],
                                     "types": set(), "techniques": set()})
        g["max_sev"] = max(g["max_sev"], _sev(f))
        g["count"] += 1
        if f.get("asset"):
            g["assets"].append(f["asset"])
        if f.get("type"):
            g["types"].add(f["type"])
        if f.get("technique"):
            g["techniques"].add(f["technique"])
    ordered = sorted(groups.values(), key=lambda g: (-g["max_sev"], -g["count"]))
    quick = [f for f in findings if (f.get("type") in _QUICK_WIN_TYPES) or _sev(f) >= 3]
    return {"actions": ordered, "quick_wins": quick, "total_findings": len(findings)}


_SEV_LABEL = {4: "Kritik", 3: "Yüksek", 2: "Orta", 1: "Düşük", 0: "Bilgi"}


def render_markdown(roadmap: dict) -> str:
    lines = ["# Öncelikli Düzeltme Yol Haritası", "",
             f"Toplam {roadmap['total_findings']} bulgu, kök nedene göre {len(roadmap['actions'])} eyleme "
             "gruplandı. Yukarıdan aşağıya öncelik sırasıyla kapatın.", "",
             "| # | Öncelik | Eylem (düzeltme) | Etkilenen | Bulgu |", "|---|---|---|---|---|"]
    for i, a in enumerate(roadmap["actions"], 1):
        assets = ", ".join(sorted(set(a["assets"]))[:4]) + ("…" if len(set(a["assets"])) > 4 else "")
        fix = a["fix"].replace("|", "/")
        lines.append(f"| {i} | {_SEV_LABEL[a['max_sev']]} | {fix[:110]} | {assets or '-'} | {a['count']} |")
    if roadmap["quick_wins"]:
        lines += ["", "## Hızlı Kazanımlar (önce bunlar — düşük emek, yüksek etki)"]
        seen = set()
        for f in roadmap["quick_wins"]:
            t = f.get("title", "")
            if t in seen:
                continue
            seen.add(t)
            lines.append(f"- **{t}** → {(f.get('recommendation') or '').split('.')[0]}.")
    return "\n".join(lines)


def write_roadmap(findings: list[dict], out_path: str) -> str:
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(build_roadmap(findings)))
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    return out_path


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    findings = [
        {"type": "adcs_esc", "severity": "critical", "asset": "UserAuth",
         "recommendation": "Restrict template enrollment + remove enrollee-supplied subject.", "technique": "T1649"},
        {"type": "local_admin", "severity": "high", "asset": "10.0.0.20",
         "recommendation": "Enforce LAPS (unique local-admin passwords)."},
        {"type": "local_admin", "severity": "high", "asset": "10.0.0.21",
         "recommendation": "Enforce LAPS (unique local-admin passwords)."},
        {"type": "kerberoast", "severity": "medium", "asset": "CORP\\svc_sql",
         "recommendation": "Use 25+ char passwords or gMSA for service accounts."},
    ]
    rm = build_roadmap(findings)
    check("groups by shared fix (2 local_admin -> 1 action)",
          any(a["count"] == 2 and "LAPS" in a["fix"] for a in rm["actions"]))
    check("most-severe action first (Critical ADCS)", rm["actions"][0]["max_sev"] == 4)
    check("total findings counted", rm["total_findings"] == 4)
    check("quick wins include high-sev items", len(rm["quick_wins"]) >= 1)
    md = render_markdown(rm)
    check("markdown has roadmap table", "Öncelikli Düzeltme Yol Haritası" in md and "| 1 |" in md)
    check("severity labels in Turkish", "Kritik" in md)

    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "REMEDIATION.md")
    write_roadmap(findings, p)
    check("writes file", os.path.exists(p))
    check("empty findings safe", build_roadmap([])["total_findings"] == 0)

    total = 8
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
