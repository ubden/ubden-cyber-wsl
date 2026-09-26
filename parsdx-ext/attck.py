"""MITRE ATT&CK mapping + Navigator layer generation for the PARSDX report layer.

Findings carry a `technique` (an ATT&CK ID). This builds a Navigator layer JSON the client
can open in the ATT&CK Navigator, and auto-tags each finding with the technique name/tactic.
Works with no dependency (static metadata for the techniques we emit); if mitreattack-python
is installed it can enrich further, but is not required.
"""
from __future__ import annotations

import json
import sys

# Minimal metadata for the techniques our chain emits (id -> name, tactic).
TECHNIQUES = {
    "T1649":     ("Steal or Forge Authentication Certificates", "credential-access"),
    "T1558.003": ("Kerberoasting", "credential-access"),
    "T1558.004": ("AS-REP Roasting", "credential-access"),
    "T1078.002": ("Valid Accounts: Domain Accounts", "privilege-escalation"),
    "T1187":     ("Forced Authentication", "credential-access"),
    "T1003.006": ("OS Credential Dumping: DCSync", "credential-access"),
    "T1550.002": ("Pass the Hash", "lateral-movement"),
    "T1210":     ("Exploitation of Remote Services", "lateral-movement"),
    "T1069.002": ("Permission Groups Discovery: Domain Groups", "discovery"),
}


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, ("Unknown technique", "unknown"))[0]


def tag_findings(findings: list[dict]) -> list[dict]:
    """Add human-readable ATT&CK name/tactic to each finding that has a technique id."""
    for f in findings:
        tid = f.get("technique")
        if tid and tid in TECHNIQUES:
            name, tactic = TECHNIQUES[tid]
            f["attack_technique_name"] = name
            f["attack_tactic"] = tactic
    return findings


def build_layer(findings: list[dict], name: str = "PARSDX Engagement",
                description: str = "Techniques demonstrated during the assessment.") -> dict:
    """Build an ATT&CK Navigator layer (schema 4.5) scored by how many findings hit each technique."""
    counts: dict[str, int] = {}
    for f in findings:
        tid = f.get("technique")
        if tid:
            counts[tid] = counts.get(tid, 0) + 1
    techniques = []
    for tid, n in sorted(counts.items()):
        techniques.append({
            "techniqueID": tid,
            "score": n,
            "color": "#e60d0d",
            "comment": f"{technique_name(tid)} — {n} finding(s)",
            "enabled": True,
        })
    return {
        "name": name,
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "gradient": {"colors": ["#ffe766", "#e60d0d"], "minValue": 0,
                     "maxValue": max(counts.values()) if counts else 1},
        "legendItems": [{"label": "demonstrated", "color": "#e60d0d"}],
        "hideDisabled": True,
    }


def write_layer(findings: list[dict], out_path: str, **kw) -> str:
    layer = build_layer(findings, **kw)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2, ensure_ascii=False)
    return out_path


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    findings = [
        {"technique": "T1558.003"}, {"technique": "T1558.003"},
        {"technique": "T1649"}, {"technique": "T1078.002"},
        {"technique": None}, {"technique": "T9999"},
    ]
    tag_findings(findings)
    check("kerberoast tagged with name", findings[0]["attack_technique_name"] == "Kerberoasting")
    check("unknown technique not tagged", "attack_technique_name" not in findings[5])

    layer = build_layer(findings)
    ids = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    check("layer counts kerberoast twice", ids.get("T1558.003") == 2)
    check("layer has ADCS technique", "T1649" in ids)
    check("None technique excluded from layer", None not in ids)
    check("layer schema fields present", layer["domain"] == "enterprise-attack"
          and layer["versions"]["layer"] == "4.5")

    import tempfile, os
    p = os.path.join(tempfile.mkdtemp(), "layer.json")
    write_layer(findings, p)
    reloaded = json.load(open(p))
    check("layer writes valid json", reloaded["name"] == "PARSDX Engagement")

    total = 7
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
