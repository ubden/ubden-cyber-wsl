"""CVSS 3.1 scoring + chain-aware severity for the PARSDX report layer.

Two jobs the competitor report failed at:
  1. Give every finding a defensible CVSS vector + score (they had none).
  2. Escalate a CHAIN of findings that reaches Domain Admin to Critical, instead of
     scoring each link in isolation (their 10 Highs were really one Critical path).

CVSS 3.1 base math is implemented from the spec and self-tested against known vectors,
so it works with no third-party dependency. If RedHatProductSecurity/cvss is installed
we cross-check against it. Suggested vectors per finding type get us started; the analyst
adjusts.
"""
from __future__ import annotations

import math
import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """Official CVSS 3.1 roundup to one decimal."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def severity_band(score: float) -> str:
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict:
    """Parse a CVSS:3.1/AV:.../... string into a metric dict (base metrics only)."""
    parts = {}
    for chunk in vector.strip().split("/"):
        if ":" in chunk:
            k, _, v = chunk.partition(":")
            parts[k.upper()] = v.upper()
    return parts


def base_score(vector: str) -> tuple[float, str]:
    """Return (score, severity) for a CVSS 3.1 base vector string."""
    m = parse_vector(vector)
    try:
        av, ac, ui, s = AV[m["AV"]], AC[m["AC"]], UI[m["UI"]], m["S"]
        pr = (PR_C if s == "C" else PR_U)[m["PR"]]
        c, i, a = CIA[m["C"]], CIA[m["I"]], CIA[m["A"]]
    except KeyError as exc:
        raise ValueError(f"invalid/incomplete CVSS vector: {vector} ({exc})") from exc
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if s == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif s == "C":
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    return score, severity_band(score)


# Suggested base vectors per finding type (analyst confirms/adjusts).
TYPE_VECTORS = {
    "adcs_esc":        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",  # ESC1/ESC8 -> DA
    "dcsync":          "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "local_admin":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # cred (needs auth) opens host (Pwn3d!) -> 8.8
    "kerberoast":      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",  # crackable SPN -> credential exposure (aligned w/ asrep)
    "asrep_roast":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # offline crack -> credential exposure
    "unauth_smb":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # sensitive share read
    "weak_pw_policy":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "default_creds":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # Honest per-finding scores: a read-only coercion SCAN or a single credential recovery does NOT
    # by itself prove full-domain impact — that comes via the CHAIN. Score the demonstrated finding
    # conservatively (credential/relay exposure); chain_severity escalates when it actually reaches DA.
    "coercion":        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # coercible host (relay is a separate step)
    "gpp_password":    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # recovered credential from SYSVOL
}


def suggest(finding_type: str) -> dict:
    """Return {'cvss': vector, 'score': float, 'severity': band} for a known type."""
    vec = TYPE_VECTORS.get(finding_type)
    if not vec:
        return {"cvss": "", "score": 0.0, "severity": "None"}
    score, band = base_score(vec)
    return {"cvss": vec, "score": score, "severity": band}


def score_finding(finding: dict) -> dict:
    """Fill cvss/score/severity on a finding: use its vector if present, else suggest by type.
    Cross-checks with RedHat cvss lib when available. Mutates and returns the finding."""
    vec = finding.get("cvss")
    if vec:
        score, band = base_score(vec)
    else:
        s = suggest(finding.get("type", ""))
        vec, score, band = s["cvss"], s["score"], s["severity"]
    finding["cvss"] = vec
    finding["cvss_score"] = score
    finding["severity"] = (band or finding.get("severity", "")).lower() if band else finding.get("severity", "")
    # optional cross-check
    try:
        from cvss import CVSS3  # type: ignore
        if vec:
            lib = round(CVSS3(vec).scores()[0], 1)
            finding["cvss_lib_crosscheck"] = lib
    except Exception:  # noqa: BLE001 - lib optional
        pass
    return finding


def chain_severity(chain: list[dict], reached_da: bool) -> dict:
    """Score a kill chain. A chain that reaches Domain Admin is Critical regardless of the
    individual link scores — the point a shallow report misses. Otherwise take the max link,
    bumped one band if the chain has >=3 links (compounding exposure)."""
    link_scores = [f.get("cvss_score", 0.0) for f in chain]
    max_link = max(link_scores) if link_scores else 0.0
    if reached_da:
        score = max(9.0, max_link)  # full domain compromise WAS demonstrated (executed DCSync)
        rationale = ("Individual links may rate lower, but chained they yielded full Active "
                     "Directory (Domain Admin) compromise — scored as the realised, executed end state.")
    else:
        # No fake numeric bump (a "+1 for 3 links" has no CVSS basis). The chain score is the
        # strongest demonstrated link; the compounding risk is described in the narrative, not invented.
        score = max_link
        rationale = "Rated as the strongest individually-demonstrated link" + (
            f"; {len(chain)} findings chain together (see the attack narrative)." if len(chain) >= 2 else ".")
    return {"chain_score": round(score, 1), "chain_severity": severity_band(score),
            "reached_da": reached_da, "links": len(chain), "rationale": rationale}


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    # Known reference vectors.
    check("9.8 network RCE", base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (9.8, "Critical"))
    check("10.0 scope-changed full", base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == (10.0, "Critical"))
    check("7.8 local priv-esc", base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == (7.8, "High"))
    check("7.2 PR:H network", base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") == (7.2, "High"))
    check("5.9 conf-only high-AC", base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N") == (5.9, "Medium"))

    check("severity bands", (severity_band(0) == "None" and severity_band(3.9) == "Low"
                             and severity_band(6.9) == "Medium" and severity_band(8.9) == "High"
                             and severity_band(9.0) == "Critical"))

    # invalid vector rejected
    bad = False
    try:
        base_score("CVSS:3.1/AV:N/AC:L")
    except ValueError:
        bad = True
    check("incomplete vector raises", bad)

    # suggestions resolve
    s = suggest("adcs_esc")
    check("adcs_esc suggestion is Critical", s["severity"] == "Critical" and s["score"] >= 9.0)
    check("unauth_smb suggestion is High", suggest("unauth_smb")["severity"] == "High")
    check("local_admin is High 8.8 (PR:L, needs auth — not 9.8)", suggest("local_admin")["score"] == 8.8)
    check("kerberoast/asrep impact severity aligned",
          suggest("kerberoast")["severity"] == suggest("asrep_roast")["severity"] == "Medium")
    check("unknown type -> empty", suggest("nope")["cvss"] == "")

    # score_finding by explicit vector and by type
    f1 = score_finding({"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    check("score_finding by vector", f1["cvss_score"] == 9.8 and f1["severity"] == "critical")
    f2 = score_finding({"type": "kerberoast"})
    check("score_finding by type fills vector", f2["cvss"].startswith("CVSS:3.1") and f2["cvss_score"] > 0)

    # chain escalation
    chain = [{"cvss_score": 5.3}, {"cvss_score": 6.5}, {"cvss_score": 4.0}]
    cs = chain_severity(chain, reached_da=True)
    check("chain to DA is Critical", cs["chain_severity"] == "Critical" and cs["chain_score"] >= 9.0)
    cs2 = chain_severity(chain, reached_da=False)
    check("non-DA chain = strongest link (no invented bump)", cs2["chain_score"] == 6.5 and cs2["chain_severity"] == "Medium")

    total = 16
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(_self_test())
    if len(sys.argv) == 2:
        sc, band = base_score(sys.argv[1])
        print(f"{sys.argv[1]}\n  score: {sc}  severity: {band}")
    else:
        print("usage: score.py 'CVSS:3.1/AV:.../...'  |  score.py --self-test")
