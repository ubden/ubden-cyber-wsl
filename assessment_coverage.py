"""Evidence-led coverage ledger for a single authorized assessment.

An installed tool or selected module never counts as a completed control.
Only recorded execution steps and analyst evidence can change coverage state.
"""
from __future__ import annotations

import json
from pathlib import Path


CONTROLS = (
    ("NET-DISC", "Ağ", "Host keşfi", ("discovery_hosts", "discovery_summary", "icmp_probe")),
    ("NET-PORT", "Ağ", "TCP servis ve sürüm tespiti", ("port_discovery", "nmap_")),
    ("NET-PROTO", "Ağ", "Servis protokol kontrolleri", ("audit_",)),
    ("NET-SNMP", "Ağ", "SNMP yapılandırması", ("snmp_v1_public",)),
    ("WEB-HTTP", "Web", "HTTP başlıkları", ("headers_",)),
    ("WEB-METHOD", "Web", "HTTP yöntemleri", ("methods_",)),
    ("WEB-TLS", "Web", "TLS protokolü ve şifre takımları", ("tls_", "cidr_tls_")),
    ("WEB-NIKTO", "Web", "Web yapılandırma taraması", ("nikto_",)),
    ("WEB-TEMPLATE", "Web", "Şablon tabanlı kontroller", ("nuclei_",)),
    ("AUTH-SESSION", "Kimlik", "Test hesabıyla erişim karşılaştırması", ("auth_",)),
    ("AUTH-ROLE", "Kimlik", "Rol ve nesne erişimi karşılaştırması", ("role_",)),
    ("AUTH-SSH", "Kimlik", "SSH test hesabı parola kontrolü", ("ssh_password_",)),
    ("AD-READ", "Etki alanı", "Salt okunur AD envanteri", ("ad_assessment",)),
    ("BROWSER", "Web", "Ayrı test tarayıcısı", ("browser_",)),
    ("WIFI", "Kablosuz", "802.11 donanım ve görev kontrolleri", ("wireless_",)),
)

SUCCESS = {"ok", "completed"}
SKIPPED = {"skipped", "excluded", "not_applicable", "missing_tool", "not_selected"}


def _steps_for(steps, prefixes):
    return [step for step in steps if isinstance(step, dict) and any(
        str(step.get("step", "")).startswith(prefix) for prefix in prefixes)]


def _status(matched):
    if not matched:
        return "kayıt yok"
    successes = sum(str(item.get("status", "")).lower() in SUCCESS for item in matched)
    failed = sum(str(item.get("status", "")).lower() not in SUCCESS | SKIPPED for item in matched)
    if successes and failed:
        return "kısmi"
    if successes:
        return "çalıştı"
    if failed:
        return "tamamlanamadı"
    return "atlandı"


def build_coverage(root: Path, meta: dict, steps: list, review: dict) -> dict:
    """Produce a truthful coverage summary from actual events and manual records."""
    rows = []
    for code, group, title, prefixes in CONTROLS:
        matched = _steps_for(steps, prefixes)
        rows.append({
            "id": code, "group": group, "title": title, "source": "otomatik",
            "status": _status(matched), "executed": sum(
                str(s.get("status", "")).lower() in SUCCESS for s in matched),
            "attempted": len(matched),
            "reason": "; ".join(str(s.get("detail") or s.get("reason") or s.get("status") or "")[:180]
                               for s in matched if str(s.get("status", "")).lower() not in SUCCESS)[:500],
            "evidence": [str(s.get("output")) for s in matched if s.get("output")][:12],
        })
    for case in review.get("cases", []):
        if not isinstance(case, dict):
            continue
        state = str(case.get("state", "bekliyor"))
        proof = str(case.get("evidence", ""))
        digest = str(case.get("sha256", ""))
        valid_proof = False
        if state in ("test edildi", "bulgu") and proof and digest:
            try:
                from analyst_review import evidence
                valid_proof = evidence(root, proof) == digest
            except ValueError:
                pass
        status = ("çalıştı" if valid_proof else "tamamlanamadı" if state in ("test edildi", "bulgu")
                  else "atlandı" if state == "uygulanamaz" else "kayıt yok")
        rows.append({"id": "MAN-" + str(case.get("id", "?")), "group": "Analist",
                     "title": str(case.get("title", "")), "source": "manuel", "status": status,
                     "executed": int(valid_proof), "attempted": int(state != "bekliyor"),
                     "reason": str(case.get("note", ""))[:500], "evidence": [proof] if valid_proof else []})
    counts = {status: sum(row["status"] == status for row in rows)
              for status in ("çalıştı", "kısmi", "tamamlanamadı", "atlandı", "kayıt yok")}
    return {"schema": 1, "engagement_id": str(meta.get("id", "")), "counts": counts,
            "meaning": "Çalıştı, yalnız kayıtlı adımın yürütüldüğünü gösterir; güvenlik açığı doğrulaması değildir.",
            "controls": rows}


def write_coverage(root: Path, meta: dict, steps: list, review: dict) -> dict:
    result = build_coverage(root, meta, steps, review)
    destination = root / "ASSESSMENT_COVERAGE.json"
    temp = root / ".ASSESSMENT_COVERAGE.pending.json"
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(destination)
    return result
