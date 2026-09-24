"""Human assessment ledger. No requests are made to a customer system here."""
import datetime as dt
import hashlib
import json
from pathlib import Path

LEGACY_CASES = (
    ("AUTH", "Kimlik doğrulama ve oturum yaşam döngüsü"),
    ("ROLES", "Dikey yetki: farklı roller ve yönetici işlemleri"),
    ("IDOR", "Yatay yetki: yalnızca test hesaplarına ait nesneler"),
    ("INPUT", "Girdi doğrulama ve çıktı kodlama"),
    ("API", "API uçları ve yetki matrisi"),
    ("LOGIC", "İş akışları ve iş kuralları"),
    ("CONFIG", "Yapılandırma, bileşenler ve servis maruziyeti"),
    ("RETEST", "Bulguları tekrar üretme ve düzeltme doğrulaması"),
)
CASES = LEGACY_CASES + (
    ("SCOPE", "Kapsam, erişim yolları ve hariçlerin doğrulanması"),
    ("ASSET", "Varlık rolleri, sahibi ve ağ segmenti doğrulaması"),
    ("AD", "Etki alanı, ayrıcalıklı gruplar ve yetki sınırları"),
    ("AD-POLICY", "Parola, kilitlenme ve kimlik doğrulama ilkeleri"),
    ("SHARES", "SMB/NFS paylaşımları ve erişim izinleri"),
    ("DATABASE", "Veritabanı erişimi, sürümü ve yapılandırması"),
    ("PATCH", "İşletim sistemi, hipervizör ve üçüncü taraf yama durumu"),
    ("PROTOCOL", "Eski protokoller ve güvensiz uzaktan yönetim"),
    ("SNMP", "SNMP sürümü, toplulukları ve erişim sınırları"),
    ("PERIMETER", "Ağ geçidi, VPN, güvenlik duvarı ve segmentasyon"),
    ("WIRELESS", "Yetkili kablosuz ağ ve test istemcisi kontrolleri"),
    ("EVIDENCE", "Bulgu kanıtı, etki ve yeniden test kaydı"),
)
STATES = {"bekliyor", "test edildi", "bulgu", "uygulanamaz"}


def save(root, data):
    dest = root / "review.json"
    tmp = root / "review.json.tmp"
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(dest)


def initial():
    return {"schema": 3, "analyst_summary": "", "reviewer": "", "approved_at": "",
            "cases": [{"id": code, "title": title, "state": "bekliyor", "note": "", "evidence": "", "sha256": ""} for code, title in CASES],
            "findings": []}


def evidence(root, name):
    """Require a file within the run, without symlinks (including parents)."""
    if not name or Path(name).is_absolute() or ".." in Path(name).parts:
        raise ValueError("Kanıt, görev klasörüne göreli bir dosya olmalı")
    path = root
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Kanıt yolunda sembolik bağ kullanılamaz")
    if not path.is_file():
        raise ValueError("Kanıt dosyası bulunamadı: " + name)
    if path.stat().st_size > 25_000_000:
        raise ValueError("Kanıt dosyası 25 MB sınırını aşıyor")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assess(root, data):
    """Evaluate recorded coverage; never infer a completed pentest from scan status."""
    cases = data.get("cases") or []
    expected = {code for code, _ in (CASES if int(data.get("schema", 2) or 2) >= 3 else LEGACY_CASES)}
    covered = set()
    errors = []
    for case in cases:
        if not isinstance(case, dict) or case.get("id") not in expected or case["id"] in covered:
            errors.append("Geçersiz veya yinelenen test başlığı")
            continue
        covered.add(case["id"])
        state = case.get("state", "bekliyor")
        if state not in STATES:
            errors.append(f"{case['id']}: geçersiz durum")
        if state != "bekliyor":
            if not str(case.get("note", "")).strip():
                errors.append(f"{case['id']}: gerekçe/sonuç eksik")
            if state != "uygulanamaz":
                try:
                    digest = evidence(root, str(case.get("evidence", "")))
                    if case.get("sha256") != digest:
                        errors.append(f"{case['id']}: kanıt özeti uyuşmuyor")
                except ValueError as exc:
                    errors.append(f"{case['id']}: {exc}")
    if covered != expected:
        errors.append("Zorunlu test başlıkları eksik")
    pending = sum(c.get("state", "bekliyor") == "bekliyor" for c in cases if isinstance(c, dict))
    for item in data.get("findings", []):
        if not isinstance(item, dict) or item.get("status") != "doğrulandı":
            continue
        fid = str(item.get("id", "bulgu"))
        for key in ("title", "asset", "description", "impact", "recommendation", "reproduction", "reviewed_by"):
            if not str(item.get(key, "")).strip():
                errors.append(f"{fid}: {key} eksik")
        try:
            digest = evidence(root, str(item.get("evidence", "")))
            if item.get("evidence_sha256") != digest:
                errors.append(f"{fid}: kanıt özeti uyuşmuyor")
        except ValueError as exc:
            errors.append(f"{fid}: {exc}")
        for extra in item.get("evidence_items", []) if isinstance(item.get("evidence_items", []), list) else []:
            if not isinstance(extra, dict):
                errors.append(f"{fid}: ek kanıt kaydı geçersiz")
                continue
            try:
                digest = evidence(root, str(extra.get("path", "")))
                if digest != extra.get("sha256"):
                    errors.append(f"{fid}: ek kanıt özeti uyuşmuyor")
            except ValueError as exc:
                errors.append(f"{fid}: {exc}")
    if not str(data.get("analyst_summary", "")).strip():
        errors.append("Analist yönetici özeti eksik")
    approved = bool(data.get("reviewer") and data.get("approved_at"))
    complete = approved and pending == 0 and not errors
    return {"complete": complete, "pending": pending, "errors": errors,
            "approved": approved, "reviewer": data.get("reviewer", "")}


def verified_finding(root, item):
    if item.get("status") != "doğrulandı":
        return False
    if any(not str(item.get(key, "")).strip() for key in
           ("title", "asset", "description", "impact", "recommendation", "reproduction", "reviewed_by")):
        return False
    try:
        if evidence(root, str(item.get("evidence", ""))) != item.get("evidence_sha256"):
            return False
        extras = item.get("evidence_items", [])
        return (isinstance(extras, list) and all(isinstance(entry, dict) and
                evidence(root, str(entry.get("path", ""))) == entry.get("sha256")
                for entry in extras))
    except ValueError:
        return False


def prompt(label, default=""):
    value = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return value or default


FINDING_FIELDS = (
    ("title", "Bulgu adı"), ("asset", "Birincil kapsamdaki varlık"),
    ("severity", "Seviye [critical/high/medium/low/info]"),
    ("category", "Bulgu kategorisi"), ("access_point", "Erişim noktası / servis"),
    ("user_profile", "Etkilenen kullanıcı profili / rol"),
    ("root_cause", "Kök neden / yapılandırma sebebi"),
    ("description", "Teknik açıklama"),
    ("reproduction", "Tekrar üretim yöntemi (sır içermez)"),
    ("impact", "Gerçek iş etkisi"), ("recommendation", "Düzeltme önerisi"),
    ("remediation_priority", "Düzeltme önceliği ve önerilen sorumlu"),
    ("retest_status", "Yeniden test durumu"),
    ("disposition_reason", "Kapatma / risk kabulü gerekçesi (varsa)"),
    ("reference", "CVE / CWE / üretici referansı (varsa)"),
    ("reviewed_by", "Doğrulayan analist"),
)


def edit_finding(root, item):
    for key, label in FINDING_FIELDS:
        item[key] = prompt(label, item.get(key, ""))
    existing = item.get("affected_assets", [])
    if not isinstance(existing, list):
        existing = []
    raw_assets = prompt("Diğer etkilenen varlıklar (virgülle ayrılmış)", ", ".join(existing))
    item["affected_assets"] = [value.strip() for value in raw_assets.split(",") if value.strip()]
    item["evidence"] = prompt("Görev klasöründeki birincil kanıt dosyası", item.get("evidence", ""))
    try:
        item["evidence_sha256"] = evidence(root, item["evidence"])
        if item["severity"] not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError("Geçersiz seviye")
        extras = item.setdefault("evidence_items", [])
        if not isinstance(extras, list):
            extras = item["evidence_items"] = []
        while prompt("Ek kanıt dosyası ekle? e/H", "H").lower() == "e":
            path = prompt("Görev klasöründeki ek kanıt yolu")
            extras.append({"path": path, "caption": prompt("Kanıt açıklaması"),
                           "sha256": evidence(root, path)})
        requested = prompt("Durum [doğrulandı/taslak/yanlış pozitif/risk kabul edildi]",
                           item.get("status") if item.get("status") not in ("taslak", "doğrulandı") else "doğrulandı")
        if requested not in {"doğrulandı", "taslak", "yanlış pozitif", "risk kabul edildi"}:
            raise ValueError("Geçersiz bulgu durumu")
        item["status"] = requested if requested != "doğrulandı" or verified_finding(root, {**item, "status": "doğrulandı"}) else "taslak"
    except ValueError as exc:
        item["status"] = "taslak"
        print("Taslak kaydedildi:", exc)
    return item


def guided(root):
    if not (root / "engagement.json").is_file():
        raise ValueError("Görev klasöründe engagement.json bulunamadı")
    dest = root / "review.json"
    data = json.loads(dest.read_text(encoding="utf-8")) if dest.exists() else initial()
    if not data.get("cases"):
        data["cases"] = initial()["cases"]
    print("Analist kaydı: müşteri verisi ve sır içeren ham istekleri kanıta koymadan önce temizleyin.")
    print("Testleri uygulama üzerinde siz yürütün. Burada yalnızca yapılan iş ve yerel kanıt kaydedilir.")
    for case in data["cases"]:
        print(f"\n{case['id']} — {case['title']} ({case.get('state', 'bekliyor')})")
        state = prompt("Durum: 0=bekliyor, 1=test edildi, 2=bulgu, 3=uygulanamaz, Enter=koru")
        if not state:
            continue
        case["state"] = {"0": "bekliyor", "1": "test edildi", "2": "bulgu", "3": "uygulanamaz"}.get(state, case.get("state", "bekliyor"))
        if case["state"] == "bekliyor":
            case.update(note="", evidence="", sha256="")
            continue
        case["note"] = prompt("Test sonucu / uygulanamaz gerekçesi", case.get("note", ""))
        if case["state"] != "uygulanamaz":
            name = prompt("Görev klasöründeki yerel kanıt yolu", case.get("evidence", ""))
            try:
                case["sha256"] = evidence(root, name)
                case["evidence"] = name
            except ValueError as exc:
                print("Kanıt kabul edilmedi:", exc)
                case.update(evidence="", sha256="")
    data["analyst_summary"] = prompt("Yönetici özeti", data.get("analyst_summary", ""))
    for item in data.get("findings", []):
        if isinstance(item, dict) and prompt(f"{item.get('id','?')} · {item.get('title','?')} bulgusunu düzenle? e/H", "H").lower() == "e":
            edit_finding(root, item)
    while prompt("Yeni bulgu kaydı ekle? e/H", "H").lower() == "e":
        item = {"id": f"PX-{len(data.get('findings', [])) + 1:03d}", "status": "taslak"}
        edit_finding(root, item)
        data.setdefault("findings", []).append(item)
    # Any edit invalidates an earlier approval until re-acknowledged.
    data.update(reviewer="", approved_at="")
    save(root, data)
    result = assess(root, data)
    if not result["errors"] and result["pending"] == 0:
        reviewer = prompt("Son incelemeyi yapan kişi")
        if reviewer and prompt("Gerçek testleri ve kanıtları inceledim: ONAYLIYORUM") == "ONAYLIYORUM":
            data.update(reviewer=reviewer, approved_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
            save(root, data)
            result = assess(root, data)
    print("Manuel çalışma:", "kayıtları tamamlandı" if result["complete"] else "eksik veya inceleme bekliyor")
    for reason in result["errors"][:15]:
        print("-", reason)
    if result["pending"]:
        print(f"Bekleyen başlık: {result['pending']}")
    return result
