"""Kill-chain narrative generator (Turkish, client-facing).

The single thing the competitor report lacked: a step-by-step story of how an attacker turns
findings into Domain Admin. This takes an ordered chain of findings and emits report prose:
"Aşama 1 ... Aşama 2 ... Sonuç: ...". Output is Turkish because the deliverable is for a
Turkish client; code/comments stay English.
"""
from __future__ import annotations

import sys

# type -> (stage verb, template). {asset} filled from the finding.
_STAGE_TR = {
    "asrep_roast":  "Kimlik elde etme",
    "kerberoast":   "Kimlik elde etme",
    "cracked_credential": "Kimlik ele geçirme",
    "unauth_smb":   "Bilgi/kimlik toplama",
    "default_creds": "İlk erişim",
    "local_admin":  "Yanal hareket",
    "adcs_esc":     "Yetki yükseltme",
    "coercion":     "Yetki yükseltme",
    "gpp_password": "Kimlik elde etme",
    "dcsync":       "Domain hakimiyeti",
}

_DESC_TR = {
    "asrep_roast":  "'{asset}' hesabında Kerberos ön kimlik doğrulaması kapalı olduğu için, hiçbir "
                    "kimlik bilgisi olmadan parolasının çevrimdışı kırılabileceği bir AS-REP elde edildi.",
    "kerberoast":   "'{asset}' servis hesabı için bir TGS istendi; bileti hesabın parola özetiyle "
                    "şifreli olduğundan parola çevrimdışı kırılabilir (kilitlenme riski olmadan).",
    "cracked_credential": "'{asset}' hesabının parolası çevrimdışı KIRILDI (ağa dokunmadan, kilitleme "
                    "riski olmadan). Artık bu hesabın açık parolası biliniyor.",
    "unauth_smb":   "'{asset}' üzerinde yetkisiz erişilebilen paylaşımda hassas veri/kimlik bulundu.",
    "default_creds": "'{asset}' üzerinde öntanımlı/zayıf kimlik bilgisi ile erişim sağlandı.",
    "local_admin":  "Elde edilen kimlik bilgisi '{asset}' üzerinde yerel yönetici yetkisi verdi; bu, "
                    "bellekteki kimlik bilgilerinin alınmasını ve yanal harekete geçilmesini sağlar.",
    "adcs_esc":     "AD Sertifika Servisi'nde '{asset}' şablonu kötüye kullanılabilir durumda; düşük "
                    "yetkili bir kullanıcı ayrıcalıklı bir kimlik doğrulayan sertifika talep edebilir.",
    "coercion":     "'{asset}' bir saldırgana kimlik doğrulamaya zorlanabiliyor; NTLM aktarımıyla "
                    "(örn. AD CS ESC8) domain ele geçirilebilir.",
    "gpp_password": "'{asset}' üzerinde Group Policy Preferences içinde şifreli parola (cpassword) bulundu.",
    "dcsync":       "Elde edilen yetkilerle DCSync yapılarak domain kimlik bilgileri (krbtgt dahil) "
                    "çoğaltılabildi — tam domain hakimiyeti kanıtlandı.",
}


def narrate(chain: list[dict], reached_da: bool, lang: str = "tr") -> str:
    """Return a numbered kill-chain narrative for the ordered chain."""
    lines = []
    header = "Saldırı Zinciri (Kill Chain)" if lang == "tr" else "Attack Chain"
    lines.append(header)
    lines.append("=" * len(header))
    lines.append("")
    for i, f in enumerate(chain, 1):
        t = f.get("type", "")
        stage = _STAGE_TR.get(t, "Adım")
        desc = _DESC_TR.get(t, f.get("description", "")).format(asset=f.get("asset", "?"))
        sev = (f.get("severity") or "").capitalize()
        cvss = f.get("cvss_score")
        tag = f" [{sev}{f' / CVSS {cvss}' if cvss else ''}]" if sev else ""
        lines.append(f"Aşama {i} — {stage}{tag}")
        lines.append(f"  {desc}")
        if f.get("evidence"):
            lines.append(f"  Kanıt: {f['evidence']}")
        lines.append("")
    if reached_da:
        lines.append("Sonuç: Zincirin sonunda tam Active Directory (Domain Admin) hakimiyeti elde "
                     "edildi. Tek tek bulguların önem derecesi düşük görünse de, birlikte "
                     "zincirlendiğinde sonuç KRİTİK'tir — bu rapor bulguları bu gerçekleşen etki "
                     "üzerinden puanlar.")
    else:
        lines.append("Sonuç: Zincir Domain Admin'e FİİLEN ulaşmadı (yıkıcı/son adım sözleşme gereği "
                     "çalıştırılmadı); ancak yukarıdaki bulgular birlikte önemli bir risk oluşturur ve "
                     "öncelikle kapatılmalıdır.")
        if any(f.get("type") in ("adcs_esc", "coercion", "dcsync") for f in chain):
            lines.append("Not: ADCS/coercion bulguları Domain Admin'e giden OLASI bir yolu gösterir; bu yol "
                         "istismar edilebilir görünüyor ancak son/yıkıcı adım güvenlik gereği ÇALIŞTIRILMADI, "
                         "yani domain ele geçirme fiilen kanıtlanmadı.")
    return "\n".join(lines)


def write_narrative(chain: list[dict], reached_da: bool, out_path: str, lang: str = "tr") -> str:
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(narrate(chain, reached_da, lang))
    return out_path


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    chain = [
        {"type": "asrep_roast", "asset": "CORP\\jdoe", "severity": "high", "cvss_score": 7.5,
         "evidence": "parsdx/asrep_roast.txt"},
        {"type": "local_admin", "asset": "10.0.0.20", "severity": "high", "cvss_score": 9.8},
        {"type": "adcs_esc", "asset": "UserAuth", "severity": "critical", "cvss_score": 9.9},
    ]
    text = narrate(chain, reached_da=True)
    check("has 3 stages", text.count("Aşama ") == 3)
    check("stage 1 is credential capture", "Aşama 1 — Kimlik elde etme" in text)
    check("fills asset", "CORP\\jdoe" in text and "UserAuth" in text)
    check("shows evidence path", "parsdx/asrep_roast.txt" in text)
    check("DA conclusion is Critical framing", "KRİTİK" in text and "Domain Admin" in text)
    text2 = narrate(chain, reached_da=False)
    check("non-DA conclusion differs", "ulaşmadı" in text2)

    import tempfile, os
    p = os.path.join(tempfile.mkdtemp(), "narr.txt")
    write_narrative(chain, True, p)
    check("writes file", os.path.exists(p) and "Aşama 1" in open(p, encoding="utf-8").read())

    total = 7
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
