"""Produce a scoped, evidence-led handoff for the human penetration tester.

The plan never executes a command. Only authorized inventory and recorded steps
may trigger a target-specific task. An absent signal is not a negative finding.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
from pathlib import Path
import re

from analyst_review import evidence
from device_inventory import allowed_ips

DATABASE_PORTS = {1433: "SQL Server", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
                  1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
WEB_PORTS = {80, 443, 8080, 8443}
SHARE_PORTS = {139, 445, 2049}
LEGACY_PORTS = {21: "FTP", 23: "Telnet", 161: "SNMP", 5900: "VNC"}


def clean(value, limit=240):
    """Keep untrusted scan labels inert in Markdown and shell examples."""
    return re.sub(r"[\x00-\x1f`<>|]", " ", str(value or ""))[:limit].strip()


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _read_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, type(default)) else default
    except (OSError, ValueError):
        return default


def _review_state(root, review, case_id):
    item = next((case for case in review.get("cases", []) if isinstance(case, dict)
                 and case.get("id") == case_id), None)
    if not item:
        return "bekliyor", ""
    state = item.get("state", "bekliyor")
    if state == "uygulanamaz":
        return "uygulanamaz", clean(item.get("note"), 400)
    if state in ("test edildi", "bulgu"):
        try:
            if evidence(root, str(item.get("evidence", ""))) == item.get("sha256"):
                return "tamamlandı", clean(item.get("note"), 400)
        except ValueError:
            pass
        return "kanıt eksik", "Kayıtlı kanıt bulunamadı veya SHA-256 değişti."
    return "bekliyor", ""


def build_plan(root: Path, meta: dict, steps: list, review: dict,
               inventory: dict, findings: list) -> dict:
    permitted = allowed_ips(root, meta)
    devices = [item for item in inventory.get("devices", []) if isinstance(item, dict)
               and _ip(item.get("ip", "")) and permitted(item["ip"])]
    by_port = {}
    for item in devices:
        for port in item.get("ports", []):
            try:
                number = int(port.get("port", ""))
            except (ValueError, TypeError):
                continue
            by_port.setdefault(number, set()).add(item["ip"])
    def addresses(ports):
        return sorted({ip for port in ports for ip in by_port.get(port, set())},
                      key=ipaddress.ip_address)
    web = addresses(WEB_PORTS)
    shares = addresses(SHARE_PORTS)
    database = addresses(DATABASE_PORTS)
    legacy = addresses(LEGACY_PORTS)
    ad = _read_json(root / "AD_ASSESSMENT.json", {})
    ad_config = meta.get("ad") if isinstance(meta.get("ad"), dict) else {}
    ad_mode = ad_config.get("mode", "disabled")
    ad_hosts = addresses({88, 389, 636, 3268, 3269})
    ad_relevant = ad_mode not in (None, "disabled") or bool(ad_hosts) or bool(ad.get("domain"))
    routes = meta.get("host_snapshot", {}).get("default_routes", []) if isinstance(meta.get("host_snapshot"), dict) else []
    gateways = sorted({_ip(row.get("gateway", "")) for row in routes if isinstance(row, dict)} - {""})
    sql_instances = []
    for path in sorted((root / "targets").glob("*/raw/sql_browser_*.json")) if (root / "targets").exists() else []:
        result = _read_json(path, {})
        if (result.get("status") == "ok" and _ip(result.get("ip", ""))
                and permitted(result["ip"])):
            for instance in result.get("instances", [])[:12]:
                if isinstance(instance, dict):
                    sql_instances.append({"ip": result["ip"], "name": clean(instance.get("name"), 70),
                                          "port": instance.get("tcp_port"), "version": clean(instance.get("version"), 55),
                                          "evidence": str(path.relative_to(root))})
            database = sorted(set(database) | {result["ip"]}, key=ipaddress.ip_address)
    confirmed = [item for item in findings if item.get("status") == "doğrulandı"]
    candidates = [item for item in findings if item.get("status") == "taslak"]
    task_list = []

    def add(code, case, priority, title, targets, trigger, steps_to_do,
            expected, commands=(), request="", references=()):
        state, note = _review_state(root, review, case)
        task_list.append({"id": code, "case": case, "priority": priority,
            "title": title, "status": state, "review_note": note,
            "targets": [clean(x, 120) for x in targets], "trigger": clean(trigger, 500),
            "steps": list(steps_to_do), "evidence_required": list(expected),
            "commands": list(commands), "customer_input": request,
            "source_evidence": [clean(x, 260) for x in references if x][:12],
            "completion": ("Yapılan işlem, sonuç ve kapsam içi varlıkları kaydedin; kanıt dosyasını "
                "görev klasörüne ekleyip `ubden-cyber --analyst-review GOREV_DIZINI` ile SHA-256 kaydını oluşturun. "
                "Ardından `ubden-cyber --report-only GOREV_DIZINI` çalıştırın.")})

    add("T-01", "SCOPE", "P1", "Kapsam ve ağ yolunu kesinleştir",
        meta.get("targets", []), "Görevde tanımlanan hedefler ve Windows rota kaydı.",
        ["Yetki belgesindeki IP/FQDN/CIDR listesini, hariçleri ve test saatlerini müşteriyle karşılaştırın.",
         "VPN, VLAN ve NAT arkasındaki ek ağları ağ sorumlusuna teyit ettirin; tarama görünürlüğünü tüm kurum envanteri saymayın.",
         "Erişilemeyen veya yanlış arayüze yönlenen hedefleri ayrı listeleyin."],
        ["İmzalı kapsam/yetki referansı", "Rota ve DNS kanıtı", "Hariç ve erişilemeyen hedef listesi"],
        request="Yetkili kapsam listesi, hariçler, bakım penceresi ve acil durdurma kişisi.")

    if devices:
        uncertain = [item for item in devices if item.get("confidence") in ("belirsiz", "düşük")]
        uncertain_ips = [clean(item.get("ip")) for item in uncertain[:20]]
        add("T-02", "ASSET", "P2", "Cihaz rollerini ve ağ şemasını doğrula", uncertain_ips or [d["ip"] for d in devices[:12]],
            f"{len(devices)} yanıtlı adres; {len(uncertain)} cihazın sınıf güveni düşük/belirsiz.",
            ["IP, host adı, gözlenen MAC/OUI, açık servis ve müşterinin CMDB kaydını satır satır eşleştirin.",
             "Sanal makine MAC önekini hipervizör sunucusu kanıtı saymayın; host yönetim arayüzü veya CMDB ile doğrulayın.",
             "Ağ geçidi, güvenlik duvarı, DC, SQL, yedekleme ve sanallaştırma bileşenlerini yalnız kanıtlı kimlikle işaretleyin."],
            ["Onaylı IP–cihaz–rol eşleştirmesi", "Güncel mantıksal ağ şeması veya VLAN listesi", "Belirsiz sınıflar için sahip/onay notu"],
            request="IP, cihaz adı, görevi ve sorumlusunu içeren mevcut envanter (Excel/CSV yeterli).")

    if gateways or devices:
        add("T-03", "PERIMETER", "P1" if gateways else "P2", "Ağ geçidi ve güvenlik sınırlarını teyit et",
            gateways or [d["ip"] for d in devices[:5]],
            "Windows rota tablosu ağ geçitlerini gösteriyor; bu kayıt kurumsal güvenlik duvarı tipini kanıtlamaz.",
            ["Varsayılan ağ geçidi IP'lerini ve VPN çıkışlarını ağ sorumlusunun şemasıyla eşleştirin.",
             "İç/dış/DMZ/misafir VLAN ayrımını, NAT ve güvenlik duvarı kural sahiplerini doğrulayın.",
             "Tarama konumundan görülemeyen segmentleri ve onlar için ayrı test noktası ihtiyacını not edin."],
            ["Ağ şeması veya redakte edilmiş kural özeti", "Ağ geçidi cihaz/ürün/sürüm doğrulaması", "Görülemeyen segment listesi"],
            request="Güvenlik duvarı modeli/yönetim IP'si, VLAN–CIDR listesi ve basit ağ çizimi.")

    if ad_relevant:
        add("T-04", "AD", "P1", "AD ve ayrıcalıklı erişim incelemesi",
            ad_hosts or [clean(ad.get("domain_controller") or ad.get("dc") or ad_config.get("dc"))],
            f"AD modu: {ad_mode or 'belirsiz'}; envanter sorgusu: {ad.get('status', 'kayıt yok')}.",
            ["Etki alanı/orman, DC ve DNS kayıtlarını müşteri envanteriyle doğrulayın.",
             "Ayrıcalıklı grupların üyelerini ve servis hesaplarını salt okunur yetkili oturumda inceleyin; görev dışı hesaplara oturum açmayın.",
             "Yetki devri, eski hesaplar ve kayıtlı istisnaları müşteri politikasıyla karşılaştırın."],
            ["DC ve alan envanteri", "Redakte edilmiş ayrıcalıklı grup üyelik özeti", "İstisna/hesap sahibi doğrulaması"],
            request="Etki alanı adı, DC adresleri, yalnız okuma yetkili test hesabı ve ayrıcalıklı grup/servis hesabı envanteri.",
            references=["AD_ASSESSMENT.json"] if ad else [])
        add("T-05", "AD-POLICY", "P1", "AD parola ve kilitlenme ilkelerini değerlendir",
            ad_hosts or [clean(ad.get("domain_controller") or ad.get("dc") or "Etki alanı")],
            "AD görüldü veya görevde AD modülü seçildi; mevcut envanter parola ilkesini tam doğrulamıyor.",
            ["Varsayılan ve varsa ince ayarlı parola ilkelerini yetkili AD oturumunda salt okunur dışa aktarın.",
             "Minimum uzunluk, karmaşıklık, geçmiş, kilitlenme eşiği/süresi ve parola süresi istisnalarını kurum politikasıyla karşılaştırın.",
             "Süresi dolmayan hesapların yalnız sayısını ve iş gerekçesini doğrulayın; parolaları veya hashleri rapora koymayın."],
            ["Parola ilkesi çıktısı (kimlik bilgisi içermez)", "İnce ayarlı ilke listesi veya yok bilgisi",
             "İstisna hesap sayısı ve müşteri gerekçesi"],
            commands=["Get-ADDefaultDomainPasswordPolicy -Server <YETKILI_DC> | Format-List MinPasswordLength,ComplexityEnabled,PasswordHistoryCount,LockoutThreshold,LockoutDuration,MaxPasswordAge"],
            request="Varsayılan/ince ayarlı AD parola politikası ekran görüntüsü veya CSV çıktısı; test hesabı erişimi yoksa müşteri dışa aktarabilir.",
            references=["AD_ASSESSMENT.json"] if ad else [])

    if shares:
        add("T-06", "SHARES", "P1", "SMB/NFS paylaşım izinlerini doğrula", shares,
            "Kapsam içi adreslerde SMB veya NFS portu gözlendi; port açıklığı paylaşım yetkisi anlamına gelmez.",
            ["Yalnız müşteri tarafından sağlanan düşük yetkili test hesabıyla paylaşım listesini ve görünürlük düzeyini kaydedin.",
             "Bir test dosyası/klasörü üzerinde beklenen ve gerçek okuma/yazma yetkisini karşılaştırın; üretim verisi kopyalamayın.",
             "SMB sürümü/imzalama ve NFS dışa aktarma kurallarını servis sahibinin yapılandırmasıyla doğrulayın."],
            ["Kapsam içi paylaşım/izin matrisi", "Test hesabı rolü ve redakte edilmiş erişim sonucu",
             "SMB/NFS yapılandırma kanıtı"],
            commands=["nmap -Pn -sT -p445 --script smb-protocols,smb2-security-mode <KAPSAMDAKI_IP>",
                      "smbclient -L //<KAPSAMDAKI_IP> -U <YETKILI_TEST_HESABI>"],
            request="Test hesabı, erişimi beklenen örnek paylaşım ve rol/izin matrisi; parola ayrı güvenli kanaldan.",
            references=[d.get("evidence", "") for d in devices if d["ip"] in shares])

    if database:
        descriptions = [f"{DATABASE_PORTS[p]}:{p} ({len(by_port.get(p, set()))} adres)"
                        for p in sorted(DATABASE_PORTS) if by_port.get(p)]
        descriptions.extend(f"SQL Browser {x['ip']}:{x['port']} {x['name']}" for x in sql_instances[:8])
        sql_commands=["nmap -Pn -sT -p1433 --script ms-sql-info --script-args mssql.scanned-ports-only=true <KAPSAMDAKI_SQL_IP>"]
        for instance in sql_instances[:8]:
            try:
                port=int(instance['port'])
            except (TypeError,ValueError):
                continue
            if 1 <= port <= 65535:
                sql_commands.append(f"nmap -Pn -sT -p{port} --script ms-sql-info --script-args mssql.scanned-ports-only=true {instance['ip']}")
        add("T-07", "DATABASE", "P1", "Veritabanı örneklerini ve erişim sınırlarını doğrula", database,
            "; ".join(descriptions) or "SQL Browser yanıtı kaydedildi.",
            ["SQL örnek adı, ürün/sürüm, dinleme portu ve sunucu sahibini müşteri envanteriyle eşleştirin.",
             "Yalnız sağlanan düşük yetkili test hesabıyla örnek bir test veritabanına erişimi doğrulayın; üretim tablolarını dökmeyin.",
             "Yama durumu, ağ izinleri, şifreleme ve yedekleme sorumluluğunu yapılandırma kanıtıyla değerlendirin."],
            ["SQL/DB sunucu ve örnek envanteri", "Test hesabı için beklenen/gerçek yetki sonucu",
             "Sürüm ve yama kaydı; veri içermeyen yapılandırma kanıtı"],
            commands=sql_commands,
            request="DB sunucusu/örnek adları, dinleme portları, ürün ve yama sürümleri; gerekirse düşük yetkili test hesabı.",
            references=[x["evidence"] for x in sql_instances] +
                       [d.get("evidence", "") for d in devices if d["ip"] in database])

    if devices:
        add("T-08", "PATCH", "P1", "İşletim sistemi ve üçüncü taraf yama durumunu doğrula",
            [d["ip"] for d in devices[:30]],
            "Servis banner'ları yalnız tahmini sürüm sağlar; kurulu güvenlik yamalarını doğrulamaz.",
            ["Müşterinin envanterinden her sunucunun OS, hipervizör, DB ve kritik uygulama sürümünü alın.",
             "Yama yönetim raporundaki son başarılı güncelleme tarihini ve bekleyen kritik yamaları varlık bazında eşleştirin.",
             "Sürüm/bülten eşleşmesini üretici kaynağıyla kontrol edin; banner'dan tek başına CVE doğrulamayın."],
            ["Varlık bazlı yama/versiyon CSV'si", "Yama yönetimi başarısız/ertelenmiş kayıtları",
             "Üretici bülteni ve analist doğrulama notu"],
            commands=["Get-HotFix | Select-Object HotFixID,InstalledOn | Sort-Object InstalledOn -Descending"],
            request="WSUS/Intune/SCCM veya kullanılan yama aracından varlık bazlı son yama tarihi ve bekleyen kritik güncelleme CSV'si.")

    if legacy:
        listed = [f"{LEGACY_PORTS[p]}:{p} -> {', '.join(sorted(by_port[p], key=ipaddress.ip_address))}"
                  for p in sorted(LEGACY_PORTS) if by_port.get(p)]
        add("T-09", "PROTOCOL", "P1", "Eski/yönetim protokollerinin kullanımını doğrula", legacy,
            "; ".join(listed),
            ["Servis sahibiyle hangi protokolün gerçekten kullanıldığını ve yönetim ağından erişim politikasını doğrulayın.",
             "Şifreleme, kimlik doğrulama ve erişim listesi ayarlarını salt okunur yapılandırma kanıtıyla karşılaştırın.",
             "SNMP için sürüm/topluluk erişimini; Telnet/FTP için şifreli alternatif ve geçiş planını kaydedin."],
            ["Servis sahibi ve kullanım amacı", "Redakte edilmiş protokol/erişim ayarları", "Alternatif veya istisna planı"],
            request="Telnet/FTP/SNMP/VNC kullanım gerekçesi ve ilgili cihazların yönetim ağı politikası.")

    snmp = [item for item in devices if any(str(p.get('port')) == '161' for p in item.get('ports',[]))
            or item.get('snmp_sysdescr')]
    if snmp:
        add("T-19", "SNMP", "P1" if any(d.get('snmp_sysdescr') for d in snmp) else "P2",
            "SNMP erişimini ve topluluk politikasını doğrula", [d['ip'] for d in snmp],
            "SNMP portu veya tek salt okunur sysDescr yanıtı görüldü; diğer topluluklar ve ACL durumu bilinmiyor.",
            ["Yanıtın gerçekten hedef cihazdan geldiğini ağ sorumlusuyla doğrulayın.",
             "Yönetim ACL'si, sürüm ve topluluk yapılandırmasını yetkili cihaz ekranından salt okunur kaydedin.",
             "SNMPv3 ve varsayılan toplulukların kapatılması politikasını müşteri standardıyla karşılaştırın."],
            ["Redakte edilmiş sürüm/topluluk ayarı", "Yetkili yönetim ağı ACL özeti", "Cihaz sahibi doğrulaması"],
            request="SNMP kullanılan cihazlar ve yönetim ağından erişmesi beklenen IP'ler.")

    if candidates:
        summary=[f"{clean(f.get('id'),20)} {clean(f.get('asset'),90)}: {clean(f.get('title'),120)}"
                 for f in candidates[:20]]
        add("T-20", "CONFIG", "P1", "Otomatik aday bulguları tek tek doğrula",
            [clean(f.get('asset'),100) for f in candidates[:30]],
            f"{len(candidates)} taslak gözlem var. İlk adaylar: " + "; ".join(summary),
            ["Her aday için kaynak kanıtı açın; varlık, servis sürümü ve test zamanı eşleşmesini denetleyin.",
             "Üretici belgesi ve müşterinin gerçek yapılandırmasıyla olası etkiyi karşılaştırın.",
             "Doğrulanmayan adayı bulgu olarak sunmayın; doğrulanan için tekrar üretim, iş etkisi ve öneriyi analist kaydına girin."],
            ["Her aday için doğrulandı/yanlış pozitif/belirsiz kararı", "Kapsam içi redakte edilmiş yapılandırma veya yanıt kanıtı",
             "Doğrulanan bulgu için iş etkisi ve düzeltme adımı"],
            references=[clean(f.get('evidence'),260) for f in candidates[:20]])

    if web:
        add("T-10", "AUTH", "P1", "Web oturum ve test hesabı akışını incele", web,
            "HTTP(S) servisi görüldü; tarama oturum yaşam döngüsünü doğrulamaz.",
            ["Müşterinin oluşturduğu iki normal test hesabı ve varsa yönetici rolüyle giriş/çıkış akışını inceleyin.",
             "MFA, oturum sonlandırma, parola sıfırlama ve rol değişimini yalnız test kullanıcılarıyla değerlendirin.",
             "Giriş ekranında sözlük veya toplu parola denemesi yapmayın."],
            ["Rol ve test hesabı matrisi", "Redakte edilmiş istek/yanıt veya ekran görüntüsü",
             "Beklenen/gerçek oturum sonucu"],
            request="İki normal test hesabı, varsa yetkili test rolü, giriş URL'si ve MFA test yöntemi; sırlar e-postadan ayrı.")
        add("T-11", "ROLES", "P1", "Dikey yetki ve rol sınırını doğrula", web,
            "Web arayüzü ve/veya görevdeki rol senaryoları.",
            ["Yalnız test hesaplarının kullanabildiği bir yönetici işlevi ve normal kullanıcı işlevi seçin.",
             "Normal test rolüyle yönetici uç noktasına erişimin reddedildiğini; yetkili rolle çalıştığını karşılaştırın.",
             "Durum kodunun yanında yanıt içeriği ve gerçek iş etkisini redakte ederek kaydedin."],
            ["Rol–işlem matrisi", "İki test rolünün redakte edilmiş karşılaştırmalı yanıtları"],
            request="Test rollerinin yapabildiği ve yapmaması gereken 2-3 örnek işlem.")
        add("T-12", "IDOR", "P1", "Test verisiyle nesne düzeyi erişimi doğrula", web,
            "Web/API yüzeyi görüldü; otomatik durum kodu karşılaştırması IDOR doğrulaması değildir.",
            ["A ve B test hesaplarına ait birer sentetik kayıt oluşturun; üretim müşterisi verisini kullanmayın.",
             "A hesabının kendi kaydını ve B kaydını okuma/değiştirme yetkisini görevde izin verilen işlemlerle karşılaştırın.",
             "Kayıt kimliğini topluca tahmin etmeyin; yalnız önceden verilen iki test nesnesini kullanın."],
            ["Test hesapları ve sentetik nesne kimlikleri", "Beklenen/gerçek erişim matrisi",
             "Redakte edilmiş iki yanıt ve iş etkisi açıklaması"],
            request="İki test hesabına ait sentetik kayıt/nesne örnekleri ve bunların beklenen erişim kuralları.")
        add("T-13", "INPUT", "P2", "Girdi ve çıktı işleme kontrolleri", web,
            "Web arayüzü görüldü; otomatik başlık kontrolleri uygulama girdisini kapsamaz.",
            ["Müşteriyle belirlenen test alanlarında zararsız işaretleyiciyle doğrulama/çıktı kodlama davranışını gözleyin.",
             "Durum değiştiren testleri yalnız izinli test kayıtlarında uygulayın; üretim verisini bozmayın."],
            ["Test alanı listesi", "Redakte edilmiş beklenen/gerçek yanıt", "Etkisi doğrulanmışsa tekrar üretim adımı"],
            request="Test edilebilecek form/API alanları ve kullanılabilecek sentetik kayıtlar.")
        add("T-14", "API", "P2", "API uçları ve erişim matrisi", web,
            "Web servisi görüldü; API kapsamı ayrıca müşteri bilgisiyle kesinleşir.",
            ["API dokümanı/Swagger veya müşteri uç listesiyle kullanılan endpoint'leri eşleştirin.",
             "Test hesapları için okuma/yazma ayrımını ve veri minimizasyonunu örnek yanıtlarla doğrulayın."],
            ["API uç listesi", "Rol bazlı erişim matrisi", "Redakte edilmiş örnek yanıt"],
            request="Swagger/OpenAPI adresi veya API uç listesi; erişimi olan iki test rolü.")
        add("T-15", "LOGIC", "P2", "İş akışı ve işlem sırası", web,
            "Uygulama servisi görüldü; iş kurallarını otomatik tarama doğrulayamaz.",
            ["Müşteriden kritik bir örnek süreç seçin (ör. onay, talep, sipariş) ve beklenen adımları kaydedin.",
             "Yalnız sentetik kayıt üzerinde rol ve adım sırasını karşılaştırın; gerçek ödeme/üretim işlemi yapmayın."],
            ["Beklenen iş akışı", "Sentetik işlem adımları ve sonuçları", "Varsa ihlal edilen iş kuralı"],
            request="Test edilebilecek örnek süreç ve sentetik işlem verisi.")

    if isinstance(meta.get("wireless"), dict) and meta["wireless"].get("enabled"):
        wireless = meta["wireless"]
        add("T-16", "WIRELESS", "P2", "Kablosuz donanım ve görev kanıtını tamamla",
            [wireless.get("ssid", "yetkili SSID")],
            "Görevde kablosuz modül seçildi; monitör modu ve işlem sonuçları adım günlüğüyle doğrulanmalı.",
            ["SSID/BSSID/kanal ve test istemcisi eşleşmesini müşteriyle doğrulayın.",
             "Monitör modu, yakalama ve sınırlı aktif adım sonuçlarını adım günlüğünden ayırın; çalışmayan adımı test edildi saymayın."],
            ["Adaptör/monitör modu kanıtı", "Yetkili AP/test istemcisi kaydı", "İşlem sonuçları ve süre sınırı"],
            request="Yetkili SSID, BSSID, kanal ve yalnız test için ayrılmış istemci.")

    if confirmed:
        add("T-17", "RETEST", "P1", "Doğrulanmış bulguların düzeltme tekrar testi",
            [clean(f.get("asset")) for f in confirmed[:30]],
            f"{len(confirmed)} analist doğrulamalı bulgu kayıtlı.",
            ["Her bulgunun düzeltme sahibini ve uygulanan değişikliği müşteriyle eşleştirin.",
             "Önceki tekrar üretim adımını aynı yetkili test koşullarında yalnız bir kez yineleyin.",
             "Yeni kanıtı önceki SHA-256 kaydıyla karıştırmadan ayrı dosya olarak ekleyin."],
            ["Değişiklik/talep numarası", "Önceki ve sonraki redakte edilmiş sonuç", "Yeniden test tarihi ve analist kararı"])

    if devices or steps:
        add("T-18", "EVIDENCE", "P2", "Kanıt ve teslim bütünlüğünü denetle",
            [clean(meta.get("id") or "görev")],
            "Adım çıktıları, analist bulguları ve rapor dosyaları teslim öncesi eşleştirilmeli.",
            ["Her doğrulanmış bulgu için hedef, zaman, sürüm, adım ve redakte edilmiş kanıtı kontrol edin.",
             "Başarısız/atlanmış testleri tamamlanmış gibi sunmayın; kapsam dışı adresleri kanıttan ayıklayın.",
             "SHA256SUMS.txt özetlerini dışa aktarılan dosyalarla karşılaştırın."],
            ["Kanıt dizini ve SHA-256 manifesti", "Eksik/atlanmış kontrol listesi", "Analist onayı"],
            commands=["sha256sum -c SHA256SUMS.txt"])

    order = {"P1": 0, "P2": 1, "P3": 2}
    task_list.sort(key=lambda item: (item["status"] == "tamamlandı", order[item["priority"]], item["id"]))
    pending = sum(item["status"] not in ("tamamlandı", "uygulanamaz") for item in task_list)
    return {"schema": 1, "engagement_id": clean(meta.get("id")),
            "client": clean(meta.get("client")), "project": clean(meta.get("project")),
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "scope": [clean(x) for x in meta.get("targets", [])],
            "observed_hosts": len(devices), "observed_web_hosts": len(web),
            "observed_share_hosts": len(shares), "observed_database_hosts": len(database),
            "observed_sql_instances": sql_instances, "pending_count": pending,
            "note": ("Bu belge kayıtlı gözlemlerden türetilen analist iş listesidir. "
                     "Görev bulunması testin yapıldığı veya zafiyetin doğrulandığı anlamına gelmez."),
            "tasks": task_list}


def markdown(plan: dict) -> str:
    lines = ["# UBDEN | Analist çalışma raporu", "",
        f"**Müşteri:** {plan['client']}  ", f"**Görev:** {plan['project']}  ",
        f"**Kayıt:** {plan['engagement_id']}  ", f"**Üretim:** {plan['generated_at']}  ",
        f"**Bekleyen adım:** {plan['pending_count']}  ", "", plan["note"], "",
        "## Gözlenen kapsam", "", ", ".join(plan["scope"]) or "Kayıt yok", "",
        f"Yanıtlı cihaz: {plan['observed_hosts']}; web: {plan['observed_web_hosts']}; "
        f"paylaşım: {plan['observed_share_hosts']}; veritabanı: {plan['observed_database_hosts']}.", "",
        "Aşağıdaki komutlar **örnektir**. Yer tutucuları görevdeki onaylı hedeflerle değiştirin. "
        "Komutlara parola/token yazmayın. Canlı giriş ekranı veya IP üzerinde sözlük/parola denemesi yapmayın.", ""]
    for task in plan["tasks"]:
        lines.extend([f"## {task['id']} · {task['title']}", "",
            f"**Öncelik:** {task['priority']} · **Manuel kayıt:** {task['case']} · **Durum:** {task['status']}", "",
            f"**İlgili varlık:** {', '.join(task['targets']) or 'müşteri bilgisi bekleniyor'}", "",
            f"**Neden:** {task['trigger']}", ""])
        if task["review_note"]:
            lines.extend([f"**Mevcut analist notu:** {task['review_note']}", ""])
        if task["customer_input"]:
            lines.extend([f"**Müşteriden gereken:** {task['customer_input']}", ""])
        lines.extend(["**Yapılacak adımlar**", ""])
        lines.extend(f"{index}. {step}" for index, step in enumerate(task["steps"], 1))
        lines.extend(["", "**Alınacak kanıt**", ""])
        lines.extend(f"- {item}" for item in task["evidence_required"])
        if task["commands"]:
            lines.extend(["", "**Salt okunur / çevrimdışı örnek komut**", "", "```text",
                          *task["commands"], "```"])
        if task["source_evidence"]:
            lines.extend(["", "**Mevcut görev kanıtı:** " + "; ".join(task["source_evidence"])])
        lines.extend(["", f"**Tamamlama:** {task['completion']}", ""])
    return "\n".join(lines) + "\n"


def write_plan(root: Path, meta: dict, steps: list, review: dict,
               inventory: dict, findings: list) -> dict:
    plan = build_plan(root, meta, steps, review, inventory, findings)
    for name, value in (("ANALIST_GOREV_RAPORU.json", json.dumps(plan, ensure_ascii=False, indent=2) + "\n"),
                        ("ANALIST_GOREV_RAPORU.md", markdown(plan))):
        temp = root / ("." + name + ".pending")
        temp.write_text(value, encoding="utf-8")
        temp.replace(root / name)
    return plan
