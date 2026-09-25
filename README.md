<p align="center">
  <img src="assets/ubden-logo.png" alt="UBDEN" width="260">
</p>

# UBDEN Cyber Security Systems

**Yetkili sızma testi operasyonları için Windows ve Kali WSL platformu.**

UBDEN, Windows ağ ortamı ile Kali araçlarını tek bir görev akışında birleştirir. Test kapsamını ve yetki bilgisini kaydeder; ağ, servis ve web kontrollerini seçilen hedeflerde yürütür; cihaz envanteri ile kanıtları yönetici ve teknik raporlara dönüştürür. Otomatik gözlemler analist incelemesine açık tutulur, doğrulanmış bulgular ayrı kaydedilir.

## Yetenekler

| Alan | UBDEN ile yapılan işlem |
| --- | --- |
| Görev ve kapsam yönetimi | Müşteri, proje, yetki referansı, hedefler, hariçler, Windows adaptörleri ve etkin modüller görev başında belirlenir. |
| Ağ keşfi | Sınırlı CIDR keşfi, TCP servis ve sürüm tespiti, uygun servislerde seçilmiş protokol kontrolleri yapılır. |
| Web değerlendirmesi | HTTP başlıkları, TLS, yöntemler, Nikto ve denetlenmiş Nuclei şablonlarıyla aday gözlemler üretilir. |
| Cihaz envanteri | IP, gözlenebilen MAC, OUI üreticisi, servis ve SNMP ipuçlarıyla gerekçeli cihaz sınıfı adayları oluşturulur. |
| Kurumsal ortam | Uygun Windows oturumu veya sağlanan test hesabıyla salt okunur AD kontrolleri; ayrı profilli Edge/Chrome ile kapsam içi web incelemesi yapılır. |
| Kablosuz değerlendirme | Uyumlu USB adaptör ve monitör modu doğrulandıktan sonra, görevde tanımlanan AP ve test istemcisi için sınırlı kontroller çalışır. |
| Kanıt ve raporlama | Yürütülen kontrol matrisi, cihaz ve servis dağılımı, analist bulguları, kanıt özetleri ve düzeltme öncelikleri yönetici PDF, teknik PDF ve HTML raporuna işlenir. |

Araç kataloğu 83 aracı kurulum, sürüm, yetenek ve görevde kullanım durumuyla izler. Hangi kontrollerin çalıştığı veya hangi ön koşul nedeniyle atlandığı raporda ayrı gösterilir. Cihaz envanteri Nmap OUI verisini ve Kali'nin `ieee-data` paketindeki IEEE MAC kayıtlarını kullanır; kurulum resmî IEEE kaynağından güncellemeyi de dener. AD, SQL Server, paylaşım, web ve ağ geçidi rol adayları ayrı gerekçelerle görünür; adaylar müşteri envanteriyle doğrulanır. SQL Browser yanıtı veren kapsam içi adreslerde adlandırılmış SQL örnekleri ve portları ayrıca listelenir.

## Teste hazırlık: müşteriden gereken bilgiler

Müşterinin mevcut bir Excel/CSV envanteri veya ağ çizimi varsa olduğu gibi paylaşması yeterlidir. Bilinmeyen alanlar `bilinmiyor` yazılabilir; test ekibi eksik veriyi görev başlangıcında işaretler. Şifreleri e-postaya veya bu tabloya koymayın; test hesapları oluşturulduğunda parolalar ayrı güvenli kanaldan iletilir.

| Bilgi | Müşterinin vereceği basit örnek | Kullanım |
| --- | --- | --- |
| Yetki ve iletişim | Yetki yazısı `BT-2026-041`; test tarihi `12–13 Ekim`; acil durdurma kişisi ve telefonu | Kapsam, zaman ve durdurma yetkisini sabitler. |
| Test edilecek adresler | `192.0.2.10`, `192.0.2.0/28`, `portal.example.com` | Yalnız bu IP, ağ ve alan adları teste girer. CIDR bilinmiyorsa IP listesi yeterlidir. |
| Hariçler | `192.0.2.14` (üretim ERP), `odeme.example.com` | Bu adresler ve uygulamalar taranmaz. |
| Ağ erişimi | Kablolu/VPN; VPN adı; hangi VLAN'dan erişileceği; gerekiyorsa sabit çıkış IP'si | Test cihazının doğru ağ yolundan bağlanmasını sağlar. |
| Sistem listesi | `192.0.2.20 = DC01 / etki alanı`; `192.0.2.30 = SQL01 / ERP DB`; `192.0.2.40 = dosya sunucusu` | Keşfedilen cihaz sınıfları ve eksik segmentler doğrulanır. Basit IP–cihaz adı–görev listesi yeterlidir. |
| Web ve API | Giriş adresi, uygulama sahibi, varsa Swagger/OpenAPI URL'si; test edilebilen yollar | Kimlik ve yetki kontrollerini doğru uygulamaya bağlar. |
| Test hesapları ve veri | A ve B adlı iki normal test kullanıcısı; varsa ayrı test yönetici rolü; iki sentetik kayıt ve beklenen erişimler | Rol, oturum ve IDOR kontrolleri yalnız test nesneleriyle yapılır. |
| AD ve paylaşımlar | Alan adı, DC IP/adı, yalnız okuma test hesabı veya müşteri tarafından verilen politika çıktısı; örnek paylaşım ve beklenen yetkiler | Parola ilkesi, grup/hesap ve paylaşım denetimini tamamlar. |
| Yama ve veritabanı | Sunucu OS/uygulama sürümü, son başarılı yama tarihi, bekleyen kritik yamalar; DB sunucusu ve örnek adları | Banner tahminleri ile gerçek sürüm/yama durumu ayrılır. CSV çıktısı yeterlidir. |
| Ağ şeması | İnternet–güvenlik duvarı–iç ağ/DMZ bağlantısını gösteren basit çizim, VLAN ve CIDR'ler | Ağ geçidi ve güvenlik sınırları doğrulanır; görünmeyen segmentler saptanır. |
| Kablosuz (seçilirse) | SSID, BSSID/MAC, kanal, yalnız test için ayrılmış istemci ve izinli zaman | Ham Wi‑Fi kontrollerini seçilen AP/istemciyle sınırlar. |

Verilen IP örnekleri ve `example.com` adları yalnız biçimi göstermek içindir; gerçek görevde müşterinin onayladığı değerler kullanılır. AD politikası, yama durumu ve paylaşım yetkileri uzaktan görülen portlarla doğrulanamaz. UBDEN bu alanlarda **analist çalışma raporu** üretir: gözlenen hedef, müşteriden istenecek veri, uygulanacak adım, örnek salt okunur komut ve kaydedilecek kanıt tek görev kartında bulunur.

### Müşteriye gönderilecek e-posta taslağı

Aşağıdaki metin doğrudan kopyalanıp müşteri yetkilisine gönderilebilir. Bilinmeyen alanlar boş bırakılabilir; IP/CIDR bilinmiyorsa sunucu adlarıyla başlayabiliriz. Test hesabı parolası e-postaya yazılmamalıdır.

```text
Konu: UBDEN sızma testi için kapsam ve test bilgileri

Merhaba,

Yetkili sızma testini başlatmak ve raporu sistemlerinize göre hazırlamak için aşağıdaki bilgileri paylaşabilir misiniz? Elinizde mevcut Excel envanteri, ağ çizimi veya yama raporu varsa bunları göndermeniz yeterlidir. Bilmediğiniz alanlara “bilinmiyor” yazabilirsiniz.

1. Kurum/proje adı ve yazılı test yetkisi referansı:
2. Test için uygun gün ve saat; acil durdurma kişisi ve telefon numarası:
3. Test edilecek IP'ler, IP blokları veya alan adları (örnek: 192.0.2.10, 192.0.2.0/28, portal.example.com):
4. Kesinlikle test edilmeyecek adresler, uygulamalar ve kritik saatler:
5. Ağa erişim şekli (yerinde kablolu ağ / Wi‑Fi / VPN), VPN adı ve gerekli test ağı/VLAN:
6. Mevcut sistem listesi: IP veya ad, cihazın görevi ve sahibi (örnek: 192.0.2.20, DC01, etki alanı sunucusu, BT ekibi):
7. Varsa basit ağ çizimi: güvenlik duvarı, iç ağ/DMZ, VLAN'lar ve bunların IP aralıkları:
8. Web uygulaması giriş adresleri, API/Swagger adresleri ve test edilebilecek iş akışları:
9. Uygulama için iki normal test hesabı; varsa ayrı test yönetici rolü; bu hesaplara ait iki örnek/sentetik kayıt ve beklenen erişim kuralları:
10. AD alan adı ve DC adresleri; varsa yalnız okuma test hesabı veya parola/kilitlenme politikası çıktısı:
11. Teste açık örnek dosya paylaşımı ve test hesabının beklenen okuma/yazma izni:
12. Sunucu ve uygulamalar için son yama tarihi/bekleyen kritik yamalar; SQL/veritabanı sunucu ve örnek adları:
13. Kablosuz test isteniyorsa SSID, BSSID, kanal ve yalnız test için ayrılmış istemci:

Test hesabı parolalarını bu e-postaya yazmayınız; ayrı güvenli kanal üzerinden iletebilirsiniz. Üretim müşteri verisi yerine sentetik test kayıtları kullanacağız.

Teşekkürler.
UBDEN Cyber Security Systems test ekibi
```

### Test bilgisayarı ve erişim ortamı

- Windows 11 22H2 veya üzeri, yönetici yetkisi, WSL 2 ve sanallaştırma desteği. UBDEN Kali WSL'yi kurar; mevcut Kali varsa kullanır.
- Temel kurulum için en az 10 GiB boş disk; GVM ve geniş araç kataloğu da seçilecekse hem Windows sistem diskinde hem Kali dosya sisteminde en az 30 GiB boş alan. 16 GiB RAM önerilir; büyük envanterlerde daha fazla kaynak gerekebilir.
- Kali paketleri ve resmî IEEE MAC kayıtları için kurulum sırasında internet; test sırasında müşterinin onayladığı hedeflere ağ erişimi. VPN kullanılacaksa test bilgisayarındaki profil ve gerekli MFA yöntemi önceden hazırlanmalıdır.
- Kablolu erişim tercih edilir. Dahili Wi‑Fi IP tabanlı ağ testlerini destekleyebilir; ham 802.11 kontrolü için Kali'de sürücü ve monitör modu doğrulanmış uyumlu USB Wi‑Fi adaptörü gerekir.
- Çıktıları teslim etmek için müşteri tarafından belirlenmiş WSL dışı güvenli dosya konumu. Hesap, token ve sırlar rapora kaydedilmez.

## Windows üzerinde hızlı başlangıç

**Gereksinimler:** Windows 11 22H2 veya üzeri, sanallaştırma desteği, yönetici yetkisi, kurulum için internet erişimi ve en az 10 GiB boş sistem diski alanı. Bazı isteğe bağlı araçlar daha fazla alan ister. Ağ testi için yazılı yetki ve açık hedef kapsamı gerekir.

PowerShell:

```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.3-wsl.1/bootstrap.ps1' | iex
```

CMD:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.3-wsl.1/bootstrap.ps1' | iex"
```

Komut [sürüm etiketli başlangıç betiğini](https://github.com/ubden/ubden-cyber-wsl/blob/v4.8.3-wsl.1/bootstrap.ps1) çalıştırır. Betik kaynak paketini indirir, mevcut Kali WSL kurulumunu kullanır veya eksikse kurar, bağımlılıkları hazırlar ve görev sihirbazını açar. Windows yeniden başlatması gerekirse işlem sonraki oturumda devam eder. Kurulum yönetici izni isteyebilir.

WSL için mirrored ağ ve DNS tünelleme ayarları uygulanır. Bu ayarlar bilgisayardaki **tüm WSL 2 dağıtımlarını** etkiler. UBDEN kurulum sırasında Windows ve Kali ağ görünürlüğünü denetler; VPN ve fiziksel adaptör davranışı kullanılan sürücü ve ağ yapılandırmasına bağlıdır.

## Bir görev nasıl yürür?

1. **Kapsam belirleme:** Sihirbazda müşteri, yetki referansı, test ekibi, IP/FQDN/CIDR hedefleri, hariçler ve kullanılacak Windows adaptörleri girilir. Adaptör alt ağları yalnızca öneri olarak gösterilir.
2. **Ön kontrol:** Ağ yolu, DNS çözümlemesi, erişim ve araç yeterlilikleri denetlenir. Kapsam ve FQDN adresleri görev için sabitlenir.
3. **Kontroller:** Seçilen profile ve bulunan servislere uygun modüller çalışır. Kapsam dışı yönlendirmeler izlenmez; eksik araçlar ve erişilemeyen hedefler adım günlüğüne işlenir.
4. **İnceleme ve teslim:** Otomatik gözlemler, cihaz envanteri ve kanıtlar raporlanır. Analist doğruladığı bulguları ve manuel test sonuçlarını görev kaydına ekler.

### Çalışma profilleri

| Profil | Odak |
| --- | --- |
| `external` | DNS/WHOIS, temel TCP servisleri, HTTP başlıkları ve TLS. |
| `web` | Web servisleri, HTTP/TLS kontrolleri, Nikto ve seçilen Nuclei şablonları. |
| `network` | Host keşfi, TCP servisleri, seçilmiş Nmap kontrolleri ve uygun hedeflerde salt okunur SNMP sorgusu. |
| `full` | Birleşik ağ ve web akışı; sağlanan test hesaplarıyla isteğe bağlı kimlikli ve rol karşılaştırmaları. |

AD, Windows test tarayıcısı, SSH test hesabı, kablosuz değerlendirme ve Claude AI analist yorumu görevde ayrıca seçilir. AI yorumu ve otomatik eşleşmeler taslak olarak işaretlenir; doğrulanmış güvenlik bulgusu analist kaydıyla oluşturulur.

Claude AI seçildiğinde dış hizmete gönderilecek veri düzeyi ayrıca belirlenir ve aktarım için sihirbazda onay alınır.

### Operasyon sınırları

- Görev başına en fazla **30 hedef**; en geniş **`/24` IPv4** veya **`/120` IPv6** ağı.
- Nmap taramaları için varsayılan **250 paket/sn**, üst sınır **500 paket/sn** ve hedef başına en fazla **1000 TCP portu**.
- Canlı SSH parola kontrolü yalnızca sağlanan test hesabında, hesap başına en fazla iki adayla yapılır.
- Ham 802.11 kontrolleri için Kali içinde doğrulanmış monitör modlu adaptör gerekir. Windows'un dahili Wi‑Fi bağlantısı IP tabanlı LAN testleri için kullanılabilir.
- Test adımlarındaki zaman aşımı, hata ve atlama nedenleri raporda görünür. Ulaşılamayan hedefler test edilmiş kabul edilmez.

## Raporlar ve kanıtlar

Her görev için ayrı bir çıktı klasörü oluşturulur. Kali masaüstü oturumunda varsayılan konum `~/Desktop/UBDEN-Cyber-Reports/`, diğer ortamlarda `/opt/ubden-cyber/runs/` dizinidir.

| Dosya | İçerik |
| --- | --- |
| `YONETICI_OZETI.pdf` | İçindekiler, kapsam ve ağ yolu, kontrol durumu, doğrulanmış risk dağılımı ve düzeltme öncelikleri. |
| `TEKNIK_RAPOR.pdf` | Test yöntemi, kontrol matrisi, AD ve ağ bağlamı, cihaz/servis envanteri, ayrıntılı bulgu kartları ve kanıt zinciri. |
| `ANALIST_GOREV_RAPORU.pdf`, `.md`, `.json` | Gözlemlere göre önceliklendirilmiş analist adımları, hedefler, müşteri girdileri, örnek komutlar ve kanıt listesi. |
| `REPORT.html` | Çevrimdışı incelenebilen; bulgu, kapsam ve cihaz tablolarıyla yerel kanıtlara bağlantı veren rapor. |
| `engagement.json`, `steps.json` | Sabitlenen görev kapsamı ve gerçek yürütme günlüğü. |
| `DEVICE_INVENTORY.json`, `TOOL_ENVIRONMENT.json` | Cihaz sınıflandırması, host adı ve OS tahmini ile araçların kurulum/çalışma durumu. |
| `ASSESSMENT_COVERAGE.json` | Otomatik ve manuel kontrollerin yürütme durumu, atlama gerekçesi ve kanıt bağlantıları. |
| `SHA256SUMS.txt` | Görev dosyalarının SHA-256 özetleri. |

[Yönetici raporu örneği](examples/ORNEK_UBDEN_YONETICI_OZETI.pdf) · [Teknik rapor örneği](examples/ORNEK_UBDEN_TEKNIK_RAPOR.pdf) · [Analist raporu örneği](examples/ORNEK_UBDEN_ANALIST_GOREV_RAPORU.pdf)

Örnek raporlar tamamen sentetik veriyle üretilmiştir. Canlı tarama veya müşteri sonucu içermez.

Rapor motoru doğrulanmış bulguları otomatik gözlemlerden ayrı tutar. Bulgu kartları önem derecesi, etkilenen varlıklar, erişim noktası, kullanıcı profili, kök neden, tekrar üretim, iş etkisi, düzeltme, yeniden test ve SHA-256 ile doğrulanan birden fazla kanıtı destekler. Servis tespitiyle görülen Telnet, FTP, SMB, RDP ve veritabanı portları doğrudan zafiyet sayılmaz; inceleme adayı olarak kaydedilir. Analist incelemesinde web, ağ, AD, yama, paylaşım, protokol ve kablosuz test başlıkları ayrı durum ve kanıtla takip edilir.

Analist incelemesi ve mevcut görevin yeniden raporlanması Kali içinde yapılır:

```bash
ubden-cyber --analyst-review /gorev/klasoru
ubden-cyber --report-only /gorev/klasoru
```

`--report-only` mevcut kanıtlardan raporu yeniden üretir. Analist incelemesi yeni bulgu ekleme, mevcut bulguyu düzenleme, yeniden test durumunu yazma ve ek kanıt bağlama akışlarını içerir.

Resmî Kali `wordlists` paketi WSL kurulumuna dahildir. Sözlükler yalnız müşterinin sağladığı çevrimdışı hash veya yetkili örneklerde kullanılabilir; canlı IP ya da giriş ekranında toplu parola denemesi akışına bağlanmaz.

## Kurulum ve ortam yönetimi

Tek satırlık kurulumdan sonra Windows giriş betiği `%LOCALAPPDATA%\Programs\UBDEN-Cyber\v4.8.3-wsl.1\ubden-wsl.ps1` konumundadır:

```powershell
$ubden = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber\v4.8.3-wsl.1\ubden-wsl.ps1'
& $ubden -Action status
& $ubden -Action run
```

`status` kurulum ve ağ durumunu gösterir; `setup` ortamı hazırlar; `run` sihirbazı açar. Kaynak koddan doğrudan Kali veya Debian tabanlı Linux kurulumu için `bash install.sh` kullanılabilir.

**Tam WSL imhası:** `destroy`, raporları WSL dışındaki seçilen klasöre SHA-256 ile doğrulayarak aktarır ve açık son onaydan sonra **bilgisayardaki tüm WSL dağıtımlarını**, Ubuntu dahil, kalıcı olarak kaldırır. Bu işlem yalnız tüm WSL ortamının kaldırılması istendiğinde kullanılmalıdır.

```powershell
$ubden = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber\v4.8.3-wsl.1\ubden-wsl.ps1'
& $ubden -Action destroy -ExportTo 'D:\UBDEN-Rapor-Devir'
```
