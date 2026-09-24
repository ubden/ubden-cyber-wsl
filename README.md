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
| Kanıt ve raporlama | Her adımın durumu ve kanıtı kaydedilir; yönetici PDF, teknik PDF, HTML raporu ve makine tarafından okunabilir çıktılar üretilir. |

Araç kataloğu 83 aracı kurulum, sürüm, yetenek ve görevde kullanım durumuyla izler. Hangi kontrollerin çalıştığı veya hangi ön koşul nedeniyle atlandığı raporda ayrı gösterilir.

## Windows üzerinde hızlı başlangıç

**Gereksinimler:** Windows 11 22H2 veya üzeri, sanallaştırma desteği, yönetici yetkisi, kurulum için internet erişimi ve en az 10 GiB boş sistem diski alanı. Bazı isteğe bağlı araçlar daha fazla alan ister. Ağ testi için yazılı yetki ve açık hedef kapsamı gerekir.

PowerShell:

```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.1-wsl.4/bootstrap.ps1' | iex
```

CMD:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.1-wsl.4/bootstrap.ps1' | iex"
```

Komut [sürüm etiketli başlangıç betiğini](https://github.com/ubden/ubden-cyber-wsl/blob/v4.8.1-wsl.4/bootstrap.ps1) çalıştırır. Betik kaynak paketini indirir, mevcut Kali WSL kurulumunu kullanır veya eksikse kurar, bağımlılıkları hazırlar ve görev sihirbazını açar. Windows yeniden başlatması gerekirse işlem sonraki oturumda devam eder. Kurulum yönetici izni isteyebilir.

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
| `YONETICI_OZETI.pdf` | Yönetim için kapsam, değerlendirme durumu ve öncelikli sonuçlar. |
| `TEKNIK_RAPOR.pdf` | Servis ve cihaz envanteri, bulgular, yöntem ve kanıt yolları. |
| `REPORT.html` | Çevrimdışı incelenebilen, yerel kanıtlara bağlantı veren rapor. |
| `engagement.json`, `steps.json` | Sabitlenen görev kapsamı ve gerçek yürütme günlüğü. |
| `DEVICE_INVENTORY.json`, `TOOL_ENVIRONMENT.json` | Cihaz sınıflandırması ve araçların kurulum/çalışma durumu. |
| `SHA256SUMS.txt` | Görev dosyalarının SHA-256 özetleri. |

[Yönetici raporu örneği](examples/ORNEK_UBDEN_YONETICI_OZETI.pdf) · [Teknik rapor örneği](examples/ORNEK_UBDEN_TEKNIK_RAPOR.pdf)

Örnek raporlar sentetik verilerle üretilmiştir. Canlı test sonucu içermez.

Analist incelemesi ve mevcut görevin yeniden raporlanması Kali içinde yapılır:

```bash
ubden-cyber --analyst-review /gorev/klasoru
ubden-cyber --report-only /gorev/klasoru
```

`--report-only` mevcut kanıtlardan raporu yeniden üretir. Analist incelemesinde doğrulanmış bulgular için açıklama, etki, tekrar üretim, düzeltme önerisi ve görev klasöründeki kanıt kaydedilir.

## Kurulum ve ortam yönetimi

Tek satırlık kurulumdan sonra Windows giriş betiği `%LOCALAPPDATA%\Programs\UBDEN-Cyber\v4.8.1-wsl.4\ubden-wsl.ps1` konumundadır:

```powershell
$ubden = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber\v4.8.1-wsl.4\ubden-wsl.ps1'
& $ubden -Action status
& $ubden -Action run
```

`status` kurulum ve ağ durumunu gösterir; `setup` ortamı hazırlar; `run` sihirbazı açar. Kaynak koddan doğrudan Kali veya Debian tabanlı Linux kurulumu için `bash install.sh` kullanılabilir.

**Tam WSL imhası:** `destroy`, raporları WSL dışındaki seçilen klasöre SHA-256 ile doğrulayarak aktarır ve açık son onaydan sonra **bilgisayardaki tüm WSL dağıtımlarını**, Ubuntu dahil, kalıcı olarak kaldırır. Bu işlem yalnız tüm WSL ortamının kaldırılması istendiğinde kullanılmalıdır.

```powershell
$ubden = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber\v4.8.1-wsl.4\ubden-wsl.ps1'
& $ubden -Action destroy -ExportTo 'D:\UBDEN-Rapor-Devir'
```
