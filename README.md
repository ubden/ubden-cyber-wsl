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

### v5 yenilikleri

- **Platform ve teknoloji tespiti:** Sanallaştırma (VMware ESXi/vCenter, Proxmox, Hyper-V), ağ güvenliği (FortiGate, Sophos, Cisco IOS-XE/ASA/IOS, MikroTik, Ubiquiti, Zyxel, pfSense, OPNsense, Aruba, Ruijie), depolama/yönetim (Synology, QNAP, TrueNAS, Dell iDRAC, HPE iLO, IPMI/BMC) ve kamera (Dahua, Hikvision, Axis, Avenir, Neutron) platformları; gözlenen sürüm, yönetim portları ve doğrulanacak üretici/CVE danışmalarıyla.
- **Canlı NVD CVE zenginleştirme:** Güvenilir CPE eşlemesi olan platform+sürümler için NVD 2.0'dan CVE adayları (çevrimdışı/hata durumunda raporu bloke etmez; adaylar analist doğrulaması bekler).
- **Çapraz-katman maruziyet korelasyonu:** Dış e-posta duruşu (DMARC/SPF), keşfedilen kullanıcı adları ve iç ağ yüzeyi birleştirilerek adlandırılmış saldırı zincirleri, maruziyet indeksi ve saldırı-yüzeyi grafiği. İnternete açık yönetim düzlemi, veritabanı, uzaktan erişim, NAS ve kamera için ayrı maruziyet kuralları.
- **CWE eşlemesi** ve geliştirilmiş görsel rapor (risk göstergeleri, KPI kutuları, ilişki grafiği, koyu siber kapak).
- **Varsayılan kimlik denemesi (opt-in, sınırlı):** Yalnız operatör açıkça etkinleştirirse ve yazılı yetkili kapsamda; tespit edilen markalarda kamuya açık üretici varsayılanları servis başına sınırlı ve tek denemeyle bellek içinde sınanır. Sözlük/kaba-kuvvet değildir; parola görev dosyasına veya rapora yazılmaz. Telnet, FTP, SSH ve HTTP Basic servisleri kapsanır.

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

- WSL 2 ve sanallaştırma desteği, yönetici yetkisi. Mirrored ağ için Windows 11 22H2 veya üzeri önerilir; daha eski Windows sürümlerinde kurulum durmaz, otomatik olarak NAT ağıyla devam eder. UBDEN Kali WSL'yi kurar; mevcut Kali varsa kullanır.
- Temel kurulum için en az 10 GiB boş disk; GVM ve geniş araç kataloğu da seçilecekse hem Windows sistem diskinde hem Kali dosya sisteminde en az 30 GiB boş alan. 16 GiB RAM önerilir; büyük envanterlerde daha fazla kaynak gerekebilir.
- Kali paketleri ve resmî IEEE MAC kayıtları için kurulum sırasında internet; test sırasında müşterinin onayladığı hedeflere ağ erişimi. VPN kullanılacaksa test bilgisayarındaki profil ve gerekli MFA yöntemi önceden hazırlanmalıdır.
- Kablolu erişim tercih edilir. Dahili Wi‑Fi IP tabanlı ağ testlerini destekleyebilir; ham 802.11 kontrolü için Kali'de sürücü ve monitör modu doğrulanmış uyumlu USB Wi‑Fi adaptörü gerekir.
- Çıktıları teslim etmek için müşteri tarafından belirlenmiş WSL dışı güvenli dosya konumu. Hesap, token ve sırlar rapora kaydedilmez.

## Windows üzerinde hızlı başlangıç

**Gereksinimler:** WSL 2 ve sanallaştırma desteği, yönetici yetkisi, kurulum için internet erişimi ve en az 10 GiB boş sistem diski alanı. Mirrored ağ modu için Windows 11 22H2 veya üzeri önerilir; daha eski sürümlerde NAT ağıyla devam edilir. Bazı isteğe bağlı araçlar daha fazla alan ister. Ağ testi için yazılı yetki ve açık hedef kapsamı gerekir.

PowerShell:

```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v5.0.0-wsl.40/bootstrap.ps1' | iex
```

CMD:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v5.0.0-wsl.40/bootstrap.ps1' | iex"
```

Komut [sürüm etiketli başlangıç betiğini](https://github.com/ubden/ubden-cyber-wsl/blob/v5.0.0-wsl.40/bootstrap.ps1) çalıştırır. Betik kaynak paketini indirir, mevcut Kali WSL kurulumunu kullanır veya eksikse kurar, bağımlılıkları hazırlar ve görev sihirbazını açar. Windows yeniden başlatması gerekirse işlem sonraki oturumda devam eder. Kurulum yönetici izni isteyebilir.

Kurulum önce mirrored ağı ve DNS tünellemeyi dener. Mirrored yapılandırması bilgisayardaki **tüm WSL 2 dağıtımlarını** etkiler. Mirrored başlatılamazsa Kali IPv4 adresi ve varsayılan rota doğrulanarak NAT ağında devam edilir. IP tabanlı LAN testlerinde Windows adaptör rotası ve Kali rotası her hedef için ayrıca denetlenir; hedefe erişim doğrulanmadan test başarılı sayılmaz. NAT modunda Kali fiziksel Windows ağ kartlarını doğrudan görmez. Ham katman-2, yayın trafiği, pasif fiziksel ağ yakalama ve bazı VPN yolları için ayrı uygunluk denetimi gerekir. Kullanılan ağ modu görev raporuna yazılır.

Windows'un kendi Wi‑Fi IP adresine Windows'tan `ping` atılması, aynı adrese Kali WSL'den erişilebildiğini göstermez. Kapsam içindeki seçili Windows adaptör adresleri cihaz envanterinde ayrı bir kanıt sınıfı olarak gösterilir. Kali yanıt alamazsa bu adresler servis taraması yapılmış cihaz sayısına eklenmez; raporda erişim doğrulanamadı olarak görünür. CIDR keşfi, ICMP'ye ek olarak 16 yaygın servis portunda sınırlı TCP SYN yoklaması yapar. İkisine de yanıt vermeyen bir cihazın kapalı olduğu varsayılmaz. Ayrıca her taramada, ayrıcalıklı **SYN taramasının bir yönlendirici/güvenlik duvarı ardındaki hostlarda “filtrelenmiş” dönmesi** (ör. başka VLAN'daki IP telefonları) durumuna karşı, işletim sistemi TCP yığınını kullanan bir **TCP connect (-sT) doğrulama taraması** yüksek değerli portlarda (SIP 5060, SCCP/MGCP 2000/2427, web, yönetim) çalışır ve sonuçları birleştirir; böylece SYN'in kaçırdığı VoIP/servis portları görülür ve cihazlar sınıflandırılabilir. Gözlenen **TTL** değeri de bir cihaz-ailesi ipucu (Windows 128 / Linux-gömülü 64 / ağ cihazı 255) olarak kaydedilir. Ek olarak **mDNS/Bonjour (5353), SSDP/UPnP (1900) ve LLDP (0x88cc)** keşfi çalışır: cihazlar kimlik doğrulamadan **ad ve tip** bilgisini gönüllü açıklar (yazıcı `_ipp._tcp`, Apple `_apple-mobdev`, medya `_googlecast/_airplay`, NAS `_afpovertcp`, Roku/UPnP `SERVER` başlığı) — böylece port taraması “bilinmiyor” bıraktığı yazıcı/AV/IoT cihazları adlandırılıp sınıflandırılır. LLDP ham L2 yakalama gerektirir (Linux/Kali; Windows'ta Npcap yakalama yolu yoksa atlanır).

## Windows-native alternatif: uPenetrator (tarayıcı arayüzü, WSL'siz)

WSL NAT ağında Kali fiziksel adaptörün L2 komşuluğuna giremediği için ARP/MAC ve
cihaz tanımlama boş kalabilir. **uPenetrator**, tamamen Windows'ta çalışan ve
Npcap ile gerçek L2/ARP erişimi olan alternatif bir tarayıcıdır: **aynı rapor
motorunu** kullanır ama MAC adresi ile üretici/kategori/rol alanlarını doldurur.
Tarayıcı üzerinden bir arayüzle (yerel `127.0.0.1`) çalışır; WSL gerektirmez.

**Gereksinimler:** Windows 10 2004+ / Windows 11, yönetici yetkisi, Npcap
(Nmap ile birlikte kurulur), kurulum için internet. Kurucu Python 3.13'ü (winget)
ve Nmap+Npcap'i kurar.

İkinci tek satırlık kurulum — PowerShell:

```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v5.0.0-wsl.40/bootstrap-win.ps1' | iex
```

CMD:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v5.0.0-wsl.40/bootstrap-win.ps1' | iex"
```

Kurucu kaynağı indirir, ayrı bir yönetici penceresinde `ubden-win.ps1`'i çalıştırır,
Python ortamını ve Nmap+Npcap'i hazırlar ve varsayılan tarayıcıda yerel arayüzü
açar. Arayüzde müşteri/proje/yetki bilgisi, hedefler ve fiziksel adaptör seçilir;
tarama Nmap ile ARP açık (fiziksel adaptörde MAC yakalanır) çalışır ve WSL sürümüyle
**birebir aynı** REPORT.html + PDF raporlarını üretir. Raporlar
`%LOCALAPPDATA%\UBDEN-Cyber\Reports\<GOREV>` altına yazılır. Arayüz yalnızca
`127.0.0.1`'e bağlanır ve tek kullanımlık bir jeton ile korunur; dışarı açılmaz.
Bu sürüm WSL kurulumunu değiştirmez; ikisi yan yana kullanılabilir.

**Eş zamanlı yürütme paneli:** Birden çok hedef paralel **şeritlerde** taranır
(arayüzde "Eş zamanlı şerit", varsayılan 3, en çok 6). Paket hızı bütçesi şeritlere
bölünür (`şerit başı = hız ÷ şerit`), böylece paralel tarama toplam hız sınırını
aşmaz ve IDS'i tetiklemez. Her şerit bir hedeftir; kilitlenmeye duyarlı kimlik
denemeleri hedef başına sıralı kalır (aynı host hiçbir zaman paralel kimlik denemesi
görmez). Panel her şeridin anlık adımını ve durumunu canlı gösterir; yürütme zaman
çizelgesi `UBDEN_EXECUTION.json` iş defterine yazılır.

**Güvenlik yazılımı (test makinesi):** Kurulumda operatör onayıyla Windows Defender
gerçek-zamanlı koruma ve Güvenlik Duvarı geçici olarak kapatılır ve araç klasörlerine
istisna eklenir; böylece tarama araçları (nuclei/sslscan/nmap) karantinaya alınmaz.
Durum doğrulanır; `ubden-win.ps1 -Action status` geri açma komutlarını gösterir.

**Kimlikli / kurumsal testler:** Arayüzde AD/LDAP (alan, DC, salt-okunur hesap),
Web/Swagger URL ve SSH bilgileri girilebilir; her biri için **bağlantı testi** butonu
vardır. Parolalar yalnız yerel oturumda bellekte kullanılır, rapora/görev dosyasına
yazılmaz. AD host domain üyesiyse kimlik bilgisiz de yerel AD envanteri çekilir.

**Derin AD değerlendirmesi (salt-okunur, tek test hesabı):** Kimlikli çalıştırıldığında
LDAP ile şunlar toplanır ve **taslak bulgulara** dönüşür: parola/kilitlenme politikası ve
MachineAccountQuota; kullanıcı/grup/bilgisayar **ad listeleri**; test hesabımızın kendi
üyelikleri; **hassas grup üyelikleri** (Domain/Enterprise/Schema Admins, Account/Backup/
Server/Print Operators, DnsAdmins, Remote Desktop/Protected Users…); **userAccountControl
risk bayrakları** (devre dışı, parola gerekmiyor, parolası hiç bitmiyor, tersinir şifreleme,
kısıtlanmamış yetkilendirme); **Kerberoast** (SPN’li hesaplar) ve **AS-REP roast**
edilebilir hesaplar; **bilgisayar OS envanteri** + 90+ gün bayat hesaplar; ve **şifresiz
LDAP SIMPLE bağlanma** kabul ediliyorsa (LDAP imzalama/kanal bağlama zorlanmıyor) bir bulgu.
AD bilgisayarlarının `dNSHostName` kayıtları IP’ye çözülüp cihaz envanterindeki **isimleri ve
sunucu/PC sınıfını** doldurur (L2/NBSTAT erişilemeyen alt ağlarda bile hostname gelir). Kapsam
tek /24 alt ağdan büyük kurumsal ağlara kadar **20.480 adrese** kadar desteklenir.

Ayrıca **pasif ADCS değerlendirmesi** (salt-okunur LDAP): Sertifika Yetkilileri, yayınlanan
şablonlar ve **ESC1-ESC4** adayları — şablon güvenlik tanımlayıcısı (DACL) çözümlenerek *hangi
düşük yetkili grubun gerçekten kayıt/yazma yapabildiği* doğrulanır (yalnız bayrağa bakan
araçların yanlış-pozitiflerinden kaçınır; ESC6/ESC7/ESC8 Attack Mode/certipy ile). Ve
**SYSVOL / Group Policy Preferences** taraması: `net use` ile SYSVOL bağlanıp GPP XML’lerindeki
**cpassword** değerleri Microsoft’un yayımladığı anahtarla çözülür (kritik bulgu; Windows-native
yolda, WSL/Kali’de nxc `--gpp-password`). Ayrıca **GPO** listesi ve `gPLink` bağlantıları (hangi
politika hangi OU/etki alanına uygulanıyor), **OU kullanıcı dağılımı** ve **yönetici-benzeri özel
gruplar** (ör. GPO ile yerel admin dağıtan bir grup, üyeleriyle) çıkarılır.

**Riskli AD (BloodHound-benzeri, salt-okunur):** Ayrıcalıklı hesaplar (Domain Admins üyeleri)
üzerinde **güvenli/Tier-0 olmayan** bir principal'ın tehlikeli hakkı (GenericAll/Write, WriteDacl/
Owner, **parola sıfırlama**, **DCSync**, **shadow credentials / msDS-KeyCredentialLink**) güvenlik
tanımlayıcısı (DACL) çözülerek tespit edilir; **kısıtlı yetkilendirme** (msDS-AllowedToDelegateTo,
T2A4D protokol geçişi) ve **RBCD** (msDS-AllowedToActOnBehalfOfOtherIdentity) listelenir — hepsi
taslak bulgu. Ve **VMware vCenter/ESXi kimliksiz sürüm ifşası**: vSphere SDK'ya (`/sdk`)
RetrieveServiceContent SOAP çağrısıyla `about.fullName`/sürüm/derleme (ör. "vCenter Server 6.7.0
build-19299595") kimlik doğrulamadan okunur; hem cihazı hypervisor olarak kimliklendirir hem de
CVE eşlemesi için kesin derleme numarasını verir.

**Ağ adaptörü tespiti (Windows-native):** gerçek NIC’ler artık `Get-NetAdapter` + WMI
`Win32_NetworkAdapter (PhysicalAdapter)` birleşimiyle bulunur; `Get-NetAdapter`’ın atladığı gizli/
kablosu-çekik fiziksel kartlar da listelenir ve her adaptör **fiziksel / sanal / VPN** olarak
etiketlenir (Hyper-V vEthernet, WSL, VMware, loopback vb. sanal sayılır). Arayüzde IP’si olmayan
fiziksel kartlar da gösterilir (bağlanınca seçilebilir).

**Agentic AI operatör (opsiyonel):** Bir Claude API anahtarı verilirse tarama sonunda
AI operatör (a) topladığı kanıttan **allowlist'li, salt-okunur, kapsam içi** takip
kontrolleri (NSE/HTTP) önerip kod tarafında doğrulanarak çalıştırır, (b) AD /
sanallaştırma / firewall-ağ / DB-SQL / kamera / web için **derin analiz** yapıp
yapılandırılmış bulgular üretir (`claude-sonnet-5` + `claude-opus-5-5`). AI bulguları
raporda **taslak** olarak görünür; insan "doğrulandı" + SHA-256 ayrı ve üst bir eşiktir.
Claude hiçbir şeyi kendi çalıştırmaz (yalnız menüden seçer), anahtar bellekte kalır.
Böylece analiste kalan iş asgariye iner.

**Attack Mode & Auto Analist (opsiyonel, %100 izole eklenti):** Tarama bittikten sonra
arayüzde beliren **"Attack Mode & Auto Analist Start"** butonu (veya `ubden-win offensive`)
`offensive-ext/` saldırı aşamasını çalıştırır: bizim ürettiğimiz run klasörünü girdi alıp
bulunan hostlara karşı **gerçek AD saldırı zinciri** yürütür (kerberoast, AS-REP, ADCS/
certipy, BloodHound, SMB kimlik-matrisi/paylaşım, offline crack) ve bulguları **aynı
müşteri raporuna** işler. Bu araçlar Linux/Kali içindir; buton bunları **Kali WSL** üzerinde
çalıştırır (Windows run klasörüne `/mnt` ile erişir), rapor Windows tarafında yeniden
üretilir. Kapsam, görevin **dondurulmuş hedefleridir** (kapsam dışı host düşürülür).
**Varsayılan salt-okunur**; yazma işlemleri + DCSync (tam domain NTLM dump) yalnız ayrı bir
onay kutusuyla, yazılı müşteri onayıyla açılır. **Tek seferlik kurulum:** `ubden-win setup-offensive`
— Kali WSL yoksa **önce onu kurar** (`wsl --install -d kali-linux`; genellikle **yeniden başlatma**
ister, Kali ilk açılışta kullanıcı hesabı oluşturmanızı bekler — sonra komutu tekrar çalıştırın),
ardından offensive-ext'i ve araçlarını Kali'ye kurar. **Kali/WSL hazır değilken butona basarsanız**
saldırı **başlamaz**: konsolda net bir uyarıyla "önce `ubden-win setup-offensive` çalıştırın" der
(buton, yeniden-başlatma gerektiren ağır WSL kurulumunu tarama iş parçacığından sessizce tetiklemez).
**Yeniden başlatma sonrası** (ör. `setup-offensive` Kali kurup PC'yi yeniden başlatınca) arayüz ve
canlı tarama durumu sıfırlanır; **her şeyi baştan yapmanız gerekmez** — üst kısımdaki **"⚔ Geçmiş
taramalar"** paneli `%LOCALAPPDATA%\UBDEN-Cyber\Reports` altındaki eski taramaları listeler; her biri
için **"⚔ Attack"** (o run klasörüne karşı saldırı) ve **"Rapor"** (raporu aç) düğmesi sunar. Yani
yeni tarama yapmadan, geçmiş bir taramayı seçip saldırı aşamasını başlatabilirsiniz.
Eklenti tamamen isteğe bağlıdır — hiç çalıştırılmazsa çekirdek
tarama/rapor akışı **bit-for-bit aynı** kalır. Parola argv'ye yazılmaz (CLI'de sorulur);
saldırı çıktısı web konsolunda canlı izlenir.

**Acil durdurma (kill-switch):** Saldırı çalışırken web arayüzünde **⛔ DURDUR (acil)** düğmesi
görünür. Basıldığında üç katman devreye girer: (1) run klasörüne `STOP` dosyası yazılır —
offensive-ext her adımdan **önce** kontrol eder ve temiz durur (kısmi kanıt saklanır); (2)
Windows'taki `wsl.exe` süreç ağacı `taskkill /T` ile sonlandırılır; (3) Kali tarafındaki araçlar
(`pipeline.py`, impacket, certipy, nxc, bloodhound, hashcat…) `pkill` ile kapatılır. offensive-ext
ayrıca kendi kendini korur: bir **hesap kilitlenme sinyali** görürse HARD-STOP yapar ve kimlik
reddedilirse yayılmadan durur. **Dürüst sınır:** STOP adımlar *arasında* etkindir; o an çalışan tek
bir adım (ör. bir BloodHound toplaması) süreç sonlandırmayla kesilir. Varsayılan salt-okunur mod
tek yetkili test hesabını kullanır, sözlük/püskürtme yapmaz — bu yüzden ağ/hesap riski düşüktür.

Windows kurulumunda `HypervisorPlatform` yeni etkinleştirildiyse **Windows'u yeniden başlatın**. UBDEN yeniden başlatma gerektiğini ağ testine geçmeden bildirir ve kurulumu sonraki oturum için kaydeder. Yeniden başlatmadan WSL dağıtımı açılmayabilir.

Mirrored WSL `0x8007054f` hatası verirse ve Windows'un IPv4/IPv6 TCP dinamik port aralığı tam olarak `1024–65534` ise kurulum önce eski değerleri kaydeder, iki TCP aralığını Windows varsayılanı olan `49152–65535` aralığına alıp ağı yeniden doğrular. Doğrulama başarısızsa eski değerler geri yüklenir ve çalışan NAT ağına geçilir. Daha önce başarısız olduğu kaydedilmiş mirrored onarımı tekrar uygulanmaz. Başarılı onarım `destroy` sırasında geri alınır. UDP aralıklarına dokunulmaz.

**Rapor gezgini (webui):** Her tarama biter bitmez rapor klasörünün içine kendi kendine yeten
bir çevrimdışı inceleme paneli kopyalanır (`<GOREV>\webui`). `webui\start.cmd` çalıştırılınca yalnız
`127.0.0.1`'e bağlı, tek kullanımlık jetonlu yerel bir sunucu açılır ve rapor tarayıcıda düzenli
bir arayüzle görüntülenir: genel bakış, gözlemler, **cihazlar (hostname'ler, ana yönlendirici/ağ
geçidi vurgusu, sınıflandırma güveni)**, **Active Directory (kullanıcı/grup/bilgisayar adları, test
hesabımızın üyelikleri, Domain Admins üyeleri, parola politikası)**, teknik yüzeyler, CVE adayları,
korelasyon, kapsam ve kanıt gezgini. Panelden analist incelemesi girilip **Yayınla** ile REPORT.html,
üç PDF, görev listesi, yol haritası ve SHA-256 listesi birlikte yeniden üretilir (eski çıktılar
`.webui\backups` altında saklanır). Dosyalar dışarı gönderilmez; her şey yerel kalır.

## Bir görev nasıl yürür?

1. **Kapsam belirleme:** Sihirbazda müşteri, yetki referansı ve test ekibi girilir. IP/CIDR hedefleri ile domain/FQDN hedefleri ayrı alanlarda, hariçler de aynı ayrımla yazılır. Adaptör alt ağları yalnızca öneri olarak gösterilir. DNS adresleri ve toplam hedef adres sayısı profil seçiminden önce kontrol edilir; hatalı kapsam, diğer görev bilgileri yeniden sorulmadan düzeltilir.
2. **Ön kontrol:** Seçilen adaptör, DNS çözümlemesi, rapor diski, gerekli araçlar, AD test bağlamı ve Kali varsayılan rotası kontrol edilir. Sonuç `PREFLIGHT.json` dosyasına kaydedilir; engelleyici sorun varsa hedef taraması başlamaz. Operatör sorunu düzelterek ön kontrolü yeniden çalıştırabilir veya tarama yapmadan ön kontrol raporuyla görevi durdurabilir. Hedef erişimi sonraki rota ve servis adımlarında doğrulanır. Kapsam ve FQDN adresleri görev için sabitlenir.
3. **Kontroller:** Seçilen profile ve bulunan servislere uygun modüller çalışır. Kapsam dışı yönlendirmeler izlenmez; eksik araçlar ve erişilemeyen hedefler adım günlüğüne işlenir.
4. **İnceleme ve teslim:** Otomatik gözlemler, cihaz envanteri ve kanıtlar raporlanır. Analist doğruladığı bulguları ve manuel test sonuçlarını görev kaydına ekler.

Etkileşimli terminalde adaptör listesinde **↑/↓** ile gezilir, **Boşluk veya Enter** ile seçim açılıp kapatılır, en alttaki **Devam et** üzerinde Enter ile ilerlenir. Wi‑Fi gibi varsayılan rotadaki adaptör önceden işaretlenir; seçim hedef kapsamına adres eklemez. Diğer seçim menülerinde ↑/↓ ve Enter kullanılır; Esc sihirbazı iptal eder. Etkileşimsiz terminalde ekranda görünen **sıra numaraları** girilir; Windows `ifIndex` değeri yazılmaz. Hatalı alanlar aynı adımda yeniden sorulur.

### Çalışma profilleri

| Profil | Odak |
| --- | --- |
| `external` | DNS/WHOIS, temel TCP servisleri, HTTP başlıkları ve TLS. |
| `web` | Web servisleri, HTTP/TLS kontrolleri, Nikto ve seçilen Nuclei şablonları. |
| `network` | Host keşfi, TCP servisleri, seçilmiş Nmap kontrolleri ve uygun hedeflerde salt okunur SNMP sorgusu. |
| `full` | Birleşik ağ ve web akışı; sağlanan test hesaplarıyla isteğe bağlı kimlikli ve rol karşılaştırmaları. |

AD, Windows test tarayıcısı, SSH test hesabı, kablosuz değerlendirme ve Claude AI analist yorumu görevde ayrıca seçilir. AI yorumu ve otomatik eşleşmeler taslak olarak işaretlenir; doğrulanmış güvenlik bulgusu analist kaydıyla oluşturulur.

**Kimlikli HTTPS kontrolü (yalnız `full` profili):** Belirlediğiniz tekil web hedefinin seçtiğiniz salt okunur yolunda, örneğin `app.example.com` üzerindeki `/hesabim` sayfasında, anonim ve müşteri tarafından sağlanan test hesabıyla yapılan HTTPS HEAD isteklerinin durum kodları karşılaştırılır. İki farklı test hesabı ve örnek test kaynağı sağlanırsa isteğe bağlı GET rol/IDOR karşılaştırması da tanımlanabilir. `HTTP Basic` uygulama bunu kullanıyorsa, `Bearer` API test tokenı varsa seçilir. **Cookie**, uygulamanın form girişini sizin test hesabınızla tarayıcıda tamamladıktan sonra elde ettiğiniz geçici test oturumunu yalnız seçilen hedefte kullanır; sihirbaz form kullanıcı adı ve parolasını alıp otomatik giriş yapmaz. Bu kontrolü istemiyorsanız **Atla / tamamla** seçilir. Test sırları görev dosyasına veya rapora yazılmaz.

Windows oturumu etki alanına bağlı değilse bağlı oturumla AD incelemesi seçeneği gösterilmez. Müşterinin sağladığı alan adı, DC ve yetkili test hesabı varsa LDAPS incelemesi seçilebilir; yoksa AD adımı atlanır. Tarama adımındaki hata veya zaman aşımı ilgili hedef/modül için kaydedilir; sonraki uygun hedefler çalışmaya devam eder ve rapor tamamlanmamış kontrolleri açıkça gösterir.

Claude AI seçildiğinde dış hizmete gönderilecek veri düzeyi ayrıca belirlenir ve aktarım için sihirbazda onay alınır.

### Operasyon sınırları

- Görev başına en fazla **30 hedef**; en geniş **`/24` IPv4** veya **`/120` IPv6** ağı.
- Her adres ailesinde en fazla **1024 benzersiz test adresi**. IPv4 ağ ve yayın adresleri ile hariç tutulan adresler sayılmaz. Bir `/24` ağında genellikle 254 kullanılabilir IPv4 adresi vardır; buna ayrıca tekil IP ve DNS hedefleri eklenebilir. DNS sonucu değişirse ilgili hedef taranmaz.
- Nmap taramaları için varsayılan **250 paket/sn**, üst sınır **500 paket/sn** ve hedef başına en fazla **1000 TCP portu**.
- Canlı SSH parola kontrolü yalnızca sağlanan test hesabında, hesap başına en fazla iki adayla yapılır.
- Ham 802.11 kontrolleri için Kali içinde doğrulanmış monitör modlu adaptör gerekir. Windows'un dahili Wi‑Fi bağlantısı IP tabanlı LAN testleri için kullanılabilir.
- Test adımlarındaki zaman aşımı, hata ve atlama nedenleri raporda görünür. Ulaşılamayan hedefler test edilmiş kabul edilmez.

## Raporlar ve kanıtlar

Her görev için ayrı bir çıktı klasörü oluşturulur. Windows tek satırlık başlatıcıyla çalıştırıldığında raporlar ve kanıtlar, SHA-256 ile doğrulanarak `%LOCALAPPDATA%\UBDEN-Cyber\Reports\GOREV_ADI` klasörüne de kopyalanır. İşlem sonunda Windows yolu terminalde gösterilir. Windows Gezgini'nde rapor klasörünü açmak için:

```powershell
explorer.exe (Join-Path $env:LOCALAPPDATA 'UBDEN-Cyber\Reports')
```

Kali içindeki asıl görev dosyaları `/opt/ubden-cyber/runs/` altında kalır. Bu dizin root hesabına özel erişimle korunur; Windows Gezgini'nden doğrudan `\\wsl.localhost\kali-linux\opt\ubden-cyber\runs` yolunu açmaya çalışmak erişim hatası verebilir. Kali masaüstü oturumundan açılan görevlerde varsayılan konum `~/Desktop/UBDEN-Cyber-Reports/` dizinidir.

Bir IP'de TCP/443 açık ve TLS sertifikası okunabilirken HTTP yanıtı boş olabilir. Sertifika yalnız bir alan adına aitse IP ile yapılan doğrulamalı HTTPS isteği ad uyuşmazlığı verir. UBDEN, bu durumu açık port, TLS kanıtı ve HTTP hatası olarak ayrı kaydeder; IP kapsamındaki salt okunur HTTP başlık kontrolünü sertifika kimliğini doğrulamadan bir kez tekrar deneyebilir. Sertifikada görülen başka alan adları otomatik olarak hedef kapsamına eklenmez. Yönlendirilen uzak adreslerde MAC görülmemesi olağandır; MAC yalnız aynı katman-2 komşuluğunda doğrulanabilir.

| Dosya | İçerik |
| --- | --- |
| `YONETICI_OZETI.pdf` | İçindekiler, kapsam ve ağ yolu, kontrol durumu, doğrulanmış risk dağılımı ve düzeltme öncelikleri. |
| `TEKNIK_RAPOR.pdf` | Test yöntemi, kontrol matrisi, AD ve ağ bağlamı, cihaz/servis envanteri, ayrıntılı bulgu kartları ve kanıt zinciri. |
| `ANALIST_GOREV_RAPORU.pdf`, `.md`, `.json` | Gözlemlere göre önceliklendirilmiş analist adımları, hedefler, müşteri girdileri, örnek komutlar ve kanıt listesi. |
| `REPORT.html` | Çevrimdışı incelenebilen; bulgu, kapsam ve cihaz tablolarıyla yerel kanıtlara bağlantı veren rapor. |
| `engagement.json`, `steps.json` | Sabitlenen görev kapsamı ve gerçek yürütme günlüğü. |
| `PREFLIGHT.json` | Hedef trafiği başlamadan yapılan görev ve ortam ön kontrollerinin durumları. |
| `DEVICE_INVENTORY.json`, `TOOL_ENVIRONMENT.json` | Cihaz sınıflandırması, host adı ve OS tahmini ile araçların kurulum/çalışma durumu. |
| `ASSESSMENT_COVERAGE.json` | Otomatik ve manuel kontrollerin yürütme durumu, atlama gerekçesi ve kanıt bağlantıları. |
| `UBDEN_INSIGHTS.json`, `ATTACK_LAYER.json` | Kaydedilmiş test yöntemleri ve tipli bulgular için ATT&CK eşlemesi; analist incelemesi bekleyen CVSS önerileri; sağlanan çevrimdışı hash örneklerinin tür sayımı. ATT&CK eşlemesi saldırı başarısı anlamına gelmez. |
| `REMEDIATION_ROADMAP.md` | Yalnız kanıtı doğrulanmış analist bulgularından üretilen düzeltme sırası. |
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

Analist bulgu tipi olarak `kerberoast`, `asrep_roast`, `adcs_esc` veya `cracked_credential` seçtiğinde uygun ATT&CK eşlemesi; desteklenen tiplerde CVSS v3.1 başlangıç vektörü önerilir. Bu öneri gerçek etki ve erişim koşullarına göre analist tarafından gözden geçirilir. Müşterinin ayrıca sağladığı çevrimdışı örnekler görev klasöründeki `offline_samples/` dizinine `.hash` veya `.txt` dosyası olarak konursa `--report-only` sırasında türleri sayılır; ham hash ve hesap değerleri rapora yazılmaz. Dosyalar parola denemesi için otomatik kullanılmaz.

Resmî Kali `wordlists` paketi WSL kurulumuna dahildir. Sözlükler yalnız müşterinin sağladığı çevrimdışı hash veya yetkili örneklerde kullanılabilir; canlı IP ya da giriş ekranında toplu parola denemesi akışına bağlanmaz.

## Kurulum ve ortam yönetimi

Tek satırlık kurulumdan sonra Windows giriş betiği `%LOCALAPPDATA%\Programs\UBDEN-Cyber\v5.0.0-wsl.40\ubden-wsl.ps1` konumundadır:

```powershell
$ubden = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber\v5.0.0-wsl.40\ubden-wsl.ps1'
& $ubden -Action status
& $ubden -Action run
```

`status` kurulum ve ağ durumunu gösterir; `setup` ortamı hazırlar; `run` sihirbazı açar. Kaynak koddan doğrudan Kali veya Debian tabanlı Linux kurulumu için `bash install.sh` kullanılabilir.

**Tam WSL imhası:** `destroy`, raporları WSL dışındaki seçilen klasöre SHA-256 ile doğrulayarak aktarır ve açık son onaydan sonra **bilgisayardaki tüm WSL dağıtımlarını**, Ubuntu dahil, kalıcı olarak kaldırır. Bu işlem yalnız tüm WSL ortamının kaldırılması istendiğinde kullanılmalıdır.

**Windows-native imha (`ubden-win.ps1 -Action destroy`):** Görev bitince Windows tarafını **varsayılana** döndürür (onay için `DESTROY` yazılır; `-Yes` ile sessiz): (1) Windows Defender gerçek-zamanlı korumayı ve Güvenlik Duvarını **geri açar**, eklenen istisnaları kaldırır; (2) güç planını ve ekran koruyucuyu eski haline alır (uyku/hazırda bekleme yeniden etkin); (3) BGInfo masaüstü panelini kaldırıp **önceki duvar kâğıdını** geri getirir; (4) kurduğumuz **venv + araçlar + durum** dosyalarını (`%LOCALAPPDATA%\UBDEN`) siler; (5) isteğe bağlı olarak Kali'deki `offensive-ext` eklentisini ve (ayrı sorup) winget ile Python/Nmap'i kaldırır. **Raporlar korunur** (`%LOCALAPPDATA%\UBDEN-Cyber\Reports`) — teslimattır. Kurulum dizininin kendisi (betik oradan çalıştığı için) elle silinebilir.

```powershell
$ubden = Join-Path $env:LOCALAPPDATA 'Programs\UBDEN-Cyber\v5.0.0-wsl.40\ubden-wsl.ps1'
& $ubden -Action destroy -ExportTo 'D:\UBDEN-Rapor-Devir'
```
