# UBDEN Cyber Security Systems 4.8.1

Ürün ve arayüz **UBDEN®** markasını taşır; **tester / test ekibi adı sihirbazda zorunlu olarak girilir**. Kali menüsüne UBDEN Cyber Security Systems girişi, terminale `ubden-cyber` komutu eklenir. İşletim sistemi teması veya duvar kâğıdı değişmez.

**Amaç:** Yazılı yetki altındaki açıkça belirtilmiş varlıklar için kontrollü dış yüzey taraması ve analist destekli kurumsal raporlama. Bu araç tek başına tam kapsamlı manuel penetrasyon testi yapmaz.

## Windows 11 + Kali WSL girişi

Herkese açık depodaki sürüm etiketinden indirmek, kurmak ve görev sihirbazını açmak için Windows PowerShell'e şu **tek satırı** yapıştırın:

```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.1-wsl.3/bootstrap.ps1' | iex
```

CMD'de aynı işlem:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.1-wsl.3/bootstrap.ps1' | iex"
```

Başlangıç betiği sürüm etiketinin kaynak arşivini `%LOCALAPPDATA%\Programs\UBDEN-Cyber\v4.8.1-wsl.3` altına indirir; gerekli dosyaları denetleyip `ubden-wsl.ps1 -Action run` akışını çalıştırır. Arşiv 100 MiB ve 500 girişle sınırlıdır, tehlikeli yollar ve sembolik bağlar reddedilir. İndirilen betiği çalıştırmadan önce [GitHub'da inceleyebilirsiniz](https://github.com/ubden/ubden-cyber-wsl/blob/v4.8.1-wsl.3/bootstrap.ps1). Windows yeniden başlatması gerekirse kurulum devam bilgisi kaydedilir; yeniden oturum açıldığında kurulum sürdürülüp görev sihirbazı açılır. Tarama, sihirbazda açık hedef ve yazılı yetki girilmeden başlamaz.

Proje klasöründen yerel kullanım için `ubden-wsl.ps1` Windows PowerShell'den çalıştırılır:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ubden-wsl.ps1 -Action status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ubden-wsl.ps1 -Action setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ubden-wsl.ps1 -Action run
```

`run` varsayılandır. `setup` Windows yönetici yetkisi ister; Kali yoksa WSL üzerinden kurar, mevcut Kali dağıtımını yeniden kurmaz, `/opt/ubden-cyber` dizinini ve Kali/Windows bağımlılıklarını hazırlar. `ubden` kullanıcısı varsa parolasını değiştirmez. Yoksa yalnız ilk oluşturma sırasında parola standart girdiden verilir. İlk kurulum APT araçlarına göre uzun sürebilir; kaynak dosyaları değişmediyse sonraki `run` tam kurulumu tekrarlamaz. Gerçek ağ işlemleri ancak sihirbazdaki yazılı yetki, hedef/hariç listesi, adaptör seçimi ve `YETKILIYIM` girişi sonrası başlar.

Windows'taki `.wslconfig` korunarak yedeklenir; `networkingMode=mirrored` ve `dnsTunneling=true` eklenir. Bu değişiklik **Ubuntu dahil tüm WSL 2 dağıtımlarını** etkiler. `status` Windows adaptör, rota, VPN, Kali rota/DNS ve araç envanterini salt okunur gösterir. Mirrored mod IP tabanlı LAN/VPN yolunu mümkün kılar; fiziksel Wi-Fi kartının ham 802.11 monitör modu WSL içinde otomatik olarak oluşmaz. Seçilen USB adaptörü için `usbipd-win` gerekirse resmî winget paketinden kurulur, sonra yalnız girilen BusID bağlanır. Monitör modu ayrıca Kali'de doğrulanır. Verilen LDAPS DC'sine doğrulanmış sayısal IP üzerinden bağlanılır; sertifika adı kontrolü sürer ve LDAP yönlendirmeleri izlenmez.

Mirrored ağ doğrulanamazsa önceki `.wslconfig` geri yüklenir. WSL `0x8007054f` ağ hatası ve kapalı `HypervisorPlatform` birlikte görülürse kurulum bu Windows bileşenini açar, yeniden başlatma gerektiğini kaydeder ve sonraki oturumda `setup` işlemine devam eder. `destroy`, UBDEN'in açtığı bu bileşeni geri kapatır. GVM kurulumu, Kali ve Windows sistem disklerinde en az 30 GiB boş alan varsa denenir.

Sihirbazda görülen adaptör ağları yalnız öneridir. Yalnız açıkça girilen IP/FQDN/CIDR hedefleri ve seçilen Windows adaptör rotaları kullanılır. FQDN ve hariçlerin DNS sonuçları görev başlangıcında kaydedilir; sonraki değişiklikte ilgili hedef engellenir. En fazla 30 hedef, en geniş `/24` IPv4 veya `/120` IPv6, en çok 1000 TCP portu ve 500 paket/sn sınırı vardır. AD bilgileri Windows bağlı oturumundan veya ayrıca girilen LDAPS test hesabından salt okunur alınır. Windows tarayıcısı Edge/Chrome'u tek kullanımlık profilde açar; yalnız sabitlenmiş IP, hedef host ve seçilmiş yollara gider.

Listelediğiniz 83 tarihî araç `TOOL_ENVIRONMENT.json` içinde ayrı ayrı yer alır; kurulum, sürüm, çalıştırılabilirlik, adım ve çalıştırılmama gerekçesi kaydedilir. Nmap/Curl/Nuclei/SNMP çekirdeğine sınırlı `fping`, `hping3`, `nbtscan`, Nikto, AD, tarayıcı, sağlanan SSH test hesabında en çok iki parola adayı ve donanım ön koşullu Wi-Fi adımları eklenmiştir. CIDR içinde bulunan web servislerinden en fazla 16 hostta sınırlı HTTP/TLS ve uygun araç kontrolü çalışır. Katalogdaki diğer paketlerin kurulması otomatik çalıştırıldıkları anlamına gelmez. Ticari/eskimiş araçlar doğrulanmamış URL'den yüklenmez. Wi-Fi adımları yalnız seçilmiş AP/test istemcisinde monitör modu sonrası çalışır; yakalama 10 dakika, çevrimdışı deneme 30 dakika, deauth 3 olay ve WPS 10 deneme tavanıyla sınırlandırılır.

`destroy`, **Kali ve Ubuntu dahil kayıtlı tüm WSL dağıtımlarını kalıcı siler**. Çalıştırmadan önce WSL dışı bir Windows aktarım dizini verin:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ubden-wsl.ps1 -Action destroy -ExportTo D:\UBDEN-Rapor-Devir
```

Betik bilinen, indekslenen ve Kali dosya sisteminde keşfedilen eski görev klasörlerini dosya başına SHA-256 ile karşılaştırıp `EXPORT_MANIFEST.json` üretir; aktarım hata verirse dağıtımları kaldırmaz. Çıktı konumu WSL, proje veya silinecek Windows durum/paket klasörü içinde olamaz. Güncel dağıtım listesini gösterip tamamını içeren açık metin doğrulaması ister; silmeden hemen önce özetleri tekrar karşılaştırır. Ardından WSL uygulaması/bileşeni ve UBDEN Windows durumu temizlenir, önceki `.wslconfig` geri getirilir ve imha tutanağı yazılır. Kaynak proje klasörü kalır.

## Kurulum (Kali Linux / Debian / Ubuntu)

ZIP'i Kali'de indirdikten sonra, dosyanın gerçekten bulunduğu yolu kullanarak açın. Tarayıcınız indirme konumunu değiştirebilir; Windows'ta indirilen ZIP, Kali sanal makinesine kendiliğinden aktarılmaz. Ev dizininizde dosyayı bulup izole bir klasöre açmak için:

```bash
ubden_zip_file="$(find "$HOME" -maxdepth 3 -type f -name 'UBDEN-Cyber-Security-Systems-v4.8.1.zip' -print -quit 2>/dev/null)"
if [ -z "$ubden_zip_file" ]; then
  echo 'ZIP Kali üzerinde bulunamadı. Bağlantıyı Kali tarayıcısında indirip tekrar çalıştırın.'
else
  mkdir -p "$HOME/Desktop/UBDEN-v4.8.1"
  unzip -o "$ubden_zip_file" -d "$HOME/Desktop/UBDEN-v4.8.1"
  cd "$HOME/Desktop/UBDEN-v4.8.1/UBDEN-Cyber-Security-Systems" || exit 1
  bash install.sh
  ubden-cyber --version
fi
```

ZIP daha Kali'ye indirilmediyse önce bu dosyayı Kali tarayıcısıyla indirin veya ana işletim sisteminden aktarın. Kurulum ekranı yeniden açıldığında önceki çalışma raporları silinmez.

Doğrudan proje klasöründeyseniz kurulum için:

```bash
bash install.sh
ubden-cyber
```

Kurulum gerektiğinde sudo ister. Çekirdek için Nmap, Net-SNMP (`snmpget`), ping (iputils-ping), curl, DNS/WHOIS ve sslscan kurulur. Depoda bulunabilen WhatWeb, Nikto, sqlmap, Gobuster, wafw00f, Nuclei, fping, arping, dnsenum, nbtscan, ike-scan, tcpdump ve traceroute ayrı ayrı yüklenir; eksik/başarısız paketler kurulumun sonunda **açıkça** gösterilir. Bunların çoğu uzman tarafından kullanılır; kurulmuş olmaları sihirbazın onları çalıştırdığı anlamına gelmez. Python bağımlılıklarının ardından komut ve dosya sözdizimi doğrulanır.

Kali üzerinde geniş araç grupları istenirse `bash install.sh --extended-tools` komutu bilgi toplama, web, zafiyet ve raporlama meta paketlerini yükler. Depodaki bütün Kali paketleri için `bash install.sh --everything` seçeneği vardır; çok yüksek disk/ağ alanı gerektirebilir. Kali'nin resmi paket grupları zamanla değişebilir. Kurulum seçenekleri otomatik taramaya yeni saldırı yöntemleri eklemez. Kurulumdan önce paketleri kurumunuzun tedarik sürecinde denetleyin.

Kurulum tamamlandığında ön izleme otomatik açılmaz. Görünümü ağ isteği oluşturmadan görmek için `ubden-cyber --preview-ui` çalıştırın. `ubden-cyber` gerektiğinde sudo ister; ön izleme, yardım ve sürüm çıktısı sudo istemez. `--no-color` veya `NO_COLOR=1` renkleri, `--no-animation` hareketi kapatır. SSH çıktıları yönlendirildiğinde terminal renkleri ve animasyon otomatik kapanır. `start.sh` kurulumun oluşturduğu `/opt/ubden-cyber/.venv` yorumlayıcısını kullanır; eksikse anlaşılır bir hata gösterir.

## Sihirbaz

Müşteri ve proje, yazılı izin/sözleşme referansı, açık FQDN/IP/CIDR hedefleri ve hariç tutulan adresleri ister. Tester adını her görevde siz belirlersiniz. Varsayılan hız **250 paket/sn üst sınırı**; Network/Full 1000, External 100 TCP portudur. Hız `--max-rate 1..500` ile ayarlanır. En fazla 30 hedef ve hedef başına en geniş /24 IPv4 veya /120 IPv6 kabul eder. Alt alan adları otomatik eklenmez. Her FQDN'nin tüm çözümlenen IP'lerini ayrı ayrı kontrol eder; müşterinin kapsamı bu IP'leri kapsamıyorsa hedefi eklemeyin. CDN ve paylaşımlı hizmetler için ayrı izin gerekir.

**CIDR taraması:** `/24` veya `/120` girildiğinde önce hariç tutulanlar elenerek sınırlı Nmap `-sn` keşfi yapılır (ICMP ve seçilmiş TCP yoklamaları; vekil ARP tüm IP’leri canlı göstermesin diye otomatik ARP/ND keşfi ve sahte RST yanıtları host kanıtı olarak kullanılmaz). Nmap keşfi en fazla 90 saniye sürer; ardından aynı izinli adreslere hız sınırlı sistem `ping` yoklaması uygulanır. İki keşfin yanıt veren adresleri birleştirilir. Nmap zaman aşımına uğrasa bile `ping 192.168.0.37` yanıt veriyorsa `192.168.0.37` servis taramasına girer ve durum **kısmi** kaydedilir. Yanıt veren IP'ler **tek bir Nmap servis/sürüm taramasına** aktarılır; seçili NSE kontrolleri yalnızca açık port bulunanlara yapılır. `-Pn` yalnızca keşif aşamasını geçen IP'ler için kullanılır. İki yoklama da hiçbir yanıt alamazsa bu CIDR'de servis taraması atlanır, diğer hedefler ve raporlama devam eder; tüm /24'e otomatik port taraması yapılmaz. Yanıt vermeyen IP mutlaka kapalı değildir: ICMP/TCP filtreleniyor olabilir. Böyle bir sistemin yazılı izin kapsamındaki adresini ayrıca tekil IP hedefi olarak belirtin. `discovery_summary.json`, adım günlüğü ve PDF/HTML raporları tamamlanan/kısmi keşfi, kontrol edilen ve yanıt veren IP sayısını gösterir. Ağ veya güvenlik cihazı kesintisinde tüm hostların test edilmesini garanti etmek mümkün değildir.

**Toplu çalışma:** Keşif sonrası yanıt veren IP adresleri için tek bir Nmap `-sS -n` **port keşfi** çağrısı çalışır. `-sV` servis sürümü tanıma yalnızca açık TCP portu tespit edilen adreslere ve bu adreslerde görülen port numaralarına uygulanır. Network/Full profilindeki seçilmiş NSE kontrolleri de açık portlu adreslere toplu çağrıyla yapılır. 254 bağımsız süreç ya da 254 hostta sınırsız eşzamanlı tarama söz konusu değildir. 254 × 1000 / 250 ≈ 1016 saniye, yalnızca paket hızı tavanı altında port yoklamalarının kuramsal **en kısa süresidir**; gerçek süre Nmap'in uyarlamalı zamanlaması, paket kaybı, sürüm ve NSE kontrolleri nedeniyle artar. Varsayılan 250 hız yoğun üretim ağında uygun değilse `--max-rate 50` ile düşürün; üst sınırı yükseltmek Nmap'in o hıza mutlaka ulaşacağı anlamına gelmez. Süre üst sınırı kapsama göre hesaplanır. 254/254 adresin canlı görünmesi olağan dışı olabilir; sanal/vekil ARP davranışını ayrıca doğrulayın.

**SNMPv1/public:** Network/Full profilinde yalnızca keşifle doğrulanan, izinli IP'lerin her birine tek bir Net-SNMP `snmpget -v1 -c public` salt okunur `sysDescr.0` sorgusu gönderilir; en fazla sekiz eşzamanlı sorgu, tekrar denemesi sıfır ve kısa zaman aşımı uygulanır. Yanıt veren IP'ler, kanıt JSON dosyaları ve taslak güvenlik gözlemleri PDF/HTML raporlarında bulunur. Yanıt yokluğu SNMP'nin kapalı olduğunu kanıtlamaz. Başka topluluklar denenmez, SNMP SET yapılmaz. Ayrıntılı cihaz kimliği için yanıtın sysDescr bilgisi envanterdeki diğer ipuçlarıyla birlikte yorumlanır.

**Canlı durum:** ICMP keşfinde adres sayısına göre gerçek yüzde ve gözlenen hızdan yaklaşık kalan süre, Nmap adımlarında `--stats-every 10s` çıktısındaki aşama yüzdesi ve bundan hesaplanan yaklaşık süre gösterilir. Nmap o an yüzde vermezse terminal açıkça "yüzde bekleniyor" der; üst süre sınırı tamamlanma tahmini değildir. SSH/çıktı yönlendirmesinde 15 saniyede bir durum yazılır. Son ekranda işin bitiş durumu ve üretilen dosyalar listelenir. Kali uygulamalar menüsünden açılan terminal kapanmadan önce Enter bekler; normal SSH komutu bitince kabuk istemine döner.

**Cihaz envanteri:** UBDEN üretici OUI bilgisi, sanallaştırma MAC önekleri ve birden fazla servis ipucuyla cihaz sınıfı adayı üretir; belirsizliği açıkça gösterir. Mevcut yetkili Nmap XML kanıtı, varsa tek SNMPv1/public yanıtı ve yerel `ip -j neigh` komşu tablosu birlikte yorumlanır; envanter oluşturma ayrıca ağ trafiği üretmez. `/usr/share/nmap/nmap-mac-prefixes` varsayılan çevrimdışı üretici tablosudur. Daha ayrıntılı IEEE MA-L/MA-M/MA-S kütüphaneleri için resmi `oui.csv`, `mam.csv`, `mas.csv` dosyalarını `data/ieee/` dizinine yerleştirebilirsiniz. Ortak/rasgele MAC ile kanıt yokluğu işaretlenir. Uzak ağın MAC adresi yönlendiriciden öğrenilemez; cihaz kategorisi adaydır, doğrulanmış model veya açık değildir.

Çalışma profilleri: `external`, `web`, `network`, `full`.

| Profil | Otomatik kontroller |
| --- | --- |
| External | DNS/WHOIS, 100 TCP portu, HTTP başlıkları ve TLS |
| Web | Web portları, HTTP başlıkları, OPTIONS yöntemi ve TLS |
| Network | 1000 TCP portu, açık portta servis tespiti, seçilmiş Nmap NSE ve SNMPv1/public salt okunur sorgusu |
| Full | External + Web + Network ve SNMPv1/public; isteğe bağlı kimlikli HTTPS, rol/IDOR ve salt okunur iş kuralı karşılaştırması; manuel kontrol planı ayrı |

Full tüm **yerleşik otomatik** modülleri kapsar. Boş bırakılabilen kimlikli erişim bölümünde en fazla dört hedef/rol için HTTP Basic (kullanıcı/parola), Bearer (API token) veya mevcut test oturumu çerezi girebilirsiniz. Bir hedef ve salt okunur korumalı yol seçilir; yalnızca HTTPS üzerinde, yönlendirme takip etmeden anonim ve kimlikli HEAD istekleri karşılaştırılır. Doğrulama başarısızsa veya uygulama HEAD desteklemiyorsa hata/durum kaydedilir. Form/SSO girişinde geçerli test oturumunun çerezini kullanın; araç oturum açma veya yenileme yapmaz.

Full'de iki veya daha fazla test hesabı girildiyse isteğe bağlı **rol / IDOR / salt okunur iş kuralı** senaryoları tanımlanabilir (en fazla sekiz). Kaynağın sahibi/yetkili hesabı, erişimi reddedilmesi beklenen ikinci hesabı ve test hesabına ait `/api/nesne/123` veya `/api/nesne?id=123` yolunu siz seçersiniz. Sorguda yalnızca sır içermeyen test kimliklerini kullanın. Her hesaptan aynı HTTPS kaynağına bir GET gönderilir; TLS doğrulaması açık, IP sabit, yönlendirme kapalı, yanıt gövdesi diske kaydedilmez ve okuma 64 KB ile sınırlıdır. HTTP 200 aday gözlemdir; giriş sayfası, önbellek veya veri sahipliği nedeniyle gerçek bir IDOR/iş kuralı ihlali olup olmadığını analist doğrulamalıdır. İşlem yapan POST/PUT/DELETE, ödeme, sipariş değiştirme, rol yükseltme gibi iş mantığı senaryoları bu otomasyonla çalıştırılmaz; manuel plan ve müşteri onayıyla yürütülür.

Parolalar, tokenlar ve çerezler gizli terminal istemiyle alınır, işlem belleğinde tutulur; rapor, `engagement.json`, `steps.json` ve subprocess argümanlarına yazılmaz. Yalnızca hedef, rol etiketi, yöntem, port, yol ve HTTP durum kodları kaydedilir. Komut girişindeki yolu sır içermeyecek şekilde seçin. Geçici test hesaplarını tercih edin, test sonunda erişimleri kapatın ve oluşturulan çıktı klasörünü koruyun. Basic yöntemi yalnızca HTTPS üzerinde kullanılır. Kimlikli kontrolü boş bıraktığınızda Full kimliksiz çalışır.

Web/Full sırasında Nuclei sorusunu **boş bırakırsanız 12 gömülü UBDEN şablonu varsayılan seçilir**. Bu küme kök HTTPS güvenlik başlıklarını (5 HEAD kontrolü) ve belirli yaygın tanılama/yapılandırma yolu açıklıklarını (7 GET kontrolü) inceler. Her isteğin yolu ve yöntemi ZIP içindeki `templates/baseline/` altında görülebilir. `0` Nuclei'yi kapatır; `--no-nuclei` de aynı işi yapar. Daha geniş, önceden gözden geçirilmiş bir dizin için `/path/to/reviewed-templates` girin veya `--nuclei-templates /path/to/reviewed-templates` kullanın. Varsayılan küme bütün zafiyetleri, bütün CVE'leri veya kimlikli uygulama iş akışlarını kapsamaz.

Nuclei kurulu değilse diğer testler devam eder, Nuclei adımları **eksik araç** olarak raporlanır. Kurulum Nuclei mevcutsa gömülü şablonları `-validate` ile doğrular ve başarısızlığı gösterir. Çalışma sırasında yalnızca açıkça girilmiş hedefin çözülmüş IP adresi kullanılır; sanal sunucu için Host/SNI bilgisi eklenir. Yönlendirme, OAST ve şablon güncelleme kontrolü kapalı; hız 5 istek/sn, eşzamanlılık 1 ve yanıt okuma üst sınırı 32 KB'dir. Şablonların SHA-256 özetleri görevle kaydedilir. Özel YAML dizininde en fazla 40 sabit `{{BaseURL}}/yol` GET/HEAD isteği kabul edilir; yazma yöntemi, dış URL, ham HTTP ve farklı protokol şablonları görev başlamadan reddedilir. Nuclei eşleşmeleri **taslak** olarak kaydedilir; doğrulanmadan müşteri bulgusu sayılmaz.

Ağ profili HTTP/TLS isteklerini atlar. Diğer profiller giriş adresine HEAD isteği yapar; yönlendirmeleri izlemez ve DNS ile elde edilen adrese sabitler. Nmap bağlantı ve hafif servis algılama kullanır; hız, tekrar ve süre sınırları vardır. Tekil IP/FQDN servis taramasında T3 zamanlama ve host başına 5 dakika, komut başına 6 dakika sınırı kullanılır; keşfedilemeyen servisler başarıyla doğrulanmış sayılmaz. Eksik araç, komut hatası ve zaman aşımı raporda görünür. Üretimde bakım penceresi ve müşteri irtibatını ayrıca teyit edin.

Sınırları değiştirmek için örnek: `ubden-cyber --max-rate 50 --top-ports 200`. Hız **500 paket/sn tavanı**, port sayısı 1000 ile üstten sınırlandırılır. Full/Network varsayılan 1000, External varsayılan 100 TCP portudur. Nmap `-sS` aşaması için sistemin root yetkisi gerekir; `ubden-cyber` gerekirse sudo ister.

## Çıktılar

Kali masaüstü kullanıcı oturumunda varsayılan klasör `~/Desktop/UBDEN-Cyber-Reports/MUSTERI_TARIH_ID/` olur. Görev bitince dosyalar masaüstü kullanıcısına devredilir; klasör erişimi yalnızca sahibine açıktır. Sunucuda masaüstü bulunmuyorsa `/opt/ubden-cyber/runs/MUSTERI_TARIH_ID/` kullanılır. Özel konum için `ubden-cyber --runs /hedef/klasor` yazın.

- `YONETICI_OZETI.pdf`: iş etkisi, öncelik ve kapsam sınırları.
- `TEKNIK_RAPOR.pdf`: servis envanteri, analist bulguları, çalışma adımları ve kanıt yolu.
- `REPORT.html`: çevrimdışı tarayıcı raporu; bulgu detaylarına, mevcut yerel kanıtlara ve oluşturulan PDF'lere tıklanabilir bağlantılar içerir. Geçersiz, kapsam dışı veya bulunamayan kanıt yolu tıklanabilir bağlantıya dönüştürülmez. Kanıt dosyalarıyla aynı görev klasöründe saklayın.
- `MANUEL_TEST_PLANI.md`: kimlik, yetki, iş mantığı, API ve doğrulama için tamamlanmamış kontrol listesi.
- `targets/.../raw/nuclei_*.jsonl`: Web/Full profilinde seçilen Nuclei şablonlarının taslak eşleşmeleri; varsayılan gömülü şablonlar otomatik seçilir.
- `nuclei_template_manifest.json`: seçilen şablonların adları ve SHA-256 özetleri; denetim izi.
- `engagement.json`, `steps.json`, `SHA256SUMS.txt`: iş kapsamı, çalıştırma günlüğü, dosya özetleri.
- `targets/.../raw/discovery_hosts.xml`, `discovery_targets.txt`, `discovery_live_targets.txt`, `discovery_summary.json`, `nmap_cidr.xml`, `audit_cidr.xml`: CIDR için hariç tutulan adresleri yoklamadan host keşfi ve yalnızca yanıt verenlerde toplu servis taraması.
- `TOOL_ENVIRONMENT.json`: kurulu araçlar ile gerçekten çalıştırılan adımları ayırt etmek için ortam kaydı.
- `DEVICE_INVENTORY.json`: IP/MAC, çevrimdışı OUI üreticisi, servis ve gerekçeli cihaz sınıfı; yönetici PDF, teknik PDF ve HTML içinde özetlenir.
- `targets/.../raw/port_discovery.xml`, `nmap_cidr.xml`: CIDR'de önce toplu port keşfi, ardından yalnızca açık portların servis/sürüm denetimi; birinci aşama eksikse durum adım günlüğünde görünür.
- `targets/.../raw/snmp_v1_public_summary.json`, `snmp_v1_public_IP.json`: Tek sorgulu SNMPv1/public sonuç özeti ve yalnızca olumlu yanıtların kanıtı.
- `targets/.../raw/`: Nmap XML ve metin çıktıları, başlıklar, TLS, DNS.
- `targets/.../raw/auth_*.json`: Full profilinde seçildiyse anonim/kimlikli HTTPS HEAD durum kodları; parola/token/çerez içermez.
- `targets/.../raw/role_*.json`: Seçilmiş test hesaplarıyla GET karşılaştırması, yalnızca HTTP kodu/boyut ve senaryo bilgisi.
- `AI_DURUM.json`, `AI_ANALIST_YORUMU.md`: Seçildiyse Claude istek sayısı, hata durumu, kısıtlı ek denemeler ve doğrulanmamış AI yorumu.

`examples/` altındaki PDF'ler yalnızca temsili, canlı bir hedefte test yapılmadan üretilmiş örneklerdir. Üç IP adresi `examples/build_examples.py` içindeki sentetik kanıtlardan gelir; gerçek ağ taraması değildir.

Eski bir görevin taraması bitmiş fakat rapor üretimi hata vermişse yeni sürümü yükledikten sonra yeniden ağ taraması yapmadan raporları oluşturun:

```bash
find "$HOME/Desktop/UBDEN-Cyber-Reports" /opt/ubden-cyber/runs -maxdepth 2 -name engagement.json -print 2>/dev/null
ubden-cyber --report-only "/buldugunuz/gorev/klasoru"
```

Görev klasörü, `engagement.json` dosyasının **bulunduğu dizindir**. PDF oluşturma tek bir bulguda hata verirse diğer PDF yine denenir, HTML rapor oluşturulur ve hata açıkça gösterilir. Eski görevdeki CIDR taranmamışsa rapor yenilemek eksik ağ testini sonradan yapmış sayılmaz.

Yanıtlarda HSTS ve `X-Content-Type-Options` görülmemesi, TRACE yönteminin listelenmesi, eski TLS sürümleri ve HTTP 200 yanıtı **taslak otomatik gözlem** üretir. Bunlar tek başına güvenlik açığı kanıtı değildir; HTTP HEAD yönteminin yanıtı ve proxy davranışı farklı olabilir. Analist gerçek bulguları `review.json` üzerinden ayrıca kaydeder.

İsterseniz boş analist kayıt şablonunu kopyalayıp doldurun; sonra raporları tekrar oluşturun:

```bash
RUN_DIR="$HOME/Desktop/UBDEN-Cyber-Reports/MUSTERI_TARIH_ID"
cp /opt/ubden-cyber/review.example.json "$RUN_DIR/review.json"
# Her test için gerçek sonuç ve yerel kanıt yolu girin.
ubden-cyber --report-only "$RUN_DIR"
```

## Analist kontrolü ve teslim

Otomatik tarama bittikten sonra gerçek testleri yetki belgesindeki hedeflerde ve test hesaplarında analist yürütür. Özellikle düşük/yüksek rol, iki ayrı normal kullanıcı ve kendi kaynaklarıyla yetki matrisi kurulur; kimlik doğrulama, oturum, IDOR, API, iş mantığı ve yapılandırma sonuçları kaydedilir. Üretimde yazma işlemleri, gerçek müşteri verileri, yük testleri ve agresif istismar için ayrıca açık kapsam ve uygun ortam belirleyin. OWASP WSTG test başlıklarını uygulamanın özelliklerine göre seçin.

```bash
RUN_DIR="$HOME/Desktop/UBDEN-Cyber-Reports/MUSTERI_TARIH_ID"
mkdir -p "$RUN_DIR/evidence"
# Kendi yaptığınız testin temizlenmiş kanıtını evidence/ altına koyun.
ubden-cyber --analyst-review "$RUN_DIR"
```

Bu komut ağ isteği yapmaz. Sekiz manuel test başlığının her birinde sonucu ve kanıt dosyasını ister; uygun olmayan testler için gerekçe kaydeder. Kanıtın görev klasöründe bulunduğunu kontrol eder ve SHA-256 özetini kaydeder. Doğrulanmış bulgu için teknik açıklama, tekrar üretim, iş etkisi, düzeltme, doğrulayan analist ve mevcut kanıt dosyası gereklidir. Dosya değişirse rapor bulguyu otomatik olarak taslağa indirir. Son inceleyen tüm başlıkları değerlendirdikten sonra kayıtları onaylar. PDF/HTML içinde bekleyen başlıklar ve tamamlanma durumu görünür; imza atılması testin gerçekten yapıldığını bağımsız olarak kanıtlayamaz.

## Claude AI analist (isteğe bağlı)

Normal sihirbazda **Claude AI analist** seçeneğini açıp model kimliği (varsayılan `claude-sonnet-4-6`) ve API anahtarını gizli terminal istemine girin. Başlamadan önce iki paylaşım modu sunulur: yalnızca varlık adları ve yol içermeyen özet veya sınırlı ham kanıt ve üretilmiş HTML rapor metni. Ham modda müşteri verisi bulunabilir; müşteri sözleşmenizde üçüncü taraf API aktarımına izin veriliyorsa açın. Yalnızca açık onaydan sonra `api.anthropic.com/v1/messages` adresine HTTPS istekleri yapılır. Anahtar dosyaya, komut argümanına ve rapora konmaz. Yaygın token/çerez alanları temizlenmeye çalışılır; otomatik temizleme bütün gizli/kişisel verileri yakalama garantisi vermez.

Claude yanıtı önce **taslak AI analist yorumu** olarak tutulur. Birinci çağrıda önceden girilmiş senaryolardan en fazla ikisini tekrar kontrol etmeyi önerebilir. Yalnızca bu mevcut senaryoların GET kontrolleri tekrar edilir; yeni hedef/yol, serbest komut, istismar veya sonsuz agent döngüsü yoktur. Tekrar yapıldıysa ikinci ve son çağrı güncel gözlemleri yorumlar. API 429/timeout/ağ/model hatası veya bozuk yanıt halinde tarama devam eder; hata ve kısmi yorum raporda açıkça gösterilir. Bu yorum doğrulanmış bulgu yaratmaz.

Analist notları sonradan güncellenince önceki AI yorumunun eskidiği raporda gösterilir. Son hali tekrar inceletmek için:

```bash
ubden-cyber --ai-review "$RUN_DIR"
```

Bu komut yalnızca kayıtlı görev verisini ve izin verdiğiniz ham kanıtı değerlendirir; yeni müşteri ağı testi başlatmaz. Bu dağıtımda canlı Claude hesabıyla uçtan uca API çağrısı doğrulanmadı; isteğin biçimi ve hata işleme yolu ağsız testlerde doğrulandı.

Eski `review.json` dosyaları okunur, ancak yalnızca `status: "doğrulandı"` yazmak artık yeterli değildir; kanıt ve doğrulama alanları eksikse kayıt taslak gösterilir. Eski dosyayı kaybetmeden aynı klasörde `--analyst-review` ile tamamlayabilirsiniz. Tarama kurulu olmayan manuel araçlarla yapılmış sayılmaz.

## Operasyon notları

- Tamamlanmış testin kanıtlarına erişimi sınırlayın; müşteri sistemlerine ait başlıklar ve sunucu bilgileri içerebilir.
- Komut çıktıları ve SHA-256 özetleri kaydedilir. `SHA256SUMS.txt` kendisini içermez; yeniden rapor üretilirse yeni özet dosyası oluşur.
- Yanlış pozitifleri doğrulayın, örnek bulguları teslim öncesi silin; manuel test yapmadan “tam pentest” beyanında bulunmayın.
- Genel parola kırma, Metasploit istismarı, DoS, exploit zinciri, veri çıkarma ve kalıcılık yer almaz. SSH modülü yalnız sağlanan test hesabında, önceden doğrulanmış sunucu anahtarıyla ve en çok iki adayla çalışır. Kurulu araçların bu görevde çalışıp çalışmadığını adım günlüğünden doğrulayın.

UBDEN logosu: https://www.ubden.com/assets/images/ubden_light_slogansiz.webp
