# PARSDX — Tek Sayfa Komut Kağıdı

Tam anlatım `RUNBOOK.md`'de. Bu sayfa sadece **sırayla yapıştırılacak komutlar**.
Her komutun çıktısını Claude'a yapıştır. **Tek bir yeri doldur (§0), gerisi düzeltmesiz yapışır.**

---

## 0 — Değişkenler (Kali WSL'de, BİR kez; aynı terminalde kal)

```bash
export RUN='/root/Desktop/UBDEN-Cyber-Reports/<CLIENT>_<tarih>_<id>'   # Can'ın UBDEN run klasörü
export DOM='<DOMAIN>'            # ör. corp.local
export DC='<DC_FQDN>'            # ör. dc01.corp.local
export IP='<DC_IP>'              # ör. 10.0.0.10
export U='<TEST_KULLANICI>'      # client'ın verdiği read-only hesap
export P='<PAROLA>'
export PX="$HOME/parsdx-ext"     # parsdx-ext'in bulunduğu yer
export PY="$PX/.venv/bin/python3"
printf '%s\n' '<CIDR>' "$IP" "$DC" > "$HOME/scope.txt"   # sözleşmedeki hedefler, satır başına bir tane
export SCOPE="$HOME/scope.txt"
cat "$SCOPE"
```

Kontrol: `echo "$RUN" && ls "$RUN" | head` → run klasörü doğru mu?

⚠️ **Scope'a DOMAIN adı yazmak host'ları yetkilendirmez.** `corp.local` satırı `dc01.corp.local`'i
kapsama ALMAZ — sözleşmedeki **her hostname'i ayrı satıra birebir yaz** (CIDR'ler zaten içindekileri
kapsar). Yanlışını §3'teki `N in / M dropped` satırından anlarsın: `dropped > 0` ise düşen hedef
sözleşmede varsa scope dosyasına eklenmeli. (Bilerek böyle: domain adını joker saymak, sözleşme dışı
bir host'a sessizce yayılmak demek olurdu.)

## 1 — Kurulum (makinede bir kez)

```bash
sudo bash "$PX/setup-offensive.sh" && source ~/.bashrc
```

Bakılacak satırlar: `[OK] nxc -> netexec`, `[OK] hashcat backend -> ...`, `[OK] Offensive toolchain hazir`.
`hashcat backend YOK` çıkarsa kırma adımında **john** kullan (§5), hashcat hiçbir şey kıramaz.

## 2 — GO / NO-GO (canlıdan önce; hiçbir kimlik denemesi yapmaz)

```bash
"$PY" "$PX/doctor.py" --scope "$SCOPE" --run-dir "$RUN" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"
```

**`==> GO` görmeden ilerleme.** `clock skew` FAIL/WARN → `sudo ntpdate "$IP"` (>5 dk fark tüm Kerberos'u öldürür).

## 3 — Planı gör (hiçbir şey çalıştırmaz)

```bash
"$PY" "$PX/pipeline.py" --run-dir "$RUN" --scope "$SCOPE" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P" --dry-run
```

**`# scope: N in / M dropped` satırını oku.** `0 in` = hiçbir host'a dokunulmayacak → `$SCOPE` ile
UBDEN'in hedef listesi uyuşmuyor, düzelt. Planı Claude'a yapıştır.

## 4 — Lockout bütçesi (kimseyi kilitlemeyelim)

```bash
"$PY" "$PX/guard.py" --policy --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"
```

`SAFE BUDGET` satırını Claude'a göster.

## 5 — CANLI (read-only zincir; yazma/dump KAPALI)

```bash
"$PY" "$PX/pipeline.py" --run-dir "$RUN" --scope "$SCOPE" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"
```

Sonra **iki şeyi birden oku**:

```bash
sed -n '1,40p' "$RUN/parsdx/SUMMARY.md"
```

⚠️ **`!! N step(s) did NOT complete cleanly` uyarısı varsa, `0 bulgu` "hedef temiz" DEMEK DEĞİLDİR.**
Adı geçen adımları tekrar çalıştır veya elle karşılığını dene (RUNBOOK § Elle yedek komutlar).

## 6 — Hash'leri OFFLINE kır (ağa dokunmaz, kilitleme riski yok)

```bash
"$PY" "$PX/crack.py" "$RUN"          # hash dosyalarını + doğru hashcat/john komutlarını basar
```

Bastığı komutu çalıştır, sonra sonucu geri besle:

```bash
"$PY" "$PX/crack.py" "$RUN" --results show.txt                        # hashcat kullandıysan
"$PY" "$PX/crack.py" "$RUN" --results "$RUN/parsdx/hashes/john.pot"   # john kullandıysan
"$PY" "$PX/pipeline.py" --run-dir "$RUN" --skip-attack --no-report    # bulguya işle
```

## 7 — ACİL DURUM

```bash
touch "$RUN/STOP"      # çalışan zincir bir sonraki adımdan ÖNCE durur, kısmi kanıt kalır
rm -f "$RUN/STOP"      # devam etmek için sil
```

Bir hesap kilitlendiyse / müşteri şikâyet ettiyse: **durdur, Claude'a söyle, client'ı bilgilendir.**

## 8 — Yazma/dump (yalnız gerekliyse, Claude onaylarsa)

```bash
"$PY" "$PX/pipeline.py" --run-dir "$RUN" --scope "$SCOPE" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P" \
  --enable-writes --allow-dcsync
```

Elle `YETKILIYIM` yaz. ⚠️ **`--assume-yes` KULLANMA** — insan onayı olmadan tüm domain hash'lerini döker.

## 9 — Temizlik (iş biter bitmez)

```bash
shred -u "$RUN/parsdx/dcsync_dump.txt" "$RUN/parsdx/hashes/"*.hash show.txt 2>/dev/null
sudo passwd ubden       # UBDEN'in zayıf 'ubden' hesabı (şifre: password)
```

DCSync hash'lerini **kendi laptobuna çekme**; rapora sadece asgari kanıt girer.
