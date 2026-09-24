#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  exec sudo -- bash "$(readlink -f -- "$0")" "$@"
fi
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST="/opt/ubden-cyber"
export DEBIAN_FRONTEND=noninteractive
if [[ ! -f /etc/debian_version ]]; then
  echo "Bu kurulum Debian tabanlı Kali/Ubuntu sistemleri için hazırlanmıştır." >&2
  exit 1
fi
case "${1:-}" in
  ""|--extended-tools|--everything|--wsl) ;;
  *) echo "Kullanım: bash install.sh [--extended-tools|--everything|--wsl]" >&2; exit 2 ;;
esac

echo "[1/5] APT paket listesi ve zorunlu araçlar"
apt-get update
if [[ "${1:-}" == --wsl ]] && { ! apt-cache policy | grep -F 'release o=Kali,' >/dev/null ||
    ! apt-cache policy nmap | grep -E '/kali[[:space:]]+kali-' >/dev/null; }; then
  echo '[HATA] Resmi Kali APT kaynagi dogrulanamadi; paket kurulumu durduruldu.' >&2
  exit 1
fi
apt-get install -y --no-install-recommends python3 python3-venv python3-pip nmap snmp iproute2 iputils-ping curl dnsutils whois sslscan ca-certificates fonts-dejavu-core
echo "[2/5] Ek araçlar (kurulum sonucu ayrıca gösterilir)"
FAILED=()
for package in whatweb nikto sqlmap gobuster wafw00f nuclei fping arping dnsenum nbtscan ike-scan tcpdump traceroute; do
  if [[ "${1:-}" == --wsl ]] && ! apt-cache policy "$package" | grep -E '/kali[[:space:]]+kali-' >/dev/null; then
    FAILED+=("$package: resmi Kali APT kaynagi yok")
    continue
  fi
  if ! apt-cache show "$package" >/dev/null 2>&1; then
    echo "[ATLANDI] $package: APT kaynaklarında yok"
    FAILED+=("$package: kaynakta yok")
  elif ! apt-get install -y --no-install-recommends "$package"; then
    echo "[HATA] $package kurulamadı. APT çıktısını inceleyin." >&2
    FAILED+=("$package: kurulum hatası")
  fi
done

if [[ "${1:-}" == --wsl ]]; then
  echo "[3/5] WSL araç kataloğundaki uygun Kali paketleri"
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    if ! apt-cache policy "$package" | grep -E '/kali[[:space:]]+kali-' >/dev/null; then
      FAILED+=("$package: resmi Kali APT kaynagi yok")
      continue
    fi
    if ! apt-cache show "$package" >/dev/null 2>&1; then
      FAILED+=("$package: kaynakta yok")
      continue
    fi
    if [[ "$package" == gvm ]]; then
      free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
      if [[ -n "$free_kb" && "$free_kb" -lt 31457280 ]] ||
         [[ -n "${UBDEN_HOST_FREE_KB:-}" && "$UBDEN_HOST_FREE_KB" -lt 31457280 ]]; then
        FAILED+=("gvm: Kali ve Windows sistem diskinde en az 30 GiB boş alan gerekir")
        continue
      fi
    fi
    if ! apt-get install -y --no-install-recommends "$package"; then
      FAILED+=("$package: kurulum hatası")
    fi
  done < <(python3 "$BASE/tool_catalog.py" --install-candidates)
  for package in iw usbutils reaver bully ldap-utils smbclient; do
    if ! apt-cache policy "$package" | grep -E '/kali[[:space:]]+kali-' >/dev/null; then
      FAILED+=("$package: resmi Kali APT kaynagi yok")
      continue
    fi
    if apt-cache show "$package" >/dev/null 2>&1; then
      if ! apt-get install -y --no-install-recommends "$package"; then
        FAILED+=("$package: kurulum hatası")
      fi
    else
      FAILED+=("$package: kaynakta yok")
    fi
  done
fi

if [[ "${1:-}" == --extended-tools || "${1:-}" == --everything ]]; then
  if [[ $(. /etc/os-release; echo "${ID:-}") != kali ]]; then
    echo "[ATLANDI] Kali araç grupları yalnızca Kali üzerinde kurulabilir." >&2
    FAILED+=("Kali araç grupları: sistem Kali değil")
  elif [[ "${1:-}" == --everything ]]; then
    echo "[3/5] Kali'nin tüm araçları: kali-linux-everything (yüksek disk/ağ kullanımı)"
    if ! apt-get install -y kali-linux-everything; then
      echo "[HATA] kali-linux-everything kurulamadı." >&2
      FAILED+=("kali-linux-everything: kurulum hatası")
    fi
  else
    echo "[3/5] Kali bilgi toplama, web, zafiyet ve raporlama araç grupları"
    for package in kali-tools-information-gathering kali-tools-web kali-tools-vulnerability kali-tools-reporting; do
      if ! apt-get install -y "$package"; then
        echo "[HATA] $package kurulamadı. APT çıktısını inceleyin." >&2
        FAILED+=("$package: kurulum hatası")
      fi
    done
  fi
fi

echo "[4/5] UBDEN uygulaması ve Python ortamı"
mkdir -p "$DEST" "$DEST/runs" "$DEST/assets"
mkdir -p "$DEST/templates/baseline/https" "$DEST/templates/baseline/web"
mkdir -p "$DEST/data/ieee"
if [[ -d "$BASE/data/ieee" ]]; then
  for csv in oui.csv mam.csv mas.csv; do
    if [[ -f "$BASE/data/ieee/$csv" ]]; then install -m 0644 "$BASE/data/ieee/$csv" "$DEST/data/ieee/$csv"; fi
  done
fi
install -m 0755 "$BASE/start.sh" "$BASE/target_scan.sh" "$BASE/install.sh" "$BASE/desktop-session.sh" "$DEST/"
install -m 0644 "$BASE/wizard.py" "$BASE/tui.py" "$BASE/analyst_review.py" "$BASE/ai_analyst.py" "$BASE/report_v2.py" "$BASE/device_inventory.py" "$BASE/tool_catalog.py" "$BASE/host_bridge.py" "$BASE/ad_assessment.py" "$BASE/wireless_assessment.py" "$BASE/supplemental_scans.py" "$BASE/credential_assessment.py" "$BASE/README.md" "$BASE/requirements.txt" "$BASE/review.example.json" "$DEST/"
install -m 0644 "$BASE/assets/"* "$DEST/assets/"
install -m 0644 "$BASE/templates/baseline/https/"*.yaml "$DEST/templates/baseline/https/"
install -m 0644 "$BASE/templates/baseline/web/"*.yaml "$DEST/templates/baseline/web/"
python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/python" -m pip install --disable-pip-version-check -r "$DEST/requirements.txt"
"$DEST/.venv/bin/python" -m py_compile "$DEST/wizard.py" "$DEST/report_v2.py" "$DEST/analyst_review.py" "$DEST/ai_analyst.py" "$DEST/tui.py" "$DEST/device_inventory.py" "$DEST/tool_catalog.py" "$DEST/host_bridge.py" "$DEST/ad_assessment.py" "$DEST/wireless_assessment.py" "$DEST/supplemental_scans.py" "$DEST/credential_assessment.py"
ln -sfn "$DEST/start.sh" /usr/local/bin/ubden-cyber
if [[ -d /usr/share/applications ]]; then
  install -m 0644 "$BASE/ubden-cyber.desktop" /usr/share/applications/ubden-cyber.desktop
fi
chmod 0700 "$DEST/runs"
echo "[5/5] Kurulum doğrulaması"
"$DEST/start.sh" --version
if command -v nuclei >/dev/null 2>&1; then
  if ! nuclei -validate -t "$DEST/templates/baseline" -duc -ni; then
    echo "[HATA] Gömülü Nuclei şablonlarının doğrulaması başarısız. Sürümü ve APT çıktısını inceleyin." >&2
    FAILED+=("UBDEN Nuclei şablonları: doğrulama hatası")
  fi
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
  printf '[UYARI] Kurulamayan/atlanan araçlar: %s\n' "${FAILED[*]}" >&2
else
  echo "[OK] İstenen ek araçlar kuruldu."
fi
echo "[OK] UBDEN Cyber Security Systems kuruldu."
echo "Başlat: ubden-cyber (gereken yetki için sudo kendiliğinden istenir)"
echo "Ön izleme: ubden-cyber --preview-ui (ağ isteği yapılmaz)"
echo "Kali masaüstünde varsayılan raporlar: ~/Desktop/UBDEN-Cyber-Reports/"
echo "Yüklü araçlar otomatik çalıştırılmaz; çalıştırılan adımlar raporda listelenir."
