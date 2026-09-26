#!/usr/bin/env bash
# Install the offensive toolchain the PARSDX post-UBDEN chain shells out to.
# Run this on the Kali WSL box AFTER UBDEN is installed, BEFORE running pipeline.py.
# Idempotent; safe to re-run. Kali/Debian only.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  exec sudo -- bash "$(readlink -f -- "$0")" "$@"
fi
if [[ ! -f /etc/debian_version ]]; then
  echo "[HATA] Bu script Kali/Debian icindir." >&2; exit 1
fi
export DEBIAN_FRONTEND=noninteractive
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FAILED=()

echo "[1/4] APT paketleri (repo araclari)"
apt-get update
for p in ldap-utils smbclient hashcat john nmap ntpdate responder krb5-user python3-pip pipx seclists dnsutils; do
  apt-get install -y --no-install-recommends "$p" || FAILED+=("apt:$p")
done

echo "[2/4] Python offensive araclari (pipx, izole)"
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
for app in netexec certipy-ad impacket coercer bloodyAD bloodhound-ce; do
  pipx install --force "$app" 2>/dev/null || pipx install "$app" || FAILED+=("pipx:$app")
done
pipx ensurepath >/dev/null 2>&1 || true

echo "[3/4] PARSDX python kutuphaneleri (izole venv; sistem python'una dokunmaz)"
# No --break-system-packages: it can break the box's Python. Use a dedicated venv.
# These libs are OPTIONAL — guard falls back to an nxc bind if ldap3 is absent, score has its own
# CVSS engine, attck works without mitreattack-python. So this step is best-effort.
if [[ -f "$HERE/requirements.txt" ]]; then
  python3 -m venv "$HERE/.venv" \
    && "$HERE/.venv/bin/pip" install -q --disable-pip-version-check -r "$HERE/requirements.txt" \
    || FAILED+=("venv:requirements (optional — tools degrade gracefully)")
fi

echo "[4/4] Dogrulama"
declare -A CHECK=(
  [nxc]="netexec nxc" [certipy]="certipy certipy-ad"
  [bloodhound-python]="bloodhound-python bloodhound-ce-python"
  [GetUserSPNs]="impacket-GetUserSPNs GetUserSPNs.py"
  [GetNPUsers]="impacket-GetNPUsers GetNPUsers.py"
  [secretsdump]="impacket-secretsdump secretsdump.py"
  [coercer]="coercer Coercer" [bloodyAD]="bloodyAD"
  [responder]="responder Responder" [hashcat]="hashcat" [ldapsearch]="ldapsearch"
)
missing=0
for key in "${!CHECK[@]}"; do
  found=""
  for name in ${CHECK[$key]}; do command -v "$name" >/dev/null 2>&1 && { found="$name"; break; }; done
  if [[ -n "$found" ]]; then printf '  [OK]      %-18s -> %s\n' "$key" "$found"
  else printf '  [MISSING] %-18s (%s)\n' "$key" "${CHECK[$key]}"; missing=$((missing+1)); fi
done
python3 - <<'PY' || true
for m in ("ldap3","cvss"):
    try: __import__(m); print(f"  [OK]      py:{m}")
    except Exception: print(f"  [MISSING] py:{m}")
PY

echo
if [[ ${#FAILED[@]} -gt 0 ]]; then printf '[UYARI] Kurulamayanlar: %s\n' "${FAILED[*]}" >&2; fi
if [[ $missing -gt 0 ]]; then
  echo "[UYARI] $missing arac eksik. pipx PATH icin yeni bir shell ac (source ~/.bashrc) ve tekrar dogrula." >&2
else
  echo "[OK] Offensive toolchain hazir. Simdi: python3 parsdx-ext/pipeline.py --run-dir <UBDEN_run> ..."
fi
